import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { verifyAudit } from "../core/audit/log.ts";
import { createBackup, restoreBackup } from "../core/backup.ts";
import { ControlPlane } from "../core/cluster/control.ts";
import { generateSigningKeyPair } from "../core/crypto/sign.ts";
import { statePaths } from "../core/store/paths.ts";
import { call, freshStateDir, ROOT, SETUP } from "./helpers.ts";

function setUp() {
  const dir = freshStateDir();
  assert.deepEqual(call(dir, SETUP).out, { ready: true });
  return { dir, paths: statePaths(dir) };
}
const readMaya = (dir: string, id: string) => call(dir, { op: "read", actor: "maya", asset: "brief", request_id: id }).out;

test("rolling state.json back to an older valid copy (undoing a revocation) is detected", () => {
  const { dir, paths } = setUp();
  const old = join(dir, "old-state.json");
  copyFileSync(paths.state, old);
  call(dir, { op: "revoke", actor: "maya" });
  copyFileSync(old, paths.state);
  assert.deepEqual(readMaya(dir, "r1"), { error: "integrity_failure" });
});

test("truncating the audit log is detected", () => {
  const { dir, paths } = setUp();
  readMaya(dir, "a");
  readMaya(dir, "b");
  const lines = readFileSync(paths.audit, "utf8").trimEnd().split("\n");
  writeFileSync(paths.audit, lines.slice(0, -1).join("\n") + "\n");
  assert.deepEqual(readMaya(dir, "c"), { error: "integrity_failure" });
});

test("audit records are ML-DSA signed and verify only against the right public key", () => {
  const { dir, paths } = setUp();
  readMaya(dir, "s1");
  assert.equal(verifyAudit(paths).ok, true);
  assert.equal(verifyAudit(paths).signatures_checked, true);
  assert.equal(verifyAudit(paths, generateSigningKeyPair().publicKey).ok, false);
});

function crashDuringRotation(dir: string, point: string) {
  const mod = pathToFileURL(join(ROOT, "dist", "core", "keys", "rotation.js")).href;
  const pathsMod = pathToFileURL(join(ROOT, "dist", "core", "store", "paths.js")).href;
  const code = `import { rotateStoredDataKey } from ${JSON.stringify(mod)}; import { statePaths } from ${JSON.stringify(pathsMod)}; rotateStoredDataKey(statePaths(${JSON.stringify(dir)}));`;
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", code], {
    env: { ...process.env, TBV_TEST_CRASH: point, TRACK4_MASTER_KEY: "" },
  });
  assert.notEqual(r.status, 0, "process should have been killed");
}

for (const [point, expectedVersion] of [["rotation_before_commit", 1], ["rotation_after_commit", 2]] as const) {
  test(`crash ${point.replace("rotation_", "").replace(/_/g, " ")} of a key rotation recovers a consistent, authorized state`, () => {
    const { dir, paths } = setUp();
    call(dir, { op: "revoke", actor: "omar" });
    crashDuringRotation(dir, point);
    assert.ok(existsSync(join(dir, ".lock")), "killed process left its lock behind");
    const started = Date.now();
    assert.deepEqual(readMaya(dir, "after"), { decision: "allow", body: SETUP.contents.brief });
    assert.ok(Date.now() - started < 3000, "dead holder's lock must be broken quickly");
    assert.deepEqual(call(dir, { op: "read", actor: "omar", asset: "ledger", request_id: "o" }).out, { decision: "deny" });
    const body = JSON.parse(JSON.parse(readFileSync(paths.state, "utf8")).body);
    assert.equal(body.keyring.active, expectedVersion);
    assert.ok(body.assets.every(([, r]: [string, { version: number }]) => r.version === expectedVersion));
    assert.equal(verifyAudit(paths).ok, true);
  });
}

test("backups: damaged or unsigned backups are refused and reported; live state is untouched", () => {
  const { dir, paths } = setUp();
  const file = join(dir, "backup.json");
  createBackup(paths, file);
  const good = JSON.parse(readFileSync(file, "utf8"));

  writeFileSync(file, JSON.stringify({ ...good, payload: good.payload.replace("state", "stat3") }));
  assert.deepEqual(restoreBackup(paths, file), { ok: false, reason: "digest_mismatch" });

  const forgedPayload = good.payload.replace('"created_at":"', '"created_at":"1');
  const digest = createHash("sha256").update(forgedPayload, "utf8").digest("hex");
  writeFileSync(file, JSON.stringify({ ...good, payload: forgedPayload, sha256: digest }));
  assert.deepEqual(restoreBackup(paths, file), { ok: false, reason: "bad_signature" });

  writeFileSync(file, "{not json");
  assert.deepEqual(restoreBackup(paths, file), { ok: false, reason: "unreadable" });
  assert.deepEqual(readMaya(dir, "live"), { decision: "allow", body: SETUP.contents.brief });
});

test("restoring an older backup keeps later revocations and a verifiable log", () => {
  const { dir, paths } = setUp();
  const file = join(dir, "backup.json");
  createBackup(paths, file);
  call(dir, { op: "revoke", actor: "omar" });
  const r = restoreBackup(paths, file);
  assert.equal(r.ok, true);
  assert.equal(r.ok && r.carried_revocations, 1);
  assert.deepEqual(call(dir, { op: "read", actor: "omar", asset: "ledger", request_id: "o2" }).out, { decision: "deny" });
  assert.deepEqual(readMaya(dir, "m2"), { decision: "allow", body: SETUP.contents.brief });
  assert.equal(verifyAudit(paths).ok, true);
});

test("control plane refuses to load a published policy older than its high-water mark", () => {
  const dir = join(freshStateDir(), "control");
  const cp = ControlPlane.create(dir);
  cp.enrolDevice("maya", "maya-phone", generateSigningKeyPair().publicKey);
  const old = join(dir, "..", "old.json");
  copyFileSync(cp.paths.published, old);
  cp.revokeDevice("maya-phone");
  copyFileSync(old, cp.paths.published);
  assert.throws(() => ControlPlane.load(dir), /rollback/);
});
