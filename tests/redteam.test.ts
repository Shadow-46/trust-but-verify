import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { verifyAudit } from "../core/audit/log.ts";
import { generateSigningKeyPair } from "../core/crypto/sign.ts";
import { statePaths } from "../core/store/paths.ts";
import { call, callAsync, freshStateDir, SETUP } from "./helpers.ts";

// Regression tests for the red-team findings F1–F5 (stale-lock race, fail-open head
// check, unsigned records, corrupt log line, Windows lock contention).

const read = (dir: string, id: string) => call(dir, { op: "read", actor: "maya", asset: "brief", request_id: id }).out;

function setUp() {
  const dir = freshStateDir();
  assert.deepEqual(call(dir, SETUP).out, { ready: true });
  assert.equal(read(dir, "warm").decision, "allow");
  return { dir, paths: statePaths(dir) };
}

test("F1/F5: a dead holder's lock plus parallel bursts never forks the audit chain", async () => {
  const { dir, paths } = setUp();
  const deadPid = spawnSync(process.execPath, ["-e", ""]).pid;
  for (let round = 0; round < 4; round++) {
    // What a request killed at the judge's timeout leaves behind.
    writeFileSync(join(dir, ".lock"), `${deadPid} ${Date.now()} stale`);
    const replies = await Promise.all(
      Array.from({ length: 20 }, (_, i) => callAsync(dir, { op: "read", actor: i % 2 ? "maya" : "omar", asset: "brief", request_id: `r${round}-${i}` })),
    );
    for (const r of replies) assert.ok(r.out.decision === "allow" || r.out.decision === "deny", JSON.stringify(r.out));
    const v = verifyAudit(paths);
    assert.equal(v.ok, true, `round ${round}: chain broken at ${v.first_bad_seq}`);
  }
  assert.equal(read(dir, "after").decision, "allow");
});

test("F2: deleting the signed head fails closed instead of hiding a truncated log", () => {
  const { dir, paths } = setUp();
  call(dir, { op: "read", actor: "omar", asset: "brief", request_id: "evidence" }); // a denial an attacker wants gone
  const lines = readFileSync(paths.audit, "utf8").trimEnd().split("\n");
  writeFileSync(paths.audit, `${lines.slice(0, -1).join("\n")}\n`);
  rmSync(paths.auditHead);
  assert.equal(read(dir, "t1").error, "integrity_failure");
  // Malformed traffic must not re-sign a head over the truncated log (self-defence writes to a side file).
  for (let i = 0; i < 12; i++) call(dir, undefined, "{not json");
  assert.equal(read(dir, "t2").error, "integrity_failure");
});

test("F2: deleting or swapping the audit verification key fails closed", () => {
  const a = setUp();
  rmSync(a.paths.auditPub);
  assert.equal(read(a.dir, "k1").error, "integrity_failure");

  const b = setUp();
  writeFileSync(b.paths.auditPub, generateSigningKeyPair().publicKey.toString("base64"));
  assert.equal(read(b.dir, "k2").error, "integrity_failure");
});

test("F3: a missing audit signing key never produces unsigned records", () => {
  const { dir, paths } = setUp();
  const before = readFileSync(paths.audit, "utf8");
  rmSync(paths.auditKey);
  assert.equal(read(dir, "s1").error, "integrity_failure");
  assert.equal(readFileSync(paths.audit, "utf8"), before);
});

test("F4: a corrupted audit line is reported as an integrity failure", () => {
  const { dir, paths } = setUp();
  writeFileSync(paths.audit, `${readFileSync(paths.audit, "utf8")}{"seq": 99, broken\n`);
  assert.equal(read(dir, "c1").error, "integrity_failure");
});
