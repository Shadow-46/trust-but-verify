import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac, generateKeyPairSync } from "node:crypto";
import { chmodSync, mkdirSync, readdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { decapsulate, exportMlKem768PublicKeyRaw } from "../core/crypto/kem.ts";
import { verifyAudit, readAudit } from "../core/audit/log.ts";
import { deriveKeys, loadMasterKey } from "../core/keys/keystore.ts";
import { readSalt } from "../core/state.ts";
import { statePaths } from "../core/store/paths.ts";
import { allBytes, call, callAsync, freshStateDir, SETUP } from "./helpers.ts";

function setUp(): string {
  const dir = freshStateDir();
  const r = call(dir, SETUP);
  assert.equal(r.status, 0);
  assert.deepEqual(r.out, { ready: true });
  return dir;
}

test("lost-device scenario: owner allowed, revoked owner denied, peer unaffected, audit matches", () => {
  const dir = setUp();
  assert.deepEqual(call(dir, { op: "read", actor: "maya", asset: "brief", request_id: "r01" }).out, {
    decision: "allow",
    body: SETUP.contents.brief,
  });
  assert.deepEqual(call(dir, { op: "read", actor: "omar", asset: "brief", request_id: "r02" }).out, { decision: "deny" });
  assert.equal(call(dir, { op: "revoke", actor: "maya" }).status, 0);
  assert.deepEqual(call(dir, { op: "read", actor: "maya", asset: "brief", request_id: "r03" }).out, { decision: "deny" });
  assert.deepEqual(call(dir, { op: "read", actor: "omar", asset: "ledger", request_id: "r04" }).out, {
    decision: "allow",
    body: SETUP.contents.ledger,
  });
  assert.deepEqual(call(dir, { op: "audit", request_id: "r03" }).out, { request_id: "r03", decision: "deny" });
  assert.deepEqual(call(dir, { op: "audit", request_id: "r01" }).out, { request_id: "r01", decision: "allow" });
});

test("disabled actors and unknown assets are denied", () => {
  const dir = setUp();
  assert.deepEqual(call(dir, { op: "read", actor: "dana", asset: "brief", request_id: "a" }).out, { decision: "deny" });
  assert.deepEqual(call(dir, { op: "read", actor: "maya", asset: "nope", request_id: "b" }).out, { decision: "deny" });
});

test("protected_read: ML-KEM-768 ciphertext decapsulates and HMAC proof verifies", () => {
  const dir = setUp();
  const { publicKey, privateKey } = generateKeyPairSync("ml-kem-768" as never);
  const raw = exportMlKem768PublicKeyRaw(publicKey);
  const challenge = "fresh-challenge-123";
  const r = call(dir, { op: "protected_read", actor: "maya", asset: "brief", challenge, public_key: raw.toString("base64") });
  assert.equal(r.status, 0);
  assert.equal(r.out.decision, "allow");
  assert.equal(r.out.body, undefined, "protected_read must not return the plaintext body");
  const ct = Buffer.from(r.out.ciphertext as string, "base64");
  assert.equal(ct.length, 1088);
  const shared = decapsulate(privateKey, ct);
  const expected = createHmac("sha256", shared).update(challenge + SETUP.contents.brief, "utf8").digest("hex");
  assert.equal(r.out.proof, expected);
  assert.match(r.out.proof as string, /^[0-9a-f]{64}$/);
});

test("protected_read denies non-owners and revoked owners without ciphertext or proof", () => {
  const dir = setUp();
  const raw = exportMlKem768PublicKeyRaw(generateKeyPairSync("ml-kem-768" as never).publicKey).toString("base64");
  const base = { op: "protected_read", asset: "brief", challenge: "c", public_key: raw };
  assert.deepEqual(call(dir, { ...base, actor: "omar" }).out, { decision: "deny" });
  call(dir, { op: "revoke", actor: "maya" });
  assert.deepEqual(call(dir, { ...base, actor: "maya" }).out, { decision: "deny" });
});

test("protected_read rejects malformed public keys and challenges", () => {
  const dir = setUp();
  const base = { op: "protected_read", actor: "maya", asset: "brief", challenge: "c" };
  assert.deepEqual(call(dir, { ...base, public_key: Buffer.alloc(100).toString("base64") }).out, { error: "invalid_public_key" });
  assert.deepEqual(call(dir, { ...base, public_key: "not base64!!" }).out, { error: "invalid_public_key" });
  assert.deepEqual(call(dir, { ...base, challenge: "", public_key: "AAAA" }).out, { error: "invalid_challenge" });
});

test("secrets never reach stdout/stderr, and bodies/key_material are not stored in plaintext", () => {
  const dir = freshStateDir();
  const outputs: string[] = [];
  const run = (req: unknown) => {
    const r = call(dir, req);
    outputs.push(r.stdout, r.stderr);
    return r;
  };
  run(SETUP);
  run({ op: "read", actor: "omar", asset: "brief", request_id: "x1" });
  run({ op: "read", actor: "maya", asset: "brief" }); // invalid: missing request_id
  run({ op: "bogus" });
  const joined = outputs.join("\n");
  assert.ok(!joined.includes(SETUP.key_material), "key_material leaked to output");
  assert.ok(!joined.includes(SETUP.contents.brief), "body leaked on a deny or error");
  const stored = allBytes(dir);
  assert.ok(!stored.includes(SETUP.key_material), "key_material stored in plaintext");
  assert.ok(!stored.includes("quarterly numbers"), "body stored in plaintext");
});

test("tampered state fails closed: an attacker cannot silently undo a revocation", () => {
  const dir = setUp();
  call(dir, { op: "revoke", actor: "maya" });
  const p = statePaths(dir).state;
  const file = JSON.parse(readFileSync(p, "utf8")) as { body: string; mac: string };
  file.body = file.body.replace('"revoked":["maya"]', '"revoked":[]');
  writeFileSync(p, JSON.stringify(file));
  const r = call(dir, { op: "read", actor: "maya", asset: "brief", request_id: "t1" });
  assert.equal(r.status, 1);
  assert.deepEqual(r.out, { error: "integrity_failure" });
});

test("corrupted asset ciphertext (valid state MAC) is denied by AES-GCM and recorded", () => {
  const dir = setUp();
  const paths = statePaths(dir);
  const file = JSON.parse(readFileSync(paths.state, "utf8")) as { body: string; mac: string };
  // Flip one ciphertext character, then re-authenticate the state with the real key so that only
  // the AES-GCM layer can catch the corruption.
  file.body = file.body.replace(/"c":"([A-Za-z0-9+/])/, (_m, ch: string) => `"c":"${ch === "A" ? "B" : "A"}`);
  const macKey = deriveKeys(loadMasterKey(paths), readSalt(paths)).stateMac;
  file.mac = createHmac("sha256", macKey).update(file.body, "utf8").digest("hex");
  writeFileSync(paths.state, JSON.stringify(file));
  const r = call(dir, { op: "read", actor: "maya", asset: "brief", request_id: "t2" });
  assert.deepEqual(r.out, { decision: "deny" });
  assert.deepEqual(call(dir, { op: "audit", request_id: "t2" }).out, { request_id: "t2", decision: "deny" });
  assert.equal(readAudit(paths).at(-1)?.reason, "integrity_failure");
});

test("IDs are opaque: __proto__/constructor and newline/JSON injection are handled safely", () => {
  const dir = freshStateDir();
  const evil = 'mallory\n{"type":"revoke","actor":"maya"}';
  const raw = JSON.stringify({ op: "setup", owners: { "a/../../etc": evil }, contents: { "a/../../etc": "path body" } })
    .replace('{"a/../../etc":"', '{"__proto__":"constructor","a/../../etc":"')
    .replace('"contents":{', '"contents":{"__proto__":"proto body",');
  assert.deepEqual(call(dir, undefined, raw).out, { ready: true });
  assert.deepEqual(call(dir, { op: "read", actor: "constructor", asset: "__proto__", request_id: "p1" }).out, {
    decision: "allow",
    body: "proto body",
  });
  assert.deepEqual(call(dir, { op: "read", actor: evil, asset: "a/../../etc", request_id: "p2" }).out, {
    decision: "allow",
    body: "path body",
  });
  const records = readAudit(statePaths(dir));
  assert.equal(records.length, 3, "injected text must not create extra audit records");
  assert.equal(records[2].actor, evil, "recorded actor must be preserved exactly");
  assert.equal(verifyAudit(statePaths(dir)).ok, true);
});

test("duplicate request_id keeps the first recorded decision", () => {
  const dir = setUp();
  call(dir, { op: "read", actor: "maya", asset: "brief", request_id: "dup" });
  call(dir, { op: "revoke", actor: "maya" });
  assert.deepEqual(call(dir, { op: "read", actor: "maya", asset: "brief", request_id: "dup" }).out, { decision: "deny" });
  assert.deepEqual(call(dir, { op: "audit", request_id: "dup" }).out, { request_id: "dup", decision: "allow" });
  assert.ok(readAudit(statePaths(dir)).some((r) => r.type === "duplicate_request_id"));
});

test("a request_id first recorded as deny can never return a body later", () => {
  const dir = setUp();
  assert.deepEqual(call(dir, { op: "read", actor: "omar", asset: "brief", request_id: "X" }).out, { decision: "deny" });
  assert.deepEqual(call(dir, { op: "read", actor: "maya", asset: "brief", request_id: "X" }).out, { decision: "deny" });
  assert.deepEqual(call(dir, { op: "audit", request_id: "X" }).out, { request_id: "X", decision: "deny" });
  // An identical retry of an allowed request stays idempotent.
  call(dir, { op: "read", actor: "maya", asset: "brief", request_id: "Y" });
  assert.equal(call(dir, { op: "read", actor: "maya", asset: "brief", request_id: "Y" }).out.decision, "allow");
});

test("a lock left by a killed request does not block the next request", () => {
  const dir = setUp();
  writeFileSync(join(dir, ".lock"), "2147483646 0"); // PID that cannot exist
  const started = Date.now();
  const r = call(dir, { op: "read", actor: "maya", asset: "brief", request_id: "after-crash" });
  assert.equal(r.out.decision, "allow");
  assert.ok(Date.now() - started < 3000, `took ${Date.now() - started} ms`);
});

test("malformed requests return fixed error codes without stack traces", () => {
  const dir = setUp();
  const cases: [string, string][] = [
    ["not json", "invalid_json"],
    ["[1,2]", "invalid_request"],
    ['{"op":"explode"}', "unsupported_operation"],
    ['{"op":"read","actor":5,"asset":"brief","request_id":"r"}', "invalid_actor"],
    ['{"op":"setup","owners":[],"contents":{}}', "invalid_owners"],
  ];
  for (const [raw, code] of cases) {
    const r = call(dir, undefined, raw);
    assert.equal(r.status, 1, raw);
    assert.deepEqual(r.out, { error: code }, raw);
    assert.ok(!/at .*\.ts/.test(r.stderr), "stack trace leaked");
  }
});

test("audit log verification detects an edited record", () => {
  const dir = setUp();
  call(dir, { op: "read", actor: "maya", asset: "brief", request_id: "v1" });
  call(dir, { op: "read", actor: "omar", asset: "brief", request_id: "v2" });
  const paths = statePaths(dir);
  assert.deepEqual(verifyAudit(paths), { ok: true, records: 3, first_bad_seq: null });
  const lines = readFileSync(paths.audit, "utf8").trimEnd().split("\n");
  lines[2] = lines[2].replace('"decision":"deny"', '"decision":"allow"');
  writeFileSync(paths.audit, lines.join("\n") + "\n");
  assert.deepEqual(verifyAudit(paths), { ok: false, records: 3, first_bad_seq: 3 });
});

test("concurrent processes do not lose decisions or break the audit chain", async () => {
  const dir = setUp();
  const results = await Promise.all(
    Array.from({ length: 8 }, (_, i) =>
      callAsync(dir, { op: "read", actor: i % 2 ? "maya" : "omar", asset: "brief", request_id: `c${i}` }),
    ),
  );
  for (const r of results) assert.equal(r.status, 0);
  const v = verifyAudit(statePaths(dir));
  assert.equal(v.ok, true);
  assert.equal(v.records, 9);
  for (let i = 0; i < 8; i++) {
    assert.equal(call(dir, { op: "audit", request_id: `c${i}` }).out.decision, i % 2 ? "allow" : "deny");
  }
});

test("planted state directory (symlink) is refused and a loose one is locked down to 0700", { skip: process.platform === "win32" }, () => {
  const base = freshStateDir();
  const target = join(base, "attacker-owned");
  mkdirSync(target);
  const link = join(base, "state-link");
  symlinkSync(target, link);
  const r = call(link, SETUP);
  assert.equal(r.status, 1);
  assert.deepEqual(r.out, { error: "internal_error" });
  assert.equal(readdirSync(target).length, 0, "nothing may be written through the planted symlink");

  const loose = join(base, "loose");
  mkdirSync(loose, { mode: 0o777 });
  chmodSync(loose, 0o777);
  assert.deepEqual(call(loose, SETUP).out, { ready: true });
  assert.equal(statSync(loose).mode & 0o777, 0o700);
});

test("requests before setup are refused cleanly", () => {
  const dir = freshStateDir();
  assert.deepEqual(call(dir, { op: "read", actor: "maya", asset: "brief", request_id: "z" }).out, {
    error: "not_initialized",
  });
});
