// Red-team harness for the judged adapter. Plays the judge's worker: one fresh
// `node track4_service.mjs` process per request, JSON on stdin, JSON on stdout.
// Every check prints PASS or FINDING with a short explanation.
//
//   node tools/redteam.mjs            (uses a fresh temp state dir per scenario)
//
// Nothing here is used at judging time.
import { spawn, spawnSync } from "node:child_process";
import { generateKeyPairSync, decapsulate, createHmac } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, unlinkSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ENTRY = join(ROOT, "track4_service.mjs");
const SECRET = "KEYMAT-zz9-plural-z-alpha";
const BODY_M = "maya secret body ✓ ü 日本 \u{1F512}";
const BODY_O = "omar notes";

const results = [];
function check(id, ok, what, detail = "") {
  results.push({ id, ok, what, detail });
  process.stdout.write(`${ok ? "PASS   " : "FINDING"} ${id} ${what}${detail ? ` — ${detail}` : ""}\n`);
}

function call(dir, req, { raw, env = {} } = {}) {
  const input = raw ?? JSON.stringify(req);
  const t0 = performance.now();
  const r = spawnSync(process.execPath, [ENTRY], {
    input,
    env: { ...process.env, TRACK4_STATE_DIR: dir, ...env },
    cwd: ROOT,
    maxBuffer: 64 * 1024 * 1024,
  });
  const ms = performance.now() - t0;
  const stdout = r.stdout.toString("utf8");
  const stderr = r.stderr.toString("utf8");
  let json;
  try { json = JSON.parse(stdout); } catch { json = undefined; }
  return { json, stdout, stderr, code: r.status, ms };
}

function callAsync(dir, req) {
  return new Promise((res) => {
    const p = spawn(process.execPath, [ENTRY], { env: { ...process.env, TRACK4_STATE_DIR: dir }, cwd: ROOT });
    let out = "", err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("close", (code) => { let json; try { json = JSON.parse(out); } catch {} res({ json, stdout: out, stderr: err, code }); });
    p.stdin.end(JSON.stringify(req));
  });
}

const fresh = (name) => mkdtempSync(join(tmpdir(), `tbv-rt-${name}-`));
const SETUP = { op: "setup", owners: { brief: "maya", notes: "omar" }, contents: { brief: BODY_M, notes: BODY_O }, disabled: ["dana"], key_material: SECRET };
function setup(dir, extra = {}) {
  const r = call(dir, { ...SETUP, ...extra });
  if (r.json?.ready !== true) throw new Error(`setup failed: ${r.stdout} ${r.stderr}`);
}
const isDeny = (r) => r.json?.decision === "deny" && Object.keys(r.json).length === 1;
const leaks = (r, ...needles) => needles.some((n) => r.stdout.includes(n) || r.stderr.includes(n));
function filesUnder(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...filesUnder(p)); else out.push(p);
  }
  return out;
}

// ---------------------------------------------------------------- 1. baseline
{
  const d = fresh("base");
  setup(d);
  const a = call(d, { op: "read", actor: "maya", asset: "brief", request_id: "r1" });
  check("BASE-1", a.json?.decision === "allow" && a.json.body === BODY_M, "owner reads exact multibyte body");
  call(d, { op: "revoke", actor: "maya" });
  const b = call(d, { op: "read", actor: "maya", asset: "brief", request_id: "r2" });
  check("BASE-2", isDeny(b), "revoked owner denied with no other fields");
  const c = call(d, { op: "read", actor: "omar", asset: "notes", request_id: "r3" });
  check("BASE-3", c.json?.body === BODY_O, "peer unaffected");
  const au = call(d, { op: "audit", request_id: "r2" });
  check("BASE-4", au.json?.request_id === "r2" && au.json?.decision === "deny", "audit returns recorded deny");
}

// ---------------------------------------------------------------- 2. malformed input
{
  const d = fresh("malformed");
  setup(d);
  const cases = [
    ["not json", "hello"], ["empty", ""], ["array", "[]"], ["null", "null"], ["number", "42"], ["string", "\"read\""],
    ["BOM", "﻿" + JSON.stringify({ op: "read", actor: "maya", asset: "brief", request_id: "b1" })],
    ["unknown op", JSON.stringify({ op: "delete_all" })], ["op array", JSON.stringify({ op: ["read"] })],
    ["op proto", JSON.stringify({ op: "__proto__" })], ["op toString", JSON.stringify({ op: "toString" })],
    ["missing fields", JSON.stringify({ op: "read" })],
    ["actor number", JSON.stringify({ op: "read", actor: 1, asset: "brief", request_id: "x" })],
    ["actor object", JSON.stringify({ op: "read", actor: { toString: "maya" }, asset: "brief", request_id: "x" })],
    ["deep nesting", "[".repeat(200000) + "]".repeat(200000)],
    ["deep object", '{"a":'.repeat(100000) + "1" + "}".repeat(100000)],
    ["owners array", JSON.stringify({ op: "setup", owners: ["maya"], contents: {}, disabled: [] })],
    ["content number", JSON.stringify({ op: "setup", owners: { a: "b" }, contents: { a: 5 }, disabled: [] })],
  ];
  for (const [name, raw] of cases) {
    const r = call(d, null, { raw });
    const okShape = r.json && typeof r.json.error === "string" && Object.keys(r.json).length === 1;
    const noEcho = !r.stdout.includes("maya") && !r.stdout.includes("delete_all");
    check(`INPUT-${name}`, okShape && noEcho && !r.stderr.includes("at "), `malformed input "${name}" → fixed error, no echo, no stack`, `${r.stdout.trim().slice(0, 60)} exit=${r.code}`);
  }
  // State must still be intact after all that.
  const ok = call(d, { op: "read", actor: "maya", asset: "brief", request_id: "after" });
  check("INPUT-state-intact", ok.json?.body === BODY_M, "state unaffected by malformed requests");
  // Duplicate JSON keys: the last one wins in JSON.parse.
  const dup = call(d, null, { raw: '{"op":"read","actor":"omar","asset":"brief","request_id":"dup1","actor":"maya"}' });
  check("INPUT-dupkeys", dup.json?.decision === "allow", "duplicate keys: last value used consistently (informational)", dup.stdout.trim().slice(0, 40));
  const dupAudit = call(d, { op: "audit", request_id: "dup1" });
  check("INPUT-dupkeys-audit", dupAudit.json?.decision === dup.json?.decision, "audit agrees with the duplicate-key decision");
}

// ---------------------------------------------------------------- 3. identifiers
{
  const d = fresh("ids");
  const weird = ["../../etc/passwd", "__proto__", "constructor", "prototype", "a\nb", 'x","decision":"allow', "\u0000", "maya\u0000", "ｍａｙａ", "MAYA", " maya", "😀", "a".repeat(256)];
  const owners = {}; const contents = {};
  // defineProperty, because `obj["__proto__"] = x` would set the prototype instead of a key.
  weird.forEach((w, i) => {
    Object.defineProperty(owners, w, { value: `owner-${i}`, enumerable: true });
    Object.defineProperty(contents, w, { value: `body-${i}`, enumerable: true });
  });
  owners.brief = "maya"; contents.brief = BODY_M;
  const s = call(d, { op: "setup", owners, contents, disabled: [], key_material: SECRET });
  check("ID-setup", s.json?.ready === true, "setup accepts opaque IDs incl. __proto__, paths, newlines, NUL");
  let allOk = true; const bad = [];
  weird.forEach((w, i) => {
    const r = call(d, { op: "read", actor: `owner-${i}`, asset: w, request_id: `w${i}` });
    if (r.json?.body !== `body-${i}`) { allOk = false; bad.push(JSON.stringify(w).slice(0, 20)); }
  });
  check("ID-roundtrip", allOk, "each weird asset ID reads back its own body", bad.join(" "));
  for (const imp of ["MAYA", " maya", "maya ", "ｍａｙａ", "maya\u0000", "__proto__", "constructor"]) {
    const r = call(d, { op: "read", actor: imp, asset: "brief", request_id: `imp-${Buffer.from(imp).toString("hex")}` });
    check(`ID-impersonate-${JSON.stringify(imp)}`, isDeny(r), `look-alike actor ${JSON.stringify(imp)} denied`);
  }
  const long = call(d, { op: "read", actor: "maya", asset: "brief", request_id: "r".repeat(257) });
  check("ID-long-request-id", !!long.json, "257-char request_id handled (informational)", long.stdout.trim().slice(0, 50));
  const fsEscape = existsSync(join(d, "..", "..", "etc", "passwd.json")) || readdirSync(d).some((n) => n.includes("passwd"));
  check("ID-no-path-use", !fsEscape, "IDs never become file names");
  // Audit injection: newline + JSON in the actor must stay one record.
  const inj = call(d, { op: "read", actor: 'evil"}\n{"seq":999,"type":"access_decision","request_id":"forged","decision":"allow"}', asset: "brief", request_id: "inj1" });
  const forged = call(d, { op: "audit", request_id: "forged" });
  check("ID-audit-injection", isDeny(inj) && forged.json?.found === false, "log injection via actor cannot forge a record");
}

// ---------------------------------------------------------------- 4. authorization + request IDs
{
  const d = fresh("authz");
  setup(d);
  check("AUTHZ-disabled", isDeny(call(d, { op: "read", actor: "dana", asset: "brief", request_id: "d1" })), "disabled actor denied");
  check("AUTHZ-unknown-asset", isDeny(call(d, { op: "read", actor: "maya", asset: "nope", request_id: "d2" })), "unknown asset denied");
  check("AUTHZ-cross-owner", isDeny(call(d, { op: "read", actor: "omar", asset: "brief", request_id: "d3" })), "non-owner denied");
  // Deny first, then the owner retries with the same request ID → must not get the body.
  call(d, { op: "read", actor: "omar", asset: "brief", request_id: "same" });
  const reuse = call(d, { op: "read", actor: "maya", asset: "brief", request_id: "same" });
  const reuseAudit = call(d, { op: "audit", request_id: "same" });
  check("AUTHZ-reuse-after-deny", isDeny(reuse) && reuseAudit.json?.decision === "deny", "body never returned under a request ID recorded as deny");
  // Allow first, then another actor uses the same request ID.
  call(d, { op: "read", actor: "maya", asset: "brief", request_id: "same2" });
  const steal = call(d, { op: "read", actor: "omar", asset: "brief", request_id: "same2" });
  check("AUTHZ-reuse-steal", isDeny(steal), "other actor reusing an allowed request ID is denied");
  // Revoke affects protected_read too.
  call(d, { op: "revoke", actor: "maya" });
  const { publicKey } = generateKeyPairSync("ml-kem-768");
  const raw = publicKey.export({ format: "der", type: "spki" }).subarray(22).toString("base64");
  const pr = call(d, { op: "protected_read", actor: "maya", asset: "brief", challenge: "c", public_key: raw });
  check("AUTHZ-protected-read-revoked", isDeny(pr), "revoked actor gets no ciphertext/proof");
  // Re-setup resets revocations (documented: setup replaces state).
  setup(d);
  const after = call(d, { op: "read", actor: "maya", asset: "brief", request_id: "post-setup" });
  check("AUTHZ-setup-resets", after.json?.decision === "allow", "setup replaces state incl. revocations (documented, informational)");
  // Revoke before setup.
  const d2 = fresh("nosetup");
  const ns = call(d2, { op: "revoke", actor: "maya" });
  check("AUTHZ-before-setup", ns.json?.error === "not_initialized", "operations before setup refused", ns.stdout.trim());
}

// ---------------------------------------------------------------- 5. protected_read crypto
{
  const d = fresh("pr");
  setup(d);
  const { publicKey, privateKey } = generateKeyPairSync("ml-kem-768");
  const raw = publicKey.export({ format: "der", type: "spki" }).subarray(22);
  const challenge = "chal-" + "é".repeat(10);
  const r = call(d, { op: "protected_read", actor: "maya", asset: "brief", challenge, public_key: raw.toString("base64") });
  let ok = false;
  if (r.json?.ciphertext) {
    const ss = decapsulate(privateKey, Buffer.from(r.json.ciphertext, "base64"));
    ok = createHmac("sha256", ss).update(Buffer.from(challenge + BODY_M, "utf8")).digest("hex") === r.json.proof;
  }
  check("PR-proof", ok && !r.stdout.includes(BODY_M), "proof verifies after decapsulation; body not in reply");
  for (const [name, key] of [["short", raw.subarray(1)], ["long", Buffer.concat([raw, Buffer.alloc(1)])], ["zeros", Buffer.alloc(1184)]]) {
    const x = call(d, { op: "protected_read", actor: "maya", asset: "brief", challenge: "c", public_key: key.toString("base64") });
    check(`PR-key-${name}`, !!x.json && !x.stdout.includes(BODY_M), `public key "${name}" handled safely`, x.stdout.trim().slice(0, 60));
  }
  for (const [name, val] of [["spaces", " " + raw.toString("base64")], ["urlsafe", raw.toString("base64url")], ["number", 5], ["missing", undefined]]) {
    const x = call(d, { op: "protected_read", actor: "maya", asset: "brief", challenge: "c", public_key: val });
    check(`PR-badkey-${name}`, x.json?.error === "invalid_public_key", `malformed key "${name}" → invalid_public_key`, x.stdout.trim());
  }
  const big = call(d, { op: "protected_read", actor: "maya", asset: "brief", challenge: "c".repeat(5000), public_key: raw.toString("base64") });
  check("PR-long-challenge", !!big.json, "5000-char challenge handled (informational)", big.stdout.trim().slice(0, 50));
}

// ---------------------------------------------------------------- 6. secrets on disk and in output
{
  const d = fresh("secrets");
  const s = call(d, SETUP);
  const outs = [s, call(d, { op: "read", actor: "maya", asset: "brief", request_id: "s1" }), call(d, { op: "read", actor: "omar", asset: "brief", request_id: "s2" })];
  check("SECRET-output", !outs.some((o) => leaks(o, SECRET)), "key_material never in stdout/stderr");
  const disk = filesUnder(d).map((f) => readFileSync(f));
  check("SECRET-disk-keymat", !disk.some((b) => b.includes(SECRET)), "key_material never written to disk");
  check("SECRET-disk-body", !disk.some((b) => b.includes(Buffer.from(BODY_O))), "plaintext bodies never on disk (audit/state)");
  if (process.platform !== "win32") {
    const loose = filesUnder(d).filter((f) => (statSync(f).mode & 0o077) !== 0);
    check("SECRET-perms", loose.length === 0, "all state files are 0600", loose.join(" "));
  }
}

// ---------------------------------------------------------------- 7. tampering (local attacker, disk write, no keys)
function tamperCase(id, what, mutate, expectFail = true) {
  const d = fresh("tamper");
  setup(d);
  call(d, { op: "read", actor: "maya", asset: "brief", request_id: "t1" });
  call(d, { op: "revoke", actor: "maya" });
  call(d, { op: "read", actor: "maya", asset: "brief", request_id: "t2" }); // denied, logged
  call(d, { op: "read", actor: "omar", asset: "brief", request_id: "t3" }); // denied, logged
  const note = mutate(d) ?? "";
  const r = call(d, { op: "read", actor: "maya", asset: "brief", request_id: "t4" });
  const a = call(d, { op: "audit", request_id: "t2" });
  const detected = r.json?.error === "integrity_failure" || a.json?.error === "integrity_failure";
  check(id, expectFail ? detected : !detected, what, `${note} read→${r.stdout.trim().slice(0, 50)} audit(t2)→${a.stdout.trim().slice(0, 50)}`);
  return d;
}
const stateFile = (d) => join(d, "state.json");
tamperCase("TAMPER-state-edit", "editing state.json (un-revoke) fails closed", (d) => {
  const f = JSON.parse(readFileSync(stateFile(d), "utf8"));
  f.body = f.body.replace('"revoked":["maya"]', '"revoked":[]');
  writeFileSync(stateFile(d), JSON.stringify(f));
});
{
  // Roll back state.json to the copy saved before the revoke.
  const d = fresh("rollback");
  setup(d);
  const before = readFileSync(stateFile(d));
  call(d, { op: "revoke", actor: "maya" });
  writeFileSync(stateFile(d), before);
  const r = call(d, { op: "read", actor: "maya", asset: "brief", request_id: "rb" });
  check("TAMPER-state-rollback", r.json?.error === "integrity_failure", "restoring pre-revoke state.json fails closed", r.stdout.trim());
}
tamperCase("TAMPER-log-truncate", "cutting the last audit records fails closed", (d) => {
  const lines = readFileSync(join(d, "audit.jsonl"), "utf8").trim().split("\n");
  writeFileSync(join(d, "audit.jsonl"), lines.slice(0, -2).join("\n") + "\n");
});
tamperCase("TAMPER-log-truncate-nohead", "truncating the log after deleting audit.head.json + keys/audit.pub is detected", (d) => {
  const lines = readFileSync(join(d, "audit.jsonl"), "utf8").trim().split("\n");
  writeFileSync(join(d, "audit.jsonl"), lines.slice(0, -2).join("\n") + "\n");
  unlinkSync(join(d, "audit.head.json"));
  unlinkSync(join(d, "keys", "audit.pub"));
  return "removed 2 denied-read records, head and pub;";
});
tamperCase("TAMPER-log-corrupt-line", "a corrupted audit line fails closed with integrity_failure (not internal_error)", (d) => {
  const p = join(d, "audit.jsonl");
  writeFileSync(p, readFileSync(p, "utf8").replace(/\n$/, "") + "\n{not json\n");
});
{
  const d = fresh("nokey");
  setup(d);
  unlinkSync(join(d, "keys", "audit.key"));
  const r = call(d, { op: "read", actor: "maya", asset: "brief", request_id: "nk" });
  const last = readFileSync(join(d, "audit.jsonl"), "utf8").trim().split("\n").at(-1);
  const sig = JSON.parse(last).sig;
  check("TAMPER-audit-key-deleted", r.json?.error === "integrity_failure" || (sig && sig.length > 0), "deleting keys/audit.key does not silently produce unsigned records", `read→${r.stdout.trim().slice(0, 40)} last sig length=${sig?.length ?? 0}`);
  const v = spawnSync(process.execPath, [join(ROOT, "dist/core/ops.js"), "verify-log"], { env: { ...process.env, TRACK4_STATE_DIR: d } });
  // Either no record was written (the service failed closed: verify ok, nothing unsigned) or verify-log flags it.
  const vOut = v.stdout.toString();
  check("TAMPER-audit-key-deleted-verify", r.json?.error === "integrity_failure" ? vOut.includes('"ok":true') : vOut.includes('"ok":false'), "no unsigned record is ever accepted by verify-log", vOut.trim().slice(0, 90));
}
tamperCase("TAMPER-master-swap", "replacing keys/master.key fails closed", (d) => {
  writeFileSync(join(d, "keys", "master.key"), Buffer.alloc(32, 7).toString("base64"));
});

// ---------------------------------------------------------------- 8. state directory planting (POSIX)
if (process.platform !== "win32") {
  const base = fresh("plant");
  const victim = join(base, "victim"); mkdirSync(victim);
  const link = join(base, "state"); symlinkSync(victim, link);
  const r = call(link, SETUP);
  check("PLANT-symlink-root", r.json?.ready !== true && readdirSync(victim).length === 0, "symlinked state dir refused", r.stdout.trim());
  const d = fresh("plant2"); setup(d);
  rmSync(join(d, "audit.jsonl"));
  symlinkSync("/etc/passwd", join(d, "audit.jsonl"));
  const r2 = call(d, { op: "read", actor: "maya", asset: "brief", request_id: "p" });
  check("PLANT-symlink-file", !r2.stdout.includes("root:"), "symlinked audit file does not leak or get written", r2.stdout.trim().slice(0, 60));
}

// ---------------------------------------------------------------- 9. stale lock + concurrency
{
  const d = fresh("lock");
  setup(d);
  writeFileSync(join(d, ".lock"), "999999 0");
  const t0 = performance.now();
  const r = call(d, { op: "read", actor: "maya", asset: "brief", request_id: "l1" });
  check("LOCK-dead-pid", r.json?.decision === "allow" && performance.now() - t0 < 2000, "lock left by a dead PID is broken quickly", `${Math.round(performance.now() - t0)} ms`);
}
{
  const d = fresh("conc");
  setup(d);
  const N = 40;
  const reqs = [];
  for (let i = 0; i < N; i++) reqs.push(callAsync(d, { op: "read", actor: i % 2 ? "maya" : "omar", asset: "brief", request_id: `c${i}` }));
  reqs.push(callAsync(d, { op: "revoke", actor: "omar" }));
  const res = await Promise.all(reqs);
  const errors = res.filter((r) => !r.json || r.json.error);
  check("CONC-no-errors", errors.length === 0, `${N} parallel reads + revoke all answered`, errors.slice(0, 2).map((e) => e.stdout.trim() || e.stderr.trim()).join(" | "));
  let recorded = 0;
  for (let i = 0; i < N; i++) if (call(d, { op: "audit", request_id: `c${i}` }).json?.decision) recorded++;
  check("CONC-all-recorded", recorded === N, "every parallel decision is in the audit log", `${recorded}/${N}`);
  const v = spawnSync(process.execPath, [join(ROOT, "dist/core/ops.js"), "verify-log"], { env: { ...process.env, TRACK4_STATE_DIR: d } });
  check("CONC-chain-valid", v.stdout.toString().includes('"ok":true'), "audit chain + signatures still verify", v.stdout.toString().trim().slice(0, 80));
}

// A lock left by a dead process, then a burst of parallel requests: several waiters may
// judge the lock dead at once; if one deletes a lock another has just taken, two
// processes enter the critical section together and fork the audit chain.
{
  let broken = 0; const rounds = Number(process.env.RT_LOCK_ROUNDS ?? 8); const why = new Set();
  for (let round = 0; round < rounds; round++) {
    const d = fresh("stale");
    setup(d);
    writeFileSync(join(d, ".lock"), "999999 0");
    const N = 30;
    const res = await Promise.all(Array.from({ length: N }, (_, i) => callAsync(d, { op: "read", actor: "maya", asset: "brief", request_id: `s${i}` })));
    const v = spawnSync(process.execPath, [join(ROOT, "dist/core/ops.js"), "verify-log"], { env: { ...process.env, TRACK4_STATE_DIR: d } });
    const after = call(d, { op: "read", actor: "maya", asset: "brief", request_id: "after" });
    const errs = res.filter((r) => !r.json || r.json.error).map((r) => (r.stdout.trim() || r.stderr.trim()).slice(0, 60));
    const chainOk = v.stdout.toString().includes('"ok":true');
    if (errs.length || !chainOk || after.json?.decision !== "allow") {
      broken++;
      why.add(`errors=[${[...new Set(errs)].join("|")}] chain=${chainOk ? "ok" : v.stdout.toString().trim().slice(0, 70)} after=${after.stdout.trim().slice(0, 40)}`);
    }
  }
  check("LOCK-stale-burst", broken === 0, "stale lock + 30 parallel requests never lets two writers in", `${broken}/${rounds} rounds broke: ${[...why].join(" ;; ")}`);
}

// ---------------------------------------------------------------- 10. latency growth with log size
{
  const d = fresh("perf");
  setup(d);
  const sample = (n) => { const t = []; for (let i = 0; i < n; i++) t.push(call(d, { op: "read", actor: "maya", asset: "brief", request_id: `p-${Math.random()}` }).ms); return t.sort((a, b) => a - b)[Math.floor(n / 2)]; };
  const early = sample(15);
  // Grow the log to ~3000 records the same way the service would (through real requests in parallel batches).
  const target = Number(process.env.RT_PERF_RECORDS ?? 1500);
  for (let done = 0; done < target; done += 50) {
    await Promise.all(Array.from({ length: 50 }, (_, i) => callAsync(d, { op: "read", actor: "maya", asset: "brief", request_id: `g${done + i}` })));
  }
  const late = sample(15);
  const records = readFileSync(join(d, "audit.jsonl"), "utf8").trim().split("\n").length;
  check("PERF-growth", late < early * 1.5, "per-request latency stays flat as the audit log grows", `median ${early.toFixed(0)} ms at start → ${late.toFixed(0)} ms at ${records} records`);
}

const findings = results.filter((r) => !r.ok);
process.stdout.write(`\n${results.length - findings.length} pass, ${findings.length} finding(s)\n`);
process.exitCode = 0;
