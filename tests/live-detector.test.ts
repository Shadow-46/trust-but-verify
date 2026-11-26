import assert from "node:assert/strict";
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { describe, test } from "node:test";
import { readAudit } from "../core/audit/log.ts";
import type { AuditRecord } from "../core/audit/log.ts";
import {
  DEFAULT_LIVE,
  alertsPath,
  evaluateDecision,
  onDecision,
  onIntegrityFailure,
  onInvalidRequest,
  readAlerts,
  verifyAlerts,
} from "../core/detector/live.ts";
import { statePaths } from "../core/store/paths.ts";
import { SETUP, call, freshStateDir } from "./helpers.ts";

// ---- pure rules on synthetic audit records ----------------------------------------
let seq = 0;
function rec(p: Partial<AuditRecord>, secondsAgo = 0): AuditRecord {
  seq++;
  return {
    seq, ts: new Date(Date.UTC(2026, 10, 26, 22, 0, 0) - secondsAgo * 1000).toISOString(),
    type: "access_decision", request_id: `r${seq}`, actor: "mallory", asset: "brief",
    decision: "deny", reason: "not_owner", state_version: 1, prev: "", hash: "", sig: "", ...p,
  };
}
const rules = (rs: AuditRecord[]) => evaluateDecision(rs, rs.at(-1)!).map((a) => a.rule);

describe("live rules (pure)", () => {
  test("probing: 5 denials on others' / unknown assets within 60 s", () => {
    const four = [rec({}, 40), rec({ reason: "unknown_asset" }, 30), rec({}, 20), rec({}, 10)];
    assert.deepEqual(rules(four), []);
    const five = [...four, rec({ asset: "ledger" })];
    const [a] = evaluateDecision(five, five.at(-1)!);
    assert.equal(a.rule, "probing");
    assert.equal(a.count, 5);
    assert.equal(a.response, "recorded");
    assert.equal(a.evidence.length, 5);
  });

  test("probing ignores old denials, other actors and allows", () => {
    const rs = [rec({}, 300), rec({}, 200), rec({ actor: "maya" }), rec({ decision: "allow", reason: "owner" }), rec({}, 5), rec({})];
    assert.deepEqual(rules(rs), []);
  });

  test("revoked identity reuse: 3 attempts -> quarantined, high", () => {
    const rs = [rec({ actor: "maya", reason: "revoked" }, 120), rec({ actor: "maya", reason: "revoked" }, 60), rec({ actor: "maya", reason: "revoked" })];
    const [a] = evaluateDecision(rs, rs.at(-1)!);
    assert.equal(a.rule, "revoked_identity_reuse");
    assert.equal(a.severity, "high");
    assert.equal(a.response, "quarantined");
  });

  test("request-ID abuse alerts on the first attempt", () => {
    const rs = [rec({ type: "duplicate_request_id", reason: "request_id_reused" })];
    assert.deepEqual(rules(rs), ["request_id_abuse"]);
  });

  test("decryption integrity failure is fail-closed", () => {
    const [a] = evaluateDecision([rec({ actor: "maya", reason: "integrity_failure" })], rec({ actor: "maya", reason: "integrity_failure" }));
    assert.equal(a.response, "fail_closed");
  });

  test("an allowed read never alerts", () => {
    assert.deepEqual(rules([rec({ decision: "allow", reason: "owner", actor: "maya" })]), []);
  });
});

// ---- hooks against a real adapter state dir -----------------------------------------
function withState() {
  const dir = freshStateDir();
  call(dir, SETUP);
  return { dir, paths: statePaths(dir) };
}
/** Run a read through the real adapter, then the hook, the way the adapter will. */
function readAndDetect(paths: ReturnType<typeof statePaths>, dir: string, actor: string, asset: string, id: string) {
  const reply = call(dir, { op: "read", actor, asset, request_id: id });
  const records = readAudit(paths);
  return { reply, alerts: onDecision(paths, records, records.at(-1)!) };
}

describe("live hooks on real adapter state", () => {
  test("lost device keeps trying after revocation -> one signed, quarantined alert", () => {
    const { dir, paths } = withState();
    call(dir, { op: "revoke", actor: "maya" });
    const raised = [];
    for (let i = 0; i < 4; i++) {
      const { reply, alerts } = readAndDetect(paths, dir, "maya", "brief", `lost${i}`);
      assert.deepEqual(reply.out, { decision: "deny" }); // reply never changes
      raised.push(...alerts);
    }
    assert.equal(raised.length, 1, "deduplicated: alert once, not on every attempt");
    const [a] = readAlerts(paths);
    assert.equal(a.rule, "revoked_identity_reuse");
    assert.equal(a.actor, "maya");
    assert.deepEqual(a.evidence, ["lost0", "lost1", "lost2"]);
    const v = verifyAlerts(paths);
    assert.equal(v.ok, true);
    assert.equal(v.signatures_checked, true);
  });

  test("probing other people's files is detected; the real owner still reads normally", () => {
    const { dir, paths } = withState();
    for (let i = 0; i < 5; i++) readAndDetect(paths, dir, "maya", i % 2 ? "ledger" : `secret-${i}`, `p${i}`);
    assert.equal(readAlerts(paths)[0]?.rule, "probing");
    const own = call(dir, { op: "read", actor: "maya", asset: "brief", request_id: "own" });
    assert.equal(own.out.decision, "allow"); // no lockout of a name an attacker can spoof
  });

  test("editing an alert breaks verification at that record", () => {
    const { dir, paths } = withState();
    call(dir, { op: "revoke", actor: "maya" });
    for (let i = 0; i < 3; i++) readAndDetect(paths, dir, "maya", "brief", `e${i}`);
    for (let i = 0; i < 5; i++) readAndDetect(paths, dir, "omar", "brief", `o${i}`);
    assert.equal(readAlerts(paths).length, 2);
    const p = alertsPath(paths);
    writeFileSync(p, readFileSync(p, "utf8").replace('"severity":"high"', '"severity":"medium"'));
    assert.deepEqual(verifyAlerts(paths).first_bad_seq, 1);
  });

  test("integrity failure alert is written even when the audit log is the broken part", () => {
    const { dir, paths } = withState();
    appendFileSync(paths.audit, "{not json\n");
    const a = onIntegrityFailure(paths, "audit log");
    assert.equal(a.length, 1);
    assert.equal(a[0].response, "fail_closed");
    assert.equal(onIntegrityFailure(paths, "audit log").length, 0, "deduplicated within a minute");
    assert.equal(verifyAlerts(paths).ok, true);
    void dir;
  });

  test("malformed burst: 10 invalid requests within 60 s -> alert; nothing before setup", () => {
    const empty = statePaths(freshStateDir());
    assert.deepEqual(onInvalidRequest(empty, "invalid_json"), []);
    const { paths } = withState();
    const t0 = Date.now();
    let fired = 0;
    for (let i = 0; i < 10; i++) fired += onInvalidRequest(paths, i % 2 ? "invalid_json" : "invalid_actor", DEFAULT_LIVE, new Date(t0 + i * 100)).length;
    assert.equal(fired, 1);
    const [a] = readAlerts(paths);
    assert.equal(a.rule, "malformed_burst");
    assert.deepEqual([...a.evidence].sort(), ["invalid_actor", "invalid_json"]);
  });

  test("alerts never contain request bodies or key material", () => {
    const { dir, paths } = withState();
    call(dir, { op: "revoke", actor: "maya" });
    for (let i = 0; i < 3; i++) readAndDetect(paths, dir, "maya", "brief", `s${i}`);
    const text = readFileSync(alertsPath(paths), "utf8");
    assert.ok(!text.includes(SETUP.key_material));
    assert.ok(!text.includes(SETUP.contents.brief));
  });
});
