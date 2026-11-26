import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { securityAlerts } from "../core/defense/guard.ts";
import { statePaths } from "../core/store/paths.ts";
import { ENTRY, freshStateDir, SETUP } from "./helpers.ts";

function callEnv(dir: string, req: unknown, extra: Record<string, string> = {}, raw?: string) {
  const r = spawnSync(process.execPath, [ENTRY], {
    input: raw ?? JSON.stringify(req),
    env: { ...process.env, TRACK4_STATE_DIR: dir, TRACK4_MASTER_KEY: "", ...extra },
    encoding: "utf8",
  });
  return JSON.parse(r.stdout) as Record<string, unknown>;
}

const probe = (dir: string, env: Record<string, string> = {}) => {
  for (const [i, asset] of ["brief", "nope-1", "nope-2"].entries()) callEnv(dir, { op: "read", actor: "omar", asset, request_id: `p${i}` }, env);
};

test("probing many files is detected and alerted; by default the identity is not locked out", () => {
  const dir = freshStateDir();
  callEnv(dir, SETUP);
  probe(dir);
  const alerts = securityAlerts(statePaths(dir));
  assert.ok(alerts.some((a) => a.rule === "probing" && a.actor === "omar"));
  assert.equal(alerts.some((a) => a.rule === "quarantined"), false);
  assert.deepEqual(callEnv(dir, { op: "read", actor: "omar", asset: "ledger", request_id: "own" }), { decision: "allow", body: SETUP.contents.ledger });
});

test("with auto-quarantine enabled, a probing identity is refused until reviewed", () => {
  const dir = freshStateDir();
  const env = { TRACK4_AUTO_QUARANTINE: "1" };
  callEnv(dir, SETUP, env);
  probe(dir, env);
  assert.ok(securityAlerts(statePaths(dir)).some((a) => a.rule === "quarantined" && a.actor === "omar"));
  assert.deepEqual(callEnv(dir, { op: "read", actor: "omar", asset: "ledger", request_id: "own" }, env), { decision: "deny" });
  assert.deepEqual(callEnv(dir, { op: "read", actor: "maya", asset: "brief", request_id: "m" }, env).decision, "allow");
});

test("malformed-input bursts and use of a revoked identity raise signed alerts", () => {
  const dir = freshStateDir();
  callEnv(dir, SETUP);
  for (let i = 0; i < 10; i++) callEnv(dir, undefined, {}, "{not json");
  callEnv(dir, { op: "revoke", actor: "maya" });
  callEnv(dir, { op: "read", actor: "maya", asset: "brief", request_id: "lost" });
  const rules = securityAlerts(statePaths(dir)).map((a) => a.rule);
  assert.ok(rules.includes("malformed_input_burst"));
  assert.ok(rules.includes("revoked_identity_used"));
});

test("every alert names the identity, the service and the triggering event(s)", async () => {
  const { readFileSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { verifyBytes } = await import("../core/crypto/sign.ts");
  const { readAudit } = await import("../core/audit/log.ts");
  const dir = freshStateDir();
  callEnv(dir, SETUP);
  probe(dir); // probing by omar: p0, p1, p2
  for (let i = 0; i < 10; i++) callEnv(dir, undefined, {}, "{not json"); // malformed burst (no identity)
  callEnv(dir, { op: "revoke", actor: "maya" });
  callEnv(dir, { op: "read", actor: "maya", asset: "brief", request_id: "lost-phone-1" });

  const paths = statePaths(dir);
  const alerts = securityAlerts(paths);
  assert.ok(alerts.length >= 3);
  for (const a of alerts) {
    assert.ok(a.identity.length > 0, `${a.rule}: identity`);
    assert.equal(a.service, "file-service adapter", `${a.rule}: service`);
    assert.ok(a.events.length > 0 && a.events !== "-", `${a.rule}: events`);
  }
  const probing = alerts.find((a) => a.rule === "probing")!;
  assert.equal(probing.identity, "omar");
  assert.match(probing.events, /^p0,p1,p2 \(audit seq \d+\)$/);
  const revoked = alerts.find((a) => a.rule === "revoked_identity_used")!;
  assert.equal(revoked.identity, "maya");
  assert.match(revoked.events, /^lost-phone-1 \(audit seq \d+\)$/);
  const burst = alerts.find((a) => a.rule === "malformed_input_burst")!;
  assert.equal(burst.identity, "unauthenticated caller");
  assert.match(burst.events, /^10 invalid requests between .+ and .+$/);

  // The audit record keeps the parseable text and the triggering request as a structured field.
  const rec = readAudit(paths).find((r) => r.type === "security_alert" && r.reason?.startsWith("revoked_identity_used"))!;
  assert.equal(rec.request_id, "lost-phone-1");
  assert.match(rec.reason ?? "", /^revoked_identity_used: identity=maya service=file-service adapter events=lost-phone-1 seq=\d+ — /);

  // Side-file alerts carry identity, service and event inside the ML-DSA-signed body.
  const side = JSON.parse(readFileSync(join(dir, "security-alerts.jsonl"), "utf8").trim().split("\n")[0]);
  const pub = Buffer.from(readFileSync(paths.auditPub, "utf8"), "base64");
  const body = JSON.stringify(["tbv/alert/v2", side.ts, side.rule, side.identity, side.service, side.event, side.detail]);
  assert.equal(verifyBytes(pub, Buffer.from(body, "utf8"), Buffer.from(side.sig, "base64")), true);
  const forged = JSON.stringify(["tbv/alert/v2", side.ts, side.rule, "maya", side.service, side.event, side.detail]);
  assert.equal(verifyBytes(pub, Buffer.from(forged, "utf8"), Buffer.from(side.sig, "base64")), false);
});
