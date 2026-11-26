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
