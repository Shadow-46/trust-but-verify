import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { statePaths } from "../core/store/paths.ts";
import { ENTRY, freshStateDir, SETUP } from "./helpers.ts";

function callEnv(dir: string, req: unknown, env: Record<string, string>) {
  const r = spawnSync(process.execPath, [ENTRY], {
    input: JSON.stringify(req),
    env: { ...process.env, TRACK4_STATE_DIR: dir, TRACK4_MASTER_KEY: "", ...env },
    encoding: "utf8",
  });
  return JSON.parse(r.stdout) as Record<string, unknown>;
}

function consistentRollback(env: Record<string, string>) {
  const dir = freshStateDir();
  const p = statePaths(dir);
  const saved = mkdtempSync(join(tmpdir(), "tbv-saved-"));
  callEnv(dir, SETUP, env);
  // Attacker snapshots state, log and log head together (an internally consistent copy).
  for (const f of [p.state, p.audit, p.auditHead]) copyFileSync(f, join(saved, f.split(/[\\/]/).pop() as string));
  callEnv(dir, { op: "revoke", actor: "maya" }, env);
  for (const f of [p.state, p.audit, p.auditHead]) copyFileSync(join(saved, f.split(/[\\/]/).pop() as string), f);
  return callEnv(dir, { op: "read", actor: "maya", asset: "brief", request_id: "after" }, env);
}

test("with a witness, rolling back state and log together is detected", () => {
  const witness = mkdtempSync(join(tmpdir(), "tbv-witness-"));
  assert.deepEqual(consistentRollback({ TRACK4_WITNESS_DIR: witness }), { error: "integrity_failure" });
});

test("without a witness, the same consistent rollback is the documented limitation", () => {
  assert.equal(consistentRollback({}).decision, "allow");
});
