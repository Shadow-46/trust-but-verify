import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { rotateStoredDataKey } from "../core/keys/rotation.ts";
import { readAudit, verifyAudit } from "../core/audit/log.ts";
import { statePaths } from "../core/store/paths.ts";
import { call, freshStateDir, SETUP } from "./helpers.ts";

test("stored data key rotation re-encrypts every asset and keeps policy intact", () => {
  const dir = freshStateDir();
  assert.deepEqual(call(dir, SETUP).out, { ready: true });
  call(dir, { op: "revoke", actor: "omar" });
  const paths = statePaths(dir);
  const before = readFileSync(paths.state, "utf8");

  assert.deepEqual(rotateStoredDataKey(paths), { from: 1, to: 2, reencrypted: 2 });
  const after = JSON.parse(JSON.parse(readFileSync(paths.state, "utf8")).body);
  assert.equal(after.keyring.active, 2);
  assert.deepEqual(after.keyring.keys.map((k: { version: number; status: string }) => [k.version, k.status]), [
    [1, "retired"],
    [2, "active"],
  ]);
  assert.ok(after.assets.every(([, r]: [string, { version: number }]) => r.version === 2));
  assert.notEqual(before, readFileSync(paths.state, "utf8"));

  // Owners still read exact bodies; the earlier revocation still holds.
  assert.deepEqual(call(dir, { op: "read", actor: "maya", asset: "brief", request_id: "k1" }).out, {
    decision: "allow",
    body: SETUP.contents.brief,
  });
  assert.deepEqual(call(dir, { op: "read", actor: "omar", asset: "ledger", request_id: "k2" }).out, { decision: "deny" });

  assert.deepEqual(rotateStoredDataKey(paths), { from: 2, to: 3, reencrypted: 2 });
  assert.equal(call(dir, { op: "read", actor: "maya", asset: "brief", request_id: "k3" }).out.body, SETUP.contents.brief);
  assert.equal(readAudit(paths).filter((r) => r.type === "key_rotation").length, 2);
  assert.equal(verifyAudit(paths).ok, true);
});
