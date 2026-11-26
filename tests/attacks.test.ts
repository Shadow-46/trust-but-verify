import { test } from "node:test";
import assert from "node:assert/strict";
import { runAttack } from "../core/demo/attacks.ts";

test("every Attack Lab attack is blocked", () => {
  const results = runAttack("all");
  assert.equal(results.length, 12);
  for (const r of results) assert.ok(r.blocked, `${r.id}: ${r.evidence}`);
});
