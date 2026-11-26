import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runAttack } from "../core/demo/attacks.ts";

test("every Attack Lab attack is blocked", () => {
  const results = runAttack("all");
  assert.equal(results.length, 15);
  for (const r of results) assert.ok(r.blocked, `${r.id}: ${r.evidence}`);
});

test("Attack Lab never writes to the operator's witness", () => {
  const witness = mkdtempSync(join(tmpdir(), "tbv-op-witness-"));
  const before = process.env.TRACK4_WITNESS_DIR;
  process.env.TRACK4_WITNESS_DIR = witness;
  try {
    const results = runAttack("all");
    for (const r of results) assert.ok(r.blocked, `${r.id}: ${r.evidence}`);
    assert.deepEqual(readdirSync(witness), []);
  } finally {
    if (before === undefined) delete process.env.TRACK4_WITNESS_DIR;
    else process.env.TRACK4_WITNESS_DIR = before;
  }
});
