import { test } from "node:test";
import assert from "node:assert/strict";
import { generate } from "../core/detector/synth.ts";
import { evaluate } from "../core/detector/evaluate.ts";

test("synthetic generator is deterministic per seed and keeps ground truth out of the detector input", () => {
  const a = generate({ seed: 7, users: 10, incidents: 4, hard: true });
  const b = generate({ seed: 7, users: 10, incidents: 4, hard: true });
  assert.equal(a.csv, b.csv);
  assert.notEqual(a.csv, generate({ seed: 8, users: 10, incidents: 4, hard: true }).csv);
  assert.ok(!/inc-\d|malicious|incident/.test(a.csv), "labels must not leak into the CSV");
  assert.equal(a.incidents.length, 4);
  assert.ok(a.incidents.every((i) => i.event_ids.length > 0));
});

test("evaluation reports per-incident precision, recall, F1, time-to-alert and false alerts per 1,000", () => {
  const m = evaluate({ seed: 3, users: 15, incidents: 8, hard: true });
  assert.equal(m.incidents, 8);
  assert.ok(m.f1 >= 0 && m.f1 <= 1);
  assert.equal(m.tp_alerts + m.fp_alerts, m.alerts);
  assert.ok(m.median_tta_ms === null || m.median_tta_ms >= 0);
  assert.ok(m.fp_per_1000_benign >= 0);
});
