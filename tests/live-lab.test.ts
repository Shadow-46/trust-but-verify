import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { handle } from "../core/adapter.ts";
import { clusterInit, NODE_NAMES } from "../core/demo/liveCluster.ts";
import { labCatalog, labStart, labStep } from "../core/demo/liveLab.ts";
import { statePaths } from "../core/store/paths.ts";
import { freshStateDir } from "./helpers.ts";

const DEMO = {
  op: "setup",
  owners: { "design-doc": "maya", "payroll.xlsx": "omar", roadmap: "maya", "budget.xlsx": "lee" },
  contents: { "design-doc": "Q3 design (confidential)", "payroll.xlsx": "salary bands (confidential)", roadmap: "2027 roadmap", "budget.xlsx": "budget v2" },
  disabled: ["dana"],
  key_material: "synthetic-live-lab-test",
};

test("every live Attack Lab storyboard runs against the live service and ends defended and healthy", { timeout: 120_000 }, async () => {
  const base = freshStateDir();
  const env = {
    TRACK4_STATE_DIR: join(base, "state"),
    TRACK4_LAB_DIR: join(base, "lab"),
    TRACK4_CLUSTER_DIR: join(base, "cluster"),
    TRACK4_WITNESS_DIR: join(base, "witness"),
    TRACK4_AUTO_QUARANTINE: "1",
  };
  const saved = Object.fromEntries(Object.keys(env).map((k) => [k, process.env[k]]));
  Object.assign(process.env, env);
  mkdirSync(env.TRACK4_WITNESS_DIR, { recursive: true });
  const nodes: ChildProcess[] = [];
  try {
    const paths = statePaths(env.TRACK4_STATE_DIR);
    assert.deepEqual(handle(JSON.stringify(DEMO), paths).body, { ready: true });
    clusterInit(env.TRACK4_CLUSTER_DIR);
    for (const n of NODE_NAMES) {
      nodes.push(spawn(process.execPath, [join(import.meta.dirname, "..", "core", "cluster", "nodeProcess.ts"), n, join(env.TRACK4_CLUSTER_DIR, n), join(env.TRACK4_CLUSTER_DIR, "control"), "20"], { stdio: "ignore" }));
    }
    await new Promise((r) => setTimeout(r, 1500)); // nodes adopt the first policy

    for (const a of labCatalog().filter((x) => x.live)) {
      const start = labStart(a.id) as { run_id?: string; error?: string; message?: string };
      assert.ok(start.run_id, `${a.id}: ${start.error} ${start.message ?? ""}`);
      let last: { tone: string; evidence: string } | undefined;
      type Ev = { tone: string; evidence: string; checks: { pass: boolean }[]; records: { service: string }[]; alerts: { rule: string; identity: string; service: string; events: string }[] };
      const events: Ev[] = [];
      for (let i = 0; i < a.steps.length; i++) {
        const r = labStep(start.run_id!) as { event: Ev };
        assert.notEqual(r.event.tone, "bad", `${a.id} step ${i + 1}: ${r.event.evidence}`);
        last = r.event;
        events.push(r.event);
        await new Promise((res) => setTimeout(res, 50)); // let node processes poll between steps
      }
      assert.equal(last?.tone, "good", `${a.id} must end defended: ${last?.evidence}`);
      // Every live attack is detected: at least one alert naming identity, service and event.
      const alerts = events.flatMap((e) => e.alerts);
      assert.ok(alerts.length > 0, `${a.id}: no security alert raised`);
      for (const al of alerts) assert.ok(al.identity && al.service && al.events && al.events !== "-", `${a.id}: ${al.rule} must name identity, service and event`);
      // Every step's outcome is read back from signed logs; cluster attacks land in the nodes' own logs.
      if (a.needs_cluster) assert.ok(events.some((e) => e.records.some((x) => x.service.startsWith("node-"))), `${a.id}: no node log record`);
      // The live service is healthy after every storyboard (destructive ones recover).
      const probe = handle(JSON.stringify({ op: "read", actor: "omar", asset: "payroll.xlsx", request_id: `probe-${a.id}` }), paths).body as Record<string, unknown>;
      assert.equal(probe.error, undefined, `${a.id} left the service unhealthy`);
      if (a.id === "state-rollback") {
        // reset maya for later storyboards that expect a fresh demo
        assert.deepEqual(handle(JSON.stringify({ ...DEMO, key_material: "synthetic-live-lab-test-2" }), paths).body, { ready: true });
      }
    }
  } finally {
    for (const n of NODE_NAMES) writeFileSync(join(env.TRACK4_CLUSTER_DIR, n, "stop"), "");
    for (const p of nodes) p.kill();
    for (const [k, v] of Object.entries(saved)) if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});
