import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { ControlPlane } from "../core/cluster/control.ts";
import { ClusterNode } from "../core/cluster/node.ts";
import { pullPolicy, servePolicy } from "../core/cluster/transport.ts";
import { generateSigningKeyPair } from "../core/crypto/sign.ts";
import { netClusterBench, netMessagingDemo } from "../core/demo/network.ts";
import { freshStateDir } from "./helpers.ts";

test("policy over HTTP: forged or older policies are refused; an unreachable control plane changes nothing", async () => {
  const base = freshStateDir();
  const cp = ControlPlane.create(join(base, "control"));
  cp.enrolDevice("maya", "maya-phone", generateSigningKeyPair().publicKey);
  cp.provision(join(base, "node"));
  const server = await servePolicy(cp.paths.dir);
  const url = `http://127.0.0.1:${server.port}/policy`;
  const node = ClusterNode.provisioned("node", join(base, "node"), url);
  try {
    assert.equal((await pullPolicy(node, url)).status, "adopted");
    cp.revokeDevice("maya-phone");
    assert.equal((await pullPolicy(node, url)).status, "adopted");
    assert.equal(server.acks.get("node")?.has(cp.policy.epoch - 1), true, "control plane saw the node's epoch");

    // A policy signed by someone else, served over the same wire, is refused.
    const rogue = ControlPlane.create(join(base, "rogue"));
    const rogueServer = await servePolicy(rogue.paths.dir);
    const r = await pullPolicy(node, `http://127.0.0.1:${rogueServer.port}/policy`);
    await rogueServer.close();
    assert.deepEqual([r.status, r.status === "rejected" && r.reason], ["rejected", "bad_signature"]);
  } finally {
    await server.close();
  }
  const cut = await pullPolicy(node, url, 300);
  assert.equal(cut.status, "unreachable");
  assert.equal(node.epoch, cp.policy.epoch, "node keeps enforcing its last verified policy");
});

test("three node processes converge over a lossy network and catch up after a partition", { timeout: 60_000 }, async () => {
  const r = await netClusterBench({ changes: 3, dropRate: 0.2, delayMs: 5 });
  assert.equal(r.propagation_ms.samples, 3);
  assert.equal(r.partition.nodes_that_adopted_while_cut_off, 0);
  assert.equal(r.partition.healed, true);
});

test("messaging over TCP between two processes: delivered; wire replay, tampering and oversized frames refused", { timeout: 30_000 }, async () => {
  const r = await netMessagingDemo("hello over the network");
  assert.equal(r.delivered, true);
  for (const a of r.attacks) assert.ok(a.blocked, `${a.name}: ${a.evidence}`);
});

test("policy server process: serves nodes, records acks on its own clock, drops a partitioned node", { timeout: 30_000 }, async () => {
  const { spawn } = await import("node:child_process");
  const { readFileSync, writeFileSync } = await import("node:fs");
  const base = freshStateDir();
  const cp = ControlPlane.create(join(base, "control"));
  const proc = spawn(process.execPath, [join(import.meta.dirname, "..", "core", "cluster", "policyServerProcess.ts"), cp.paths.dir], { stdio: ["ignore", "pipe", "ignore"] });
  try {
    const port = await new Promise<number>((resolve, reject) => {
      const t = setTimeout(() => reject(new Error("no ready line")), 10_000);
      proc.stdout!.on("data", (d: Buffer) => {
        const m = /ready (\d+)/.exec(d.toString());
        if (m) {
          clearTimeout(t);
          resolve(Number(m[1]));
        }
      });
    });
    const get = (node: string) => fetch(`http://127.0.0.1:${port}/policy`, { headers: { "x-node": node, "x-epoch": "0" } }).then((r) => r.status, () => "reset");
    assert.equal(await get("node-a"), 200);
    writeFileSync(join(cp.paths.dir, "blocked.json"), JSON.stringify(["node-a"]));
    await new Promise((r) => setTimeout(r, 250));
    assert.equal(await get("node-a"), "reset", "partitioned node is cut off");
    assert.equal(await get("node-b"), 200, "other nodes still served");
    await new Promise((r) => setTimeout(r, 250));
    const acks = JSON.parse(readFileSync(join(cp.paths.dir, "acks.json"), "utf8"));
    assert.equal(typeof acks.acks["node-a"]["0"], "number");
    assert.equal(acks.port, port);
  } finally {
    proc.kill();
  }
});
