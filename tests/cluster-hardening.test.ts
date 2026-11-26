import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ControlPlane } from "../core/cluster/control.ts";
import { ClusterNode, signRequest } from "../core/cluster/node.ts";
import type { AccessRequest } from "../core/cluster/node.ts";
import { generateSigningKeyPair } from "../core/crypto/sign.ts";
import { freshStateDir } from "./helpers.ts";

function cluster() {
  const base = freshStateDir();
  const cp = ControlPlane.create(join(base, "control"));
  const phone = generateSigningKeyPair();
  cp.enrolDevice("maya", "maya-phone", phone.publicKey);
  const nodeDir = join(base, "node-a");
  const start = () => {
    const n = new ClusterNode("node-a", nodeDir, cp.anchor, cp.paths.published);
    n.sync();
    return n;
  };
  const req = (op: AccessRequest["op"], transfer_id: string | null = null) =>
    signRequest(phone.privateKey, { actor: "maya", device_id: "maya-phone", key_version: 1, op, transfer_id, nonce: randomBytes(8).toString("hex"), ts: Date.now() });
  return { base, cp, nodeDir, start, req };
}

test("a replayed request is still refused after the node restarts", () => {
  const { start, req } = cluster();
  const r = req("request");
  assert.equal(start().authorize(r).decision, "allow");
  const restarted = start(); // new process, same node directory
  assert.deepEqual([restarted.authorize(r).decision, restarted.authorize(r).reason], ["deny", "replayed_request"]);
});

test("an in-flight transfer survives a node restart", () => {
  const { start, req } = cluster();
  assert.equal(start().authorize(req("begin_transfer", "t-1")).decision, "allow");
  const d = start().authorize(req("chunk", "t-1"));
  assert.deepEqual([d.decision, d.reason], ["allow", "in_flight_transfer"]);
});

test("a newly provisioned node never trusts a policy older than its floor", () => {
  const { base, cp } = cluster();
  const before = readFileSync(cp.paths.published, "utf8"); // genuine, signed, but from before the revocation
  cp.revokeDevice("maya-phone");
  const oldFile = join(base, "old-policy.json");
  writeFileSync(oldFile, before);

  // Without provisioning, a blank node would adopt the old policy (the documented gap) ...
  const naive = new ClusterNode("naive", join(base, "naive"), cp.anchor, oldFile);
  assert.equal(naive.sync().status, "adopted");

  // ... a provisioned node refuses it and only accepts the current or a newer one.
  const nodeDir = join(base, "node-new");
  cp.provision(nodeDir);
  const fresh = ClusterNode.provisioned("node-new", nodeDir, oldFile);
  assert.deepEqual(fresh.sync(), { status: "rejected", epoch: 0, reason: "below_floor" });
  assert.equal(fresh.adoptText(readFileSync(cp.paths.published, "utf8")).status, "adopted");
  assert.equal(fresh.epoch, cp.policy.epoch);
});
