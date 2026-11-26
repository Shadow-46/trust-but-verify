import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { copyFileSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ControlPlane } from "../core/cluster/control.ts";
import { ClusterNode, signRequest } from "../core/cluster/node.ts";
import type { AccessRequest, RequestOp } from "../core/cluster/node.ts";
import { signPolicy } from "../core/cluster/policy.ts";
import { generateSigningKeyPair } from "../core/crypto/sign.ts";
import type { SigningKeyPair } from "../core/crypto/sign.ts";
import { freshStateDir } from "./helpers.ts";

const GRACE = 1_000;

type Device = { id: string; owner: string; keys: SigningKeyPair };

function cluster(names = ["node-a", "node-b", "node-c"]) {
  const base = freshStateDir();
  const t0 = Date.now();
  const cp = ControlPlane.create(join(base, "control"), { graceMs: GRACE, now: t0 });
  const nodes = names.map((n) => new ClusterNode(n, join(base, n), cp.anchor, cp.paths.published));
  const syncAll = (now = Date.now()) => nodes.map((n) => n.sync(now));
  const device = (owner: string, id: string): Device => {
    const d = { id, owner, keys: generateSigningKeyPair() };
    cp.enrolDevice(owner, id, d.keys.publicKey);
    return d;
  };
  return { base, cp, nodes, syncAll, device, t0 };
}

function req(d: Device, now: number, extra: Partial<AccessRequest> = {}) {
  const r: AccessRequest = {
    actor: d.owner,
    device_id: d.id,
    key_version: 1,
    op: "request" as RequestOp,
    transfer_id: null,
    nonce: randomBytes(12).toString("hex"),
    ts: now,
    ...extra,
  };
  return signRequest(d.keys.privateKey, r);
}

const decisions = (nodes: ClusterNode[], r: ReturnType<typeof req>, now: number) =>
  nodes.map((n) => n.authorize(r, now).decision);

test("signed device requests are allowed; forged, replayed and stale ones are denied", () => {
  const { nodes, syncAll, device } = cluster();
  const laptop = device("maya", "maya-laptop");
  const intruder = { ...laptop, keys: generateSigningKeyPair() }; // claims maya's device id
  syncAll();
  const now = Date.now();
  const ok = req(laptop, now);
  assert.deepEqual(nodes.map((n) => n.authorize(ok, now).reason), ["authorized", "authorized", "authorized"]);
  assert.equal(nodes[0].authorize(ok, now).reason, "replayed_request");
  assert.equal(nodes[0].authorize(req(intruder, now), now).reason, "bad_signature");
  assert.equal(nodes[0].authorize(req(laptop, now - 60_000), now).reason, "stale_or_future_request");
  const tampered = { ...req(laptop, now), actor: "omar" };
  assert.equal(nodes[0].authorize(tampered, now).reason, "device_owner_mismatch");
});

test("lost device: revocation reaches every node, owner re-enrols, other users keep access", () => {
  const { cp, nodes, syncAll, device } = cluster();
  const phone = device("maya", "maya-phone");
  const laptop = device("maya", "maya-laptop");
  const omar = device("omar", "omar-laptop");
  syncAll();

  const revokedAt = Date.now();
  cp.revokeDevice("maya-phone", revokedAt);
  // Only node-a has synced so far: the others still enforce the previous epoch.
  nodes[0].sync(revokedAt);
  assert.deepEqual(decisions(nodes, req(phone, revokedAt), revokedAt), ["deny", "allow", "allow"]);
  syncAll(revokedAt + 5);
  assert.deepEqual(decisions(nodes, req(phone, revokedAt + 5), revokedAt + 5), ["deny", "deny", "deny"]);
  assert.equal(nodes[1].authorize(req(phone, revokedAt + 6), revokedAt + 6).reason, "device_revoked");

  // Same owner, other device, and other users are unaffected.
  assert.deepEqual(decisions(nodes, req(laptop, revokedAt + 7), revokedAt + 7), ["allow", "allow", "allow"]);
  assert.deepEqual(decisions(nodes, req(omar, revokedAt + 8), revokedAt + 8), ["allow", "allow", "allow"]);

  // Re-enrolment with a brand-new key pair.
  const phone2 = device("maya", "maya-phone-2");
  syncAll();
  const now = Date.now();
  assert.deepEqual(decisions(nodes, req(phone2, now), now), ["allow", "allow", "allow"]);
  assert.deepEqual(decisions(nodes, req(phone, now + 1), now + 1), ["deny", "deny", "deny"]);
});

test("revoking an identity disables all of its devices on every node", () => {
  const { cp, nodes, syncAll, device } = cluster();
  const a = device("omar", "omar-laptop");
  const b = device("omar", "omar-phone");
  cp.revokeActor("omar");
  syncAll();
  const now = Date.now();
  for (const d of [a, b]) assert.deepEqual(decisions(nodes, req(d, now), now), ["deny", "deny", "deny"]);
});

test("key rotation: old version accepted until the cutoff, then rejected everywhere; in-flight transfers finish", () => {
  const { cp, nodes, syncAll, device } = cluster();
  const laptop = device("maya", "maya-laptop");
  syncAll();
  const t = Date.now();
  const { newVersion, cutoff } = cp.rotateKey(t);
  assert.equal(newVersion, 2);
  assert.equal(cutoff, t + GRACE);
  syncAll(t + 1);

  // During the grace period both versions work, and a transfer starts on v1 at every node.
  const before = t + GRACE - 10;
  assert.deepEqual(decisions(nodes, req(laptop, before, { key_version: 1 }), before), ["allow", "allow", "allow"]);
  assert.deepEqual(decisions(nodes, req(laptop, before, { key_version: 2 }), before), ["allow", "allow", "allow"]);
  for (const n of nodes) {
    const begin = req(laptop, before, { key_version: 1, op: "begin_transfer", transfer_id: `tx-${n.name}` });
    assert.equal(n.authorize(begin, before).decision, "allow");
  }

  // After the cutoff: new v1 requests and new v1 transfers are rejected on every node ...
  const after = cutoff + 1;
  const reasons = nodes.map((n) => n.authorize(req(laptop, after, { key_version: 1 }), after).reason);
  assert.deepEqual(reasons, ["key_version_retired", "key_version_retired", "key_version_retired"]);
  const lateBegin = req(laptop, after, { key_version: 1, op: "begin_transfer", transfer_id: "tx-late" });
  assert.equal(nodes[0].authorize(lateBegin, after).reason, "key_version_retired");
  // ... while transfers authorized before the cutoff complete on their original version.
  for (const n of nodes) {
    const chunk = req(laptop, after, { key_version: 1, op: "chunk", transfer_id: `tx-${n.name}` });
    assert.equal(n.authorize(chunk, after).reason, "in_flight_transfer");
  }
  // A chunk cannot ride on a transfer it does not own.
  const hijack = req(laptop, after, { key_version: 1, op: "chunk", transfer_id: "tx-never-started" });
  assert.equal(nodes[0].authorize(hijack, after).reason, "unknown_transfer");
  assert.deepEqual(decisions(nodes, req(laptop, after, { key_version: 2 }), after), ["allow", "allow", "allow"]);
});

test("revoking a device stops its in-flight transfer, and unknown ops are denied", () => {
  const { cp, nodes, syncAll, device } = cluster(["node-a"]);
  const phone = device("maya", "maya-phone");
  syncAll();
  const t = Date.now();
  assert.equal(nodes[0].authorize(req(phone, t, { op: "begin_transfer", transfer_id: "tx" }), t).decision, "allow");
  cp.revokeDevice("maya-phone", t + 1);
  syncAll(t + 2);
  const chunk = req(phone, t + 3, { op: "chunk", transfer_id: "tx" });
  assert.equal(nodes[0].authorize(chunk, t + 3).reason, "device_revoked");
  const laptop = device("maya", "maya-laptop");
  syncAll();
  const bogus = req(laptop, Date.now(), { op: "delete_everything" as RequestOp });
  assert.equal(nodes[0].authorize(bogus).reason, "invalid_op");
});

test("nodes refuse forged policies and rollback to an older epoch", () => {
  const { base, cp, nodes, syncAll, device } = cluster();
  device("maya", "maya-phone");
  syncAll();
  const oldCopy = join(base, "old-policy.json");
  copyFileSync(cp.paths.published, oldCopy);
  cp.revokeDevice("maya-phone");
  syncAll();
  const epoch = nodes[0].epoch;

  // Rollback: replay a genuinely signed but older policy (from before the revocation).
  copyFileSync(oldCopy, cp.paths.published);
  assert.deepEqual(nodes[0].sync(), { status: "rejected", epoch, reason: "rollback" });

  // Forgery: a policy with a higher epoch signed by someone else's key.
  const evil = generateSigningKeyPair();
  const forged = { ...cp.policy, epoch: epoch + 100, devices: [], revoked_actors: [] };
  writeFileSync(cp.paths.published, JSON.stringify(signPolicy(evil.privateKey, forged)));
  assert.deepEqual(nodes[0].sync(), { status: "rejected", epoch, reason: "bad_signature" });
  assert.equal(nodes[0].policy?.devices.find((d) => d.device_id === "maya-phone")?.status, "revoked");
});

test("a restarted node enforces its last verified policy even if the control plane is unreachable", () => {
  const { cp, nodes, syncAll, device } = cluster(["node-a"]);
  const phone = device("maya", "maya-phone");
  cp.revokeDevice("maya-phone");
  syncAll();
  rmSync(cp.paths.published); // control plane gone
  const restarted = new ClusterNode("node-a", nodes[0].dir, cp.anchor, cp.paths.published);
  assert.equal(restarted.epoch, nodes[0].epoch);
  const now = Date.now();
  assert.equal(restarted.authorize(req(phone, now), now).reason, "device_revoked");
  assert.equal(restarted.sync().status, "rejected");
  assert.ok(readFileSync(join(nodes[0].dir, "ack.json"), "utf8").includes('"epoch"'));
});
