import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { readAudit, verifyAudit } from "../core/audit/log.ts";
import { ControlPlane } from "../core/cluster/control.ts";
import { ClusterNode, signRequest } from "../core/cluster/node.ts";
import { signPolicy } from "../core/cluster/policy.ts";
import { generateSigningKeyPair } from "../core/crypto/sign.ts";
import { clusterAlerts, clusterLog, NODE_NAMES } from "../core/demo/liveCluster.ts";
import { freshStateDir } from "./helpers.ts";

function cluster() {
  const base = freshStateDir();
  const cp = ControlPlane.create(join(base, "control"));
  const phone = generateSigningKeyPair();
  cp.enrolDevice("maya", "maya-phone", phone.publicKey);
  const node = (name: string) => {
    const n = new ClusterNode(name, join(base, name), cp.anchor, cp.paths.published);
    n.sync();
    return n;
  };
  const req = (target: string) =>
    signRequest(phone.privateKey, { actor: "maya", device_id: "maya-phone", node: target, key_version: 1, op: "request", transfer_id: null, nonce: randomBytes(8).toString("hex"), ts: Date.now() });
  return { base, cp, node, req };
}

test("every node decision (allow and deny) lands in the node's own signed, hash-chained log", () => {
  const { node, req } = cluster();
  const a = node("node-a");
  const r = req("node-a");
  assert.equal(a.authorize(r).decision, "allow");
  assert.equal(a.authorize(r).reason, "replayed_request");
  const recs = readAudit(a.logPaths).filter((x) => x.type === "node_decision");
  assert.deepEqual(recs.map((x) => [x.decision, x.reason, x.actor, x.asset, x.request_id]), [
    ["allow", "authorized", "maya", "maya-phone", r.nonce],
    ["deny", "replayed_request", "maya", "maya-phone", r.nonce],
  ]);
  assert.ok(readAudit(a.logPaths).some((x) => x.type === "policy_adopted"));
  const v = verifyAudit(a.logPaths);
  assert.equal(v.ok, true);
  assert.equal(v.signatures_checked, true);

  // Editing a record (e.g. turning the replay deny into an allow) breaks verification.
  const p = a.logPaths.audit;
  writeFileSync(p, readFileSync(p, "utf8").replace('"decision":"deny","reason":"replayed_request"', '"decision":"allow","reason":"replayed_request"'));
  assert.equal(verifyAudit(a.logPaths).ok, false);
});

test("a restarted node keeps appending to the same signed chain; probes are never logged", () => {
  const { node, req } = cluster();
  node("node-b").authorize(req("node-b"));
  const restarted = node("node-b");
  const before = readAudit(restarted.logPaths).length;
  restarted.probe(req("node-b")); // status probe: no record, no nonce consumed
  assert.equal(readAudit(restarted.logPaths).length, before);
  restarted.authorize(req("node-b"));
  assert.equal(readAudit(restarted.logPaths).length, before + 1);
  assert.equal(verifyAudit(restarted.logPaths).ok, true);
});

test("replay, cross-node replay, a revoked device and a forged policy each raise one alert naming identity, service and event", () => {
  const { base, cp, node, req } = cluster();
  const [a, b, c] = NODE_NAMES.map(node);
  const r = req("node-a");
  a.authorize(r);
  a.authorize(r); // replay on node-a
  a.authorize(r); // again: deduplicated within the minute
  b.authorize(r); // cross-node replay to node-b
  cp.revokeDevice("maya-phone");
  c.sync();
  c.authorize(req("node-c")); // stolen phone keeps signing
  const forged = { ...cp.policy, epoch: cp.policy.epoch + 50, devices: [], revoked_actors: [] };
  assert.equal(c.adoptText(JSON.stringify(signPolicy(generateSigningKeyPair().privateKey, forged))).status, "rejected");

  const alerts = clusterAlerts(base);
  const byRule = (rule: string) => alerts.filter((x) => x.rule === rule);
  assert.equal(byRule("replayed_request").length, 1, "deduplicated");
  for (const [rule, service] of [["replayed_request", "node-a"], ["request_for_another_node", "node-b"], ["revoked_device_used", "node-c"], ["forged_or_old_policy", "node-c"]] as const) {
    const al = byRule(rule)[0];
    assert.ok(al, rule);
    assert.equal(al.service, service, `${rule}: service`);
    assert.ok(al.identity.length > 0 && al.events.length > 0 && al.events !== "-", `${rule}: identity and event`);
  }
  assert.match(byRule("replayed_request")[0].identity, /^maya \(device maya-phone\)$/);
  assert.match(byRule("replayed_request")[0].events, new RegExp(`^${r.nonce} \\(audit seq \\d+\\)$`));
  assert.equal(byRule("forged_or_old_policy")[0].identity, "unauthenticated sender");

  // The merged node log carries every node's records, tagged with the node, and never keys.
  const log = clusterLog(base);
  assert.ok(log.some((x) => x.service === "node-b" && x.reason === "wrong_node"));
  assert.ok(!JSON.stringify(log).includes("PRIVATE"));
});
