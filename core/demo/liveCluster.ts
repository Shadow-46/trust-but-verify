import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { ControlPlane } from "../cluster/control.ts";
import { ClusterNode, signRequest } from "../cluster/node.ts";
import { generateSigningKeyPair } from "../crypto/sign.ts";
import { appendDurable, atomicWriteFile, readTextIfExists } from "../store/fsx.ts";

/**
 * Live cluster demo state on disk, driven by the operator console. The node
 * processes themselves are started by the console (core/cluster/nodeProcess.ts);
 * these helpers create the control plane, change policy, and report what each
 * node is currently enforcing for maya's phone.
 */
export const NODE_NAMES = ["node-a", "node-b", "node-c"];

type DemoDevice = { device_id: string; privateKey: string; publicKey: string };
const deviceFile = (dir: string) => join(dir, "demo-device.json");

function enrolNew(cp: ControlPlane, dir: string, n: number): DemoDevice {
  const kp = generateSigningKeyPair();
  const d = { device_id: `maya-phone-${n}`, privateKey: kp.privateKey.toString("base64"), publicKey: kp.publicKey.toString("base64") };
  cp.enrolDevice("maya", d.device_id, kp.publicKey);
  atomicWriteFile(deviceFile(dir), JSON.stringify(d)); // synthetic demo key, temp dir only
  return d;
}

export function clusterInit(dir: string) {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const cp = ControlPlane.create(join(dir, "control"));
  const d = enrolNew(cp, dir, 1);
  for (const n of NODE_NAMES) cp.provision(join(dir, n)); // anchor + epoch floor, out of band
  return { epoch: cp.policy.epoch, device: d.device_id, nodes: NODE_NAMES.map((n) => join(dir, n)), control: cp.paths.dir };
}

export function clusterStatus(dir: string) {
  if (!existsSync(deviceFile(dir))) return { ready: false };
  const cp = ControlPlane.load(join(dir, "control"));
  const d = JSON.parse(readFileSync(deviceFile(dir), "utf8")) as DemoDevice;
  const nodes = NODE_NAMES.map((name) => {
    const nodeDir = join(dir, name);
    if (!existsSync(join(nodeDir, "ack.json"))) return { name, epoch: 0, adopted_at: null, decision: "deny", reason: "no_policy" };
    const ack = JSON.parse(readFileSync(join(nodeDir, "ack.json"), "utf8")) as { epoch: number; adopted_at: number };
    const view = new ClusterNode(name, nodeDir, cp.anchor, join(dir, "unused"));
    const req = signRequest(Buffer.from(d.privateKey, "base64"), {
      actor: "maya", device_id: d.device_id, node: name, key_version: cp.policy.active_key, op: "request", transfer_id: null, nonce: randomBytes(8).toString("hex"), ts: Date.now(),
    });
    const decision = view.authorize(req);
    return { name, epoch: ack.epoch, adopted_at: ack.adopted_at, decision: decision.decision, reason: decision.reason };
  });
  return { ready: true, published_epoch: cp.policy.epoch, published_at: cp.policy.issued_at, device: d.device_id, nodes, control: controlView(dir), attempts: recentAttempts(dir) };
}

/** What the control plane itself observed over the network (its own clock) and which links are cut. */
function controlView(dir: string) {
  const read = (f: string) => {
    try {
      return JSON.parse(readTextIfExists(join(dir, "control", f)) ?? "null") as unknown;
    } catch {
      return null;
    }
  };
  const acks = read("acks.json") as { port?: number; acks?: Record<string, Record<string, number>>; last_seen?: Record<string, number>; at?: number } | null;
  const blocked = read("blocked.json");
  return { transport: acks?.port ? "http" : "file", acks: acks?.acks ?? {}, last_seen: acks?.last_seen ?? {}, observed_at: acks?.at ?? null, blocked: Array.isArray(blocked) ? blocked : [] };
}

/** A device request that reached a node (e.g. from the Attack Lab), for the network map. */
export type Attempt = { at: number; device: string; node: string; decision: string; reason: string; label: string };

export function recordAttempt(dir: string, a: Attempt): void {
  appendDurable(join(dir, "attempts.jsonl"), JSON.stringify(a));
}

function recentAttempts(dir: string): Attempt[] {
  const text = readTextIfExists(join(dir, "attempts.jsonl")) ?? "";
  return text
    .split("\n")
    .filter((l) => l.length > 0)
    .slice(-12)
    .flatMap((l) => {
      try {
        return [JSON.parse(l) as Attempt];
      } catch {
        return [];
      }
    });
}

export function clusterRevoke(dir: string) {
  const cp = ControlPlane.load(join(dir, "control"));
  const d = JSON.parse(readFileSync(deviceFile(dir), "utf8")) as DemoDevice;
  const at = Date.now();
  const epoch = cp.revokeDevice(d.device_id, at);
  return { epoch, at, device: d.device_id };
}

export function clusterEnrol(dir: string) {
  const cp = ControlPlane.load(join(dir, "control"));
  const n = cp.policy.devices.filter((x) => x.owner === "maya").length + 1;
  const d = enrolNew(cp, dir, n);
  return { epoch: cp.policy.epoch, device: d.device_id };
}
