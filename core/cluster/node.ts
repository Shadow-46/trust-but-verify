import { createHash } from "node:crypto";
import { join } from "node:path";
import { signBytes, verifyBytes } from "../crypto/sign.ts";
import { atomicWriteFile, ensurePrivateDir, readTextIfExists, withLock } from "../store/fsx.ts";
import { verifyPolicy } from "./policy.ts";
import type { Policy, SignedPolicy } from "./policy.ts";

/**
 * A service node. It enforces only the policy it has itself verified and
 * stored, so it keeps working (with its last known policy) if the control plane
 * is unreachable, and it never accepts a forged or older policy.
 */

/** Maximum accepted difference between a request timestamp and the node clock. */
export const MAX_CLOCK_SKEW_MS = 30_000;
/** An authorized transfer may continue on its original key version for at most this long. */
export const MAX_TRANSFER_MS = 120_000;

export type RequestOp = "request" | "begin_transfer" | "chunk";

export type AccessRequest = {
  actor: string;
  device_id: string;
  key_version: number;
  op: RequestOp;
  transfer_id: string | null;
  nonce: string;
  ts: number;
};

export type SignedAccessRequest = AccessRequest & { signature: string };

export type NodeDecision = {
  node: string;
  epoch: number;
  decision: "allow" | "deny";
  reason: string;
};

/** The exact bytes a device signs: a fixed-order JSON array, so fields cannot be confused. */
export function requestBytes(r: AccessRequest): Buffer {
  return Buffer.from(
    JSON.stringify(["tbv/req/v1", r.actor, r.device_id, r.key_version, r.op, r.transfer_id, r.nonce, r.ts]),
    "utf8",
  );
}

export function signRequest(devicePrivateKeyDer: Buffer, r: AccessRequest): SignedAccessRequest {
  return { ...r, signature: signBytes(devicePrivateKeyDer, requestBytes(r)).toString("base64") };
}

export type SyncResult =
  | { status: "adopted"; epoch: number }
  | { status: "unchanged"; epoch: number }
  | { status: "rejected"; epoch: number; reason: "bad_signature" | "rollback" | "unreadable" | "below_floor" | "bootstrap_mismatch" };

type Transfer = { actor: string; device_id: string; version: number; started_at: number };

/**
 * Provisioning record written by the control plane when a node is enrolled
 * (out of band, like the anchor): a new node must not accept any genuinely
 * signed policy older than the one current at enrolment, and the policy at that
 * exact epoch must be the one it was provisioned with.
 */
export type NodeTrust = { anchor: string; min_epoch: number; policy_sha256: string };

/** Replay nonces and in-flight transfers, persisted so a node restart forgets neither. */
type ReplayFile = { nonces: [string, number][]; transfers: [string, Transfer][] };

const sha256 = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");

export class ClusterNode {
  readonly name: string;
  readonly dir: string;
  private readonly anchor: Buffer;
  private readonly source: string;
  policy: Policy | null = null;
  private readonly transfers = new Map<string, Transfer>();
  private readonly nonces = new Map<string, number>();

  /**
   * @param anchorDer control-plane public key, provisioned out of band (trust anchor)
   * @param source    path of the published signed policy this node pulls
   */
  /** Provisioned trust floor (absent for nodes created before provisioning existed, e.g. tests). */
  private readonly trust: NodeTrust | null;

  constructor(name: string, dir: string, anchorDer: Buffer, source: string) {
    this.name = name;
    this.dir = dir;
    this.anchor = anchorDer;
    this.source = source;
    ensurePrivateDir(dir);
    const t = readTextIfExists(join(dir, "trust.json"));
    this.trust = t ? (JSON.parse(t) as NodeTrust) : null;
    if (this.trust && this.trust.anchor !== anchorDer.toString("base64")) throw new Error("node trust anchor mismatch");
    this.reloadLocal();
  }

  /** Start a node from its provisioning record (anchor + epoch floor), pulling from `source`. */
  static provisioned(name: string, dir: string, source: string): ClusterNode {
    const t = readTextIfExists(join(dir, "trust.json"));
    if (!t) throw new Error("node is not provisioned");
    return new ClusterNode(name, dir, Buffer.from((JSON.parse(t) as NodeTrust).anchor, "base64"), source);
  }

  /** Enforce the provisioning floor: nothing older, and exactly the provisioned policy at the floor. */
  private belowTrust(p: Policy, text: string): "below_floor" | "bootstrap_mismatch" | null {
    if (!this.trust) return null;
    if (p.epoch < this.trust.min_epoch) return "below_floor";
    if (p.epoch === this.trust.min_epoch && sha256(text) !== this.trust.policy_sha256) return "bootstrap_mismatch";
    return null;
  }

  /**
   * Re-read this node's own stored policy (e.g. one adopted by the node's
   * process). The stored copy is re-verified; a corrupted copy means the node
   * refuses everything until the next valid sync.
   */
  reloadLocal(): void {
    const cached = readTextIfExists(join(this.dir, "policy.signed.json"));
    if (!cached) return;
    try {
      const p = verifyPolicy(this.anchor, JSON.parse(cached) as SignedPolicy);
      if (this.belowTrust(p, cached)) throw new Error("below trust floor");
      if (p.epoch >= this.epoch) this.policy = p;
    } catch {
      this.policy = null;
    }
  }

  get epoch(): number {
    return this.policy?.epoch ?? 0;
  }

  /**
   * Pull the published policy; adopt it only if authentic and newer. The ack's
   * `adopted_at` is stamped after verification and persistence (i.e. when the
   * node actually starts enforcing), unless a fixed `now` is given by tests.
   */
  sync(now?: number): SyncResult {
    const text = readTextIfExists(this.source);
    if (!text) return { status: "rejected", epoch: this.epoch, reason: "unreadable" };
    return this.adoptText(text, now);
  }

  /**
   * Verify and (if newer) adopt a signed policy received by any transport: a
   * shared file (`sync`) or the network (core/cluster/transport.ts). The bytes
   * are untrusted; only the ML-DSA signature, the epoch and the provisioning
   * floor decide.
   */
  adoptText(text: string, now?: number): SyncResult {
    let incoming: Policy;
    try {
      incoming = verifyPolicy(this.anchor, JSON.parse(text) as SignedPolicy);
    } catch {
      return { status: "rejected", epoch: this.epoch, reason: "bad_signature" };
    }
    const floor = this.belowTrust(incoming, text);
    if (floor) return { status: "rejected", epoch: this.epoch, reason: floor };
    if (incoming.epoch < this.epoch) return { status: "rejected", epoch: this.epoch, reason: "rollback" };
    if (incoming.epoch === this.epoch) return { status: "unchanged", epoch: this.epoch };
    // Persist first, adopt in memory last: if either write fails, the next sync
    // retries the whole adoption instead of treating the epoch as already done.
    atomicWriteFile(join(this.dir, "policy.signed.json"), text);
    const adoptedAt = now ?? Date.now();
    atomicWriteFile(join(this.dir, "ack.json"), JSON.stringify({ node: this.name, epoch: incoming.epoch, adopted_at: adoptedAt }));
    this.policy = incoming;
    return { status: "adopted", epoch: incoming.epoch };
  }

  private deny(reason: string): NodeDecision {
    return { node: this.name, epoch: this.epoch, decision: "deny", reason };
  }

  /** Zero-trust check of one signed request against this node's verified policy. */
  authorize(req: SignedAccessRequest, now = Date.now()): NodeDecision {
    const p = this.policy;
    if (!p) return this.deny("no_policy");
    if (req.op !== "request" && req.op !== "begin_transfer" && req.op !== "chunk") return this.deny("invalid_op");

    const device = p.devices.find((d) => d.device_id === req.device_id);
    if (!device) return this.deny("unknown_device");
    if (device.owner !== req.actor) return this.deny("device_owner_mismatch");
    if (device.status !== "active") return this.deny("device_revoked");
    if (p.revoked_actors.includes(req.actor)) return this.deny("actor_revoked");

    const signature = Buffer.from(typeof req.signature === "string" ? req.signature : "", "base64");
    if (!verifyBytes(Buffer.from(device.public_key, "base64"), requestBytes(req), signature)) {
      return this.deny("bad_signature");
    }
    if (!Number.isFinite(req.ts) || Math.abs(now - req.ts) > MAX_CLOCK_SKEW_MS) return this.deny("stale_or_future_request");

    // Replay nonces and transfers live on disk (under the node's lock), so a restarted node,
    // or a second process on the same node directory, still refuses a replay and still
    // lets an in-flight transfer finish.
    return withLock(this.dir, () => {
      this.loadReplay(now);
      const d = this.decide(req, p, now);
      this.saveReplay();
      return d;
    });
  }

  private loadReplay(now: number): void {
    this.nonces.clear();
    this.transfers.clear();
    const text = readTextIfExists(join(this.dir, "replay.json"));
    if (!text) return;
    try {
      const f = JSON.parse(text) as ReplayFile;
      for (const [k, t] of f.nonces) if (now - t <= 2 * MAX_CLOCK_SKEW_MS) this.nonces.set(k, t);
      // Keep expired transfers a while longer so a late chunk is refused as "transfer_expired".
      for (const [id, t] of f.transfers) if (now - t.started_at <= 2 * MAX_TRANSFER_MS) this.transfers.set(id, t);
    } catch {
      // Unreadable replay file: start empty. In-flight transfers then end (fail safe); nonces are
      // still bounded by the ±30 s timestamp window.
    }
  }

  private saveReplay(): void {
    const f: ReplayFile = { nonces: [...this.nonces], transfers: [...this.transfers] };
    atomicWriteFile(join(this.dir, "replay.json"), JSON.stringify(f));
  }

  private decide(req: SignedAccessRequest, p: Policy, now: number): NodeDecision {
    // Replay protection: a nonce is accepted once within the skew window.
    const nonceKey = `${req.device_id}\u0000${req.nonce}`;
    if (this.nonces.has(nonceKey)) return this.deny("replayed_request");

    const window = p.keys.find((k) => k.version === req.key_version);
    if (!window) return this.deny("unknown_key_version");

    let decision: NodeDecision;
    if (req.op === "chunk") {
      const t = req.transfer_id ? this.transfers.get(req.transfer_id) : undefined;
      if (!t || t.actor !== req.actor || t.device_id !== req.device_id || t.version !== req.key_version) {
        decision = this.deny("unknown_transfer");
      } else if (now - t.started_at > MAX_TRANSFER_MS) {
        decision = this.deny("transfer_expired");
      } else {
        // In-flight transfer authorized before the cutoff continues on its key version.
        decision = { node: this.name, epoch: p.epoch, decision: "allow", reason: "in_flight_transfer" };
      }
    } else if (window.accept_until !== null && now >= window.accept_until) {
      decision = this.deny("key_version_retired");
    } else {
      decision = { node: this.name, epoch: p.epoch, decision: "allow", reason: "authorized" };
      if (req.op === "begin_transfer") {
        if (!req.transfer_id || this.transfers.has(req.transfer_id)) return this.deny("invalid_transfer_id");
        this.transfers.set(req.transfer_id, {
          actor: req.actor,
          device_id: req.device_id,
          version: req.key_version,
          started_at: now,
        });
      }
    }
    this.nonces.set(nonceKey, now);
    return decision;
  }
}
