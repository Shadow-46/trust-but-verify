import { join } from "node:path";
import { generateSigningKeyPair } from "../crypto/sign.ts";
import { atomicWriteFile, ensurePrivateDir, readTextIfExists } from "../store/fsx.ts";
import { RequestError } from "../errors.ts";
import { signPolicy, verifyPolicy } from "./policy.ts";
import type { DeviceRecord, Policy, SignedPolicy } from "./policy.ts";

/**
 * Control plane: the single writer of policy. Every change produces a new,
 * signed policy version with epoch + 1, written atomically to the published
 * file that nodes pull. The signing key never leaves the control directory.
 */

export const DEFAULT_GRACE_MS = 30_000;

export type ControlPaths = { dir: string; signingKey: string; anchor: string; published: string };

export function controlPaths(dir: string): ControlPaths {
  return {
    dir,
    signingKey: join(dir, "keys", "control.key"),
    anchor: join(dir, "anchor.pub"),
    published: join(dir, "policy.signed.json"),
  };
}

export class ControlPlane {
  readonly paths: ControlPaths;
  private readonly signingKey: Buffer;
  readonly anchor: Buffer;
  policy: Policy;
  /** When each epoch was published (ms), for propagation measurements. */
  readonly publishedAt = new Map<number, number>();

  private constructor(paths: ControlPaths, signingKey: Buffer, anchor: Buffer, policy: Policy) {
    this.paths = paths;
    this.signingKey = signingKey;
    this.anchor = anchor;
    this.policy = policy;
  }

  static create(dir: string, opts: { graceMs?: number; now?: number } = {}): ControlPlane {
    const paths = controlPaths(dir);
    ensurePrivateDir(dir);
    const kp = generateSigningKeyPair();
    atomicWriteFile(paths.signingKey, kp.privateKey.toString("base64"));
    atomicWriteFile(paths.anchor, kp.publicKey.toString("base64"));
    const now = opts.now ?? Date.now();
    const cp = new ControlPlane(paths, kp.privateKey, kp.publicKey, {
      epoch: 0,
      issued_at: now,
      grace_ms: opts.graceMs ?? DEFAULT_GRACE_MS,
      active_key: 1,
      keys: [{ version: 1, activated_at: now, accept_until: null }],
      revoked_actors: [],
      devices: [],
    });
    cp.publish(now);
    return cp;
  }

  static load(dir: string): ControlPlane {
    const paths = controlPaths(dir);
    const key = readTextIfExists(paths.signingKey);
    const anchor = readTextIfExists(paths.anchor);
    const published = readTextIfExists(paths.published);
    if (!key || !anchor || !published) throw new RequestError("control_plane_not_initialized");
    const anchorDer = Buffer.from(anchor, "base64");
    const policy = verifyPolicy(anchorDer, JSON.parse(published) as SignedPolicy);
    return new ControlPlane(paths, Buffer.from(key, "base64"), anchorDer, policy);
  }

  /** Sign and atomically publish the next epoch. Returns the new epoch. */
  publish(now = Date.now()): number {
    this.policy = { ...this.policy, epoch: this.policy.epoch + 1, issued_at: now };
    atomicWriteFile(this.paths.published, JSON.stringify(signPolicy(this.signingKey, this.policy)));
    this.publishedAt.set(this.policy.epoch, now);
    return this.policy.epoch;
  }

  enrolDevice(owner: string, deviceId: string, publicKeyDer: Buffer, now = Date.now()): number {
    if (this.policy.devices.some((d) => d.device_id === deviceId)) throw new RequestError("device_exists");
    const record: DeviceRecord = {
      device_id: deviceId,
      owner,
      public_key: publicKeyDer.toString("base64"),
      status: "active",
      enrolled_at: now,
      revoked_at: null,
    };
    this.policy = { ...this.policy, devices: [...this.policy.devices, record] };
    return this.publish(now);
  }

  /** Lost or stolen device: revoke only that device; the owner keeps other devices. */
  revokeDevice(deviceId: string, now = Date.now()): number {
    if (!this.policy.devices.some((d) => d.device_id === deviceId)) throw new RequestError("unknown_device");
    this.policy = {
      ...this.policy,
      devices: this.policy.devices.map((d) =>
        d.device_id === deviceId ? { ...d, status: "revoked" as const, revoked_at: now } : d,
      ),
    };
    return this.publish(now);
  }

  /** Revoke an identity everywhere (all of its devices stop working). */
  revokeActor(actor: string, now = Date.now()): number {
    if (!this.policy.revoked_actors.includes(actor)) {
      this.policy = { ...this.policy, revoked_actors: [...this.policy.revoked_actors, actor] };
    }
    return this.publish(now);
  }

  /**
   * Activate key version n+1. The previous active version stays valid for new
   * requests until `now + grace_ms` (the documented cutoff); after that every
   * node rejects new requests that use it. Transfers begun before the cutoff
   * may finish (see ClusterNode).
   */
  rotateKey(now = Date.now()): { epoch: number; newVersion: number; cutoff: number } {
    const old = this.policy.active_key;
    const newVersion = old + 1;
    const cutoff = now + this.policy.grace_ms;
    this.policy = {
      ...this.policy,
      active_key: newVersion,
      keys: [
        ...this.policy.keys.map((k) => (k.version === old ? { ...k, accept_until: cutoff } : k)),
        { version: newVersion, activated_at: now, accept_until: null },
      ],
    };
    return { epoch: this.publish(now), newVersion, cutoff };
  }
}
