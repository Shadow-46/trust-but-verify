import { signBytes, verifyBytes } from "../crypto/sign.ts";
import { IntegrityError } from "../errors.ts";

/**
 * The access policy every node enforces. The control plane signs each version
 * with ML-DSA-65; nodes accept a version only if the signature verifies against
 * their trust anchor AND its epoch is higher than the one they already hold, so
 * an attacker can neither forge a policy nor replay an older one (for example
 * one issued before a revocation).
 */

export type KeyWindow = {
  version: number;
  activated_at: number; // ms since epoch
  /** New requests using this version are rejected from this instant on (null = no cutoff). */
  accept_until: number | null;
};

export type DeviceStatus = "active" | "revoked";

export type DeviceRecord = {
  device_id: string;
  owner: string;
  public_key: string; // Base64 SPKI DER, ML-DSA-65
  status: DeviceStatus;
  enrolled_at: number;
  revoked_at: number | null;
};

export type Policy = {
  epoch: number;
  issued_at: number;
  grace_ms: number;
  active_key: number;
  keys: KeyWindow[];
  revoked_actors: string[];
  devices: DeviceRecord[];
};

export type SignedPolicy = { policy: string; signature: string };

export function signPolicy(privateKeyDer: Buffer, policy: Policy): SignedPolicy {
  const json = JSON.stringify(policy);
  return { policy: json, signature: signBytes(privateKeyDer, Buffer.from(json, "utf8")).toString("base64") };
}

/** Verify and parse; throws IntegrityError on any forgery or corruption. */
export function verifyPolicy(anchorDer: Buffer, signed: SignedPolicy): Policy {
  if (typeof signed?.policy !== "string" || typeof signed?.signature !== "string") {
    throw new IntegrityError("policy");
  }
  if (!verifyBytes(anchorDer, Buffer.from(signed.policy, "utf8"), Buffer.from(signed.signature, "base64"))) {
    throw new IntegrityError("policy signature");
  }
  const p = JSON.parse(signed.policy) as Policy;
  if (!Number.isInteger(p.epoch) || p.epoch < 1) throw new IntegrityError("policy epoch");
  return p;
}
