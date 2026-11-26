import { randomBytes } from "node:crypto";
import { seal, open, aad } from "../crypto/aead.ts";
import type { Sealed } from "../crypto/aead.ts";
import { hkdf } from "../crypto/kdf.ts";
import { atomicWriteFile, readTextIfExists } from "../store/fsx.ts";
import type { StatePaths } from "../store/paths.ts";
import { RequestError } from "../errors.ts";

/**
 * Key hierarchy
 *   master key (32 B)      — from TRACK4_MASTER_KEY (KMS/HSM stand-in) or a 0600 file in keys/
 *     └─ KEK  = HKDF(master, salt, "tbv/kek/v1")        wraps data keys
 *     └─ MACK = HKDF(master, salt, "tbv/state-mac/v1")  authenticates state.json
 *   data key v_n (32 B)    — AES-256-GCM key for protected bodies, stored only wrapped by the KEK
 *
 * The setup `key_material` is mixed into the first data key's derivation and is
 * never written anywhere.
 */

const MASTER_BYTES = 32;

function masterFromEnv(): Buffer | undefined {
  const value = process.env.TRACK4_MASTER_KEY;
  if (!value) return undefined;
  const key = Buffer.from(value, "base64");
  if (key.length !== MASTER_BYTES) throw new Error("TRACK4_MASTER_KEY must be 32 bytes, Base64");
  return key;
}

/** Create (or adopt from the environment) the master key during setup. */
export function createMasterKey(paths: StatePaths): Buffer {
  const fromEnv = masterFromEnv();
  if (fromEnv) return fromEnv;
  const key = randomBytes(MASTER_BYTES);
  atomicWriteFile(paths.masterKey, key.toString("base64"));
  return key;
}

export function loadMasterKey(paths: StatePaths): Buffer {
  const fromEnv = masterFromEnv();
  if (fromEnv) return fromEnv;
  const text = readTextIfExists(paths.masterKey);
  if (text === undefined) throw new RequestError("not_initialized");
  const key = Buffer.from(text.trim(), "base64");
  if (key.length !== MASTER_BYTES) throw new RequestError("not_initialized");
  return key;
}

export type KeyStatus = "active" | "retired";

export type WrappedDataKey = {
  version: number;
  created_at: string;
  status: KeyStatus;
  wrapped: Sealed;
};

export type DerivedKeys = { kek: Buffer; stateMac: Buffer };

export function deriveKeys(master: Buffer, salt: Buffer): DerivedKeys {
  return {
    kek: hkdf(master, salt, "tbv/kek/v1"),
    stateMac: hkdf(master, salt, "tbv/state-mac/v1"),
  };
}

/** New data key; `extraEntropy` (e.g. the setup key_material) is mixed in, never stored. */
export function newDataKey(salt: Buffer, version: number, extraEntropy?: string): Buffer {
  const ikm = Buffer.concat([randomBytes(32), Buffer.from(extraEntropy ?? "", "utf8")]);
  return hkdf(ikm, salt, `tbv/dek/v${version}`);
}

export function wrapDataKey(kek: Buffer, setupId: string, version: number, dek: Buffer): WrappedDataKey {
  return {
    version,
    created_at: new Date().toISOString(),
    status: "active",
    wrapped: seal(kek, dek, aad("tbv/dek/v1", setupId, version)),
  };
}

export function unwrapDataKey(kek: Buffer, setupId: string, record: WrappedDataKey): Buffer {
  return open(kek, record.wrapped, aad("tbv/dek/v1", setupId, record.version), "data key");
}
