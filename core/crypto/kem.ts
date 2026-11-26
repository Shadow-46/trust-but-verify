import * as nodeCrypto from "node:crypto";
import type { KeyObject } from "node:crypto";
import { RequestError } from "../errors.ts";

/** FIPS 203 ML-KEM-768 sizes. */
export const ML_KEM_768_PUBLIC_KEY_BYTES = 1184;
export const ML_KEM_768_CIPHERTEXT_BYTES = 1088;

/**
 * DER SubjectPublicKeyInfo prefix for an ML-KEM-768 key (OID 2.16.840.1.101.3.4.4.2).
 * Node 24.11.1 cannot import raw ML-KEM keys directly (`format: "raw-public"` was
 * added later), so a raw key is wrapped in this fixed SPKI header instead.
 */
const ML_KEM_768_SPKI_PREFIX = Buffer.from("308204b2300b0609608648016503040402038204a100", "hex");

// encapsulate/decapsulate exist since Node 24.7 but are missing from some @types/node versions.
type KemApi = {
  encapsulate(key: KeyObject): { sharedKey: Buffer; ciphertext: Buffer };
  decapsulate(key: KeyObject, ciphertext: Buffer): Buffer;
};
const kem = nodeCrypto as unknown as KemApi;

export function importMlKem768PublicKey(raw: Buffer): KeyObject {
  if (raw.length !== ML_KEM_768_PUBLIC_KEY_BYTES) throw new RequestError("invalid_public_key");
  try {
    const key = nodeCrypto.createPublicKey({
      key: Buffer.concat([ML_KEM_768_SPKI_PREFIX, raw]),
      format: "der",
      type: "spki",
    });
    if (key.asymmetricKeyType !== "ml-kem-768") throw new Error("unexpected key type");
    return key;
  } catch {
    throw new RequestError("invalid_public_key");
  }
}

/** Encapsulate to `publicKey`: returns the KEM ciphertext and the 32-byte shared secret. */
export function encapsulate(publicKey: KeyObject): { ciphertext: Buffer; sharedKey: Buffer } {
  const { ciphertext, sharedKey } = kem.encapsulate(publicKey);
  return { ciphertext, sharedKey };
}

export function decapsulate(privateKey: KeyObject, ciphertext: Buffer): Buffer {
  return kem.decapsulate(privateKey, ciphertext);
}

/** Raw 1184-byte public key from a KeyObject (inverse of importMlKem768PublicKey). */
export function exportMlKem768PublicKeyRaw(publicKey: KeyObject): Buffer {
  const der = publicKey.export({ type: "spki", format: "der" });
  return der.subarray(der.length - ML_KEM_768_PUBLIC_KEY_BYTES);
}
