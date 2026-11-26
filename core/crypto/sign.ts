import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";

/**
 * ML-DSA-65 (FIPS 204) signatures via node:crypto / OpenSSL. Keys are passed
 * around as DER bytes: SPKI for public keys, PKCS#8 for private keys.
 */
export type SigningKeyPair = { publicKey: Buffer; privateKey: Buffer };

export function generateSigningKeyPair(): SigningKeyPair {
  const kp = generateKeyPairSync("ml-dsa-65" as never);
  return {
    publicKey: kp.publicKey.export({ type: "spki", format: "der" }),
    privateKey: kp.privateKey.export({ type: "pkcs8", format: "der" }),
  };
}

export function signBytes(privateKeyDer: Buffer, data: Buffer): Buffer {
  return sign(null, data, createPrivateKey({ key: privateKeyDer, format: "der", type: "pkcs8" }));
}

/** False for any malformed key, malformed signature or mismatch (never throws). */
export function verifyBytes(publicKeyDer: Buffer, data: Buffer, signature: Buffer): boolean {
  try {
    const key = createPublicKey({ key: publicKeyDer, format: "der", type: "spki" });
    if (key.asymmetricKeyType !== "ml-dsa-65") return false;
    return verify(null, data, key, signature);
  } catch {
    return false;
  }
}
