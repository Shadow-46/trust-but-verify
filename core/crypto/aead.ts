import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { IntegrityError } from "../errors.ts";

/** AES-256-GCM ciphertext: 96-bit random nonce, ciphertext, 128-bit tag (all Base64). */
export type Sealed = { n: string; c: string; t: string };

const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

function checkKey(key: Buffer): void {
  if (key.length !== KEY_BYTES) throw new Error("AES-256-GCM key must be 32 bytes");
}

/** Encrypt and authenticate `plaintext`; `aad` is authenticated but not encrypted. */
export function seal(key: Buffer, plaintext: Buffer, aad: Buffer): Sealed {
  checkKey(key);
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_BYTES });
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    n: nonce.toString("base64"),
    c: ct.toString("base64"),
    t: cipher.getAuthTag().toString("base64"),
  };
}

/** Decrypt; throws IntegrityError if the ciphertext, tag, nonce or AAD was altered. */
export function open(key: Buffer, sealed: Sealed, aad: Buffer, what: string): Buffer {
  checkKey(key);
  const nonce = Buffer.from(sealed.n, "base64");
  const tag = Buffer.from(sealed.t, "base64");
  if (nonce.length !== NONCE_BYTES || tag.length !== TAG_BYTES) throw new IntegrityError(what);
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_BYTES });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(Buffer.from(sealed.c, "base64")), decipher.final()]);
  } catch {
    throw new IntegrityError(what);
  }
}

/** Associated data for a sealed value: an unambiguous JSON array of context fields. */
export function aad(...parts: (string | number)[]): Buffer {
  return Buffer.from(JSON.stringify(parts), "utf8");
}
