import { hkdfSync } from "node:crypto";

/** HKDF-SHA-256 (RFC 5869). `info` separates keys derived for different purposes. */
export function hkdf(ikm: Buffer, salt: Buffer, info: string, length = 32): Buffer {
  return Buffer.from(hkdfSync("sha256", ikm, salt, Buffer.from(info, "utf8"), length));
}
