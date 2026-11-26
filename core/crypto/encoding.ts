import { RequestError } from "../errors.ts";

const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * Strict standard-Base64 decode. Node's Buffer.from silently skips invalid
 * characters, which would let malformed input through; reject it instead.
 */
export function decodeBase64Strict(value: string, errorCode: string): Buffer {
  if (value.length === 0 || value.length % 4 !== 0 || !BASE64.test(value)) {
    throw new RequestError(errorCode);
  }
  return Buffer.from(value, "base64");
}
