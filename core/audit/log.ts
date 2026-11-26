import { createHash } from "node:crypto";
import { signBytes, verifyBytes } from "../crypto/sign.ts";
import { appendDurable, atomicWriteFile, readTextIfExists } from "../store/fsx.ts";
import type { StatePaths } from "../store/paths.ts";

/**
 * Append-only, hash-chained audit log (one JSON object per line).
 *
 * Record boundaries cannot be forged by user-supplied text: every value is a
 * JSON string field, so a newline or brace inside an ID is escaped by
 * JSON.stringify and stays inside its field. Each record commits to the
 * previous record's hash, so editing, deleting or reordering a record breaks
 * verification from that point on.
 */

export type AuditType =
  | "setup"
  | "access_decision"
  | "duplicate_request_id"
  | "revoke"
  | "key_rotation"
  | "backup_restored"
  | "security_alert";

export type AuditFields = {
  type: AuditType;
  request_id: string | null;
  actor: string | null;
  asset: string | null;
  decision: "allow" | "deny" | null;
  reason: string | null;
  /** State version this record was written against (binds the log to state; detects rollback). */
  state_version: number;
};

export type AuditRecord = AuditFields & { seq: number; ts: string; prev: string; hash: string; sig: string };

const GENESIS = "0".repeat(64);

function recordHash(prev: string, r: Omit<AuditRecord, "hash" | "sig">): string {
  // Fixed field order so the hash is reproducible by any verifier.
  const canonical = JSON.stringify([
    r.seq, r.ts, r.type, r.request_id, r.actor, r.asset, r.decision, r.reason, r.state_version, r.prev,
  ]);
  return createHash("sha256").update(prev, "utf8").update("\n").update(canonical, "utf8").digest("hex");
}

export function readAudit(paths: StatePaths): AuditRecord[] {
  const text = readTextIfExists(paths.audit);
  if (!text) return [];
  return text
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as AuditRecord);
}

export function appendAudit(paths: StatePaths, fields: AuditFields, existing?: AuditRecord[]): AuditRecord {
  const records = existing ?? readAudit(paths);
  const last = records.at(-1);
  const base = {
    seq: last ? last.seq + 1 : 1,
    ts: new Date().toISOString(),
    ...fields,
    prev: last ? last.hash : GENESIS,
  };
  const hash = recordHash(base.prev, base);
  // ML-DSA-65 signature over the chain hash: anyone holding keys/audit.pub can verify an exported log,
  // and someone without the signing key cannot rebuild a valid chain after editing it.
  const key = readTextIfExists(paths.auditKey);
  const sig = key ? signBytes(Buffer.from(key, "base64"), Buffer.from(hash, "utf8")).toString("base64") : "";
  const record: AuditRecord = { ...base, hash, sig };
  appendDurable(paths.audit, JSON.stringify(record));
  // Signed head: lets a load detect a log whose tail was cut off after the last state save.
  atomicWriteFile(paths.auditHead, JSON.stringify({ seq: record.seq, hash: record.hash, sig: record.sig }));
  return record;
}

export type AuditHead = { seq: number; hash: string; sig: string };

/** Throws if the signed head is forged or the log no longer contains it (truncation/replacement). */
export function checkAuditHead(paths: StatePaths, records: AuditRecord[]): boolean {
  const text = readTextIfExists(paths.auditHead);
  const pub = readTextIfExists(paths.auditPub);
  if (!text || !pub) return true;
  const head = JSON.parse(text) as AuditHead;
  if (!verifyBytes(Buffer.from(pub, "base64"), Buffer.from(head.hash, "utf8"), Buffer.from(head.sig, "base64"))) return false;
  return records[head.seq - 1]?.hash === head.hash;
}

/** First recorded access decision for a request ID (later duplicates never overwrite it). */
export function findDecision(records: AuditRecord[], requestId: string): AuditRecord | undefined {
  return records.find((r) => r.type === "access_decision" && r.request_id === requestId);
}

export type AuditVerification = { ok: boolean; records: number; first_bad_seq: number | null; signatures_checked: boolean };

/** Verify chain links, hashes and (when the public key is available) every ML-DSA signature. */
export function verifyAudit(paths: StatePaths, publicKeyDer?: Buffer): AuditVerification {
  const pubText = publicKeyDer ? undefined : readTextIfExists(paths.auditPub);
  const pub = publicKeyDer ?? (pubText ? Buffer.from(pubText, "base64") : undefined);
  const checked = pub !== undefined;
  let records: AuditRecord[];
  try {
    records = readAudit(paths);
  } catch {
    return { ok: false, records: 0, first_bad_seq: 0, signatures_checked: checked };
  }
  let prev = GENESIS;
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    const { hash, sig, ...rest } = r;
    const badSig = pub !== undefined && !verifyBytes(pub, Buffer.from(hash, "utf8"), Buffer.from(sig ?? "", "base64"));
    if (r.seq !== i + 1 || r.prev !== prev || recordHash(prev, rest) !== hash || badSig) {
      return { ok: false, records: records.length, first_bad_seq: i + 1, signatures_checked: checked };
    }
    prev = hash;
  }
  return { ok: true, records: records.length, first_bad_seq: null, signatures_checked: checked };
}
