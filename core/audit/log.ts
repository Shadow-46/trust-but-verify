import { createHash } from "node:crypto";
import { appendDurable, readTextIfExists } from "../store/fsx.ts";
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

export type AuditType = "setup" | "access_decision" | "duplicate_request_id" | "revoke";

export type AuditFields = {
  type: AuditType;
  request_id: string | null;
  actor: string | null;
  asset: string | null;
  decision: "allow" | "deny" | null;
  reason: string | null;
};

export type AuditRecord = AuditFields & { seq: number; ts: string; prev: string; hash: string };

const GENESIS = "0".repeat(64);

function recordHash(prev: string, r: Omit<AuditRecord, "hash">): string {
  // Fixed field order so the hash is reproducible by any verifier.
  const canonical = JSON.stringify([
    r.seq, r.ts, r.type, r.request_id, r.actor, r.asset, r.decision, r.reason, r.prev,
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
  const record: AuditRecord = { ...base, hash: recordHash(base.prev, base) };
  appendDurable(paths.audit, JSON.stringify(record));
  return record;
}

/** First recorded access decision for a request ID (later duplicates never overwrite it). */
export function findDecision(records: AuditRecord[], requestId: string): AuditRecord | undefined {
  return records.find((r) => r.type === "access_decision" && r.request_id === requestId);
}

export type AuditVerification = { ok: boolean; records: number; first_bad_seq: number | null };

export function verifyAudit(paths: StatePaths): AuditVerification {
  let records: AuditRecord[];
  try {
    records = readAudit(paths);
  } catch {
    return { ok: false, records: 0, first_bad_seq: 0 };
  }
  let prev = GENESIS;
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    const { hash, ...rest } = r;
    if (r.seq !== i + 1 || r.prev !== prev || recordHash(prev, rest) !== hash) {
      return { ok: false, records: records.length, first_bad_seq: i + 1 };
    }
    prev = hash;
  }
  return { ok: true, records: records.length, first_bad_seq: null };
}
