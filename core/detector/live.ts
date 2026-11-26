// Live detect-and-respond for the judged adapter (T13).
//
// The adapter calls these hooks while it handles a request:
//   onDecision(paths, records, latest)   after a read/protected_read decision is in the audit log
//                                        (caller already holds the state lock)
//   onIntegrityFailure(paths, what)      when stored state or the log fails an integrity check
//   onInvalidRequest(paths, code)        when a request is rejected as malformed
//
// Detected attacks become records in a separate append-only alert log
// (<state dir>/alerts.jsonl): hash-chained and ML-DSA-65 signed with the audit key,
// kept apart from the audit log so an alert can still be written when that log is the
// thing that was tampered with.
//
// Response policy ("safe containment"): actors are identified only by the name in the
// request, so automatically blocking a name would let an attacker lock out its real
// owner. We therefore never change a decision. Alerts are always recorded; identities
// that are already revoked/disabled are additionally marked "quarantined" (they are denied
// anyway, so this can never harm a legitimate user); integrity failures stay fail-closed.
//
// Hooks never throw and never change the reply: detection failure must not become an
// availability problem. Nothing user-controlled is written to stderr.

import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";
import type { AuditRecord } from "../audit/log.ts";
import { signBytes, verifyBytes } from "../crypto/sign.ts";
import { appendDurable, atomicWriteFile, readTextIfExists, withLock } from "../store/fsx.ts";
import type { StatePaths } from "../store/paths.ts";

export type LiveRule =
  | "probing"
  | "revoked_identity_reuse"
  | "request_id_abuse"
  | "integrity_failure"
  | "malformed_burst";

export type LiveResponse = "recorded" | "quarantined" | "fail_closed";

export interface LiveOptions {
  /** denials on assets the actor doesn't own / that don't exist */
  probe: { count: number; windowMs: number };
  /** attempts by an identity that is revoked or disabled */
  revokedReuse: { count: number; windowMs: number };
  /** malformed requests from anyone */
  invalid: { count: number; windowMs: number };
  /** don't raise the same rule for the same actor again within this time */
  dedupeMs: number;
}

export const DEFAULT_LIVE: LiveOptions = {
  probe: { count: 5, windowMs: 60_000 },
  revokedReuse: { count: 3, windowMs: 10 * 60_000 },
  invalid: { count: 10, windowMs: 60_000 },
  dedupeMs: 60_000,
};

export interface AlertDraft {
  rule: LiveRule;
  severity: "high" | "medium";
  actor: string | null;
  /** request IDs (or fixed error codes for malformed bursts) supporting the alert, max 20 */
  evidence: string[];
  count: number;
  window_ms: number;
  summary: string;
  response: LiveResponse;
}

export type AlertRecord = AlertDraft & { seq: number; ts: string; prev: string; hash: string; sig: string };

const GENESIS = "0".repeat(64);
const MAX_EVIDENCE = 20;
const MAX_INVALID_KEPT = 200;
const PROBE_REASONS = new Set(["not_owner", "unknown_asset"]);
const REVOKED_REASONS = new Set(["revoked", "disabled"]);

// ---------------------------------------------------------------- pure rules

function inWindow(r: AuditRecord, latestMs: number, windowMs: number): boolean {
  const t = Date.parse(r.ts);
  return Number.isFinite(t) && t <= latestMs && latestMs - t <= windowMs;
}

const isDecision = (r: AuditRecord) => r.type === "access_decision" || r.type === "duplicate_request_id";

/**
 * Rules over the audit log right after `latest` was appended. Pure: no I/O.
 * `records` must include `latest`.
 */
export function evaluateDecision(
  records: readonly AuditRecord[],
  latest: AuditRecord,
  opts: LiveOptions = DEFAULT_LIVE,
): AlertDraft[] {
  if (!isDecision(latest) || latest.decision !== "deny" || latest.actor === null) return [];
  const actor = latest.actor;
  const latestMs = Date.parse(latest.ts);
  if (!Number.isFinite(latestMs)) return [];
  const out: AlertDraft[] = [];
  const reason = latest.reason ?? "";

  const matching = (reasons: Set<string>, windowMs: number) =>
    records.filter((r) => isDecision(r) && r.actor === actor && r.decision === "deny" &&
      reasons.has(r.reason ?? "") && inWindow(r, latestMs, windowMs));
  const ids = (rs: AuditRecord[]) => rs.map((r) => r.request_id ?? "").filter((s) => s !== "").slice(-MAX_EVIDENCE);

  if (PROBE_REASONS.has(reason)) {
    const hits = matching(PROBE_REASONS, opts.probe.windowMs);
    if (hits.length >= opts.probe.count) {
      const assets = new Set(hits.map((r) => r.asset));
      out.push({
        rule: "probing", severity: "medium", actor, evidence: ids(hits), count: hits.length, window_ms: opts.probe.windowMs,
        summary: `${hits.length} denied requests on ${assets.size} asset(s) the actor does not own or that do not exist within ${opts.probe.windowMs / 1000} s: enumeration or impersonation attempt. Nothing was disclosed.`,
        response: "recorded",
      });
    }
  }

  if (REVOKED_REASONS.has(reason)) {
    const hits = matching(REVOKED_REASONS, opts.revokedReuse.windowMs);
    if (hits.length >= opts.revokedReuse.count) {
      out.push({
        rule: "revoked_identity_reuse", severity: "high", actor, evidence: ids(hits), count: hits.length, window_ms: opts.revokedReuse.windowMs,
        summary: `A ${reason} identity keeps requesting access (${hits.length} attempts within ${opts.revokedReuse.windowMs / 60_000} min), e.g. a lost or stolen device still in use. All were denied; identity quarantined.`,
        response: "quarantined",
      });
    }
  }

  if (reason === "request_id_reused") {
    out.push({
      rule: "request_id_abuse", severity: "medium", actor, evidence: ids([latest]), count: 1, window_ms: 0,
      summary: "A request reused an existing request ID with a different actor/asset or after a deny: attempt to obtain content or overwrite an audit record. Denied; the first recorded decision is unchanged.",
      response: "recorded",
    });
  }

  if (reason === "integrity_failure") {
    out.push({
      rule: "integrity_failure", severity: "high", actor, evidence: ids([latest]), count: 1, window_ms: 0,
      summary: "A protected body failed authenticated decryption (stored data altered or corrupted). Request denied; service fails closed.",
      response: "fail_closed",
    });
  }
  return out;
}

// ---------------------------------------------------------------- alert log

export function alertsPath(paths: StatePaths): string {
  return join(paths.root, "alerts.jsonl");
}
function invalidPath(paths: StatePaths): string {
  return join(paths.root, "alerts.invalid.json");
}

function alertHash(prev: string, a: Omit<AlertRecord, "hash" | "sig">): string {
  const canonical = JSON.stringify([
    a.seq, a.ts, a.rule, a.severity, a.actor, a.evidence, a.count, a.window_ms, a.summary, a.response, a.prev,
  ]);
  return createHash("sha256").update(prev, "utf8").update("\n").update(canonical, "utf8").digest("hex");
}

export function readAlerts(paths: StatePaths): AlertRecord[] {
  const text = readTextIfExists(alertsPath(paths));
  if (!text) return [];
  return text.split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l) as AlertRecord);
}

function recentlyRaised(existing: readonly AlertRecord[], d: AlertDraft, nowMs: number, dedupeMs: number): boolean {
  for (let i = existing.length - 1; i >= 0; i--) {
    const a = existing[i];
    const t = Date.parse(a.ts);
    if (!Number.isFinite(t) || nowMs - t > dedupeMs) break;
    if (a.rule === d.rule && a.actor === d.actor) return true;
  }
  return false;
}

/** Append one alert (chained + signed when the audit key exists). Returns the record. */
export function appendAlert(paths: StatePaths, d: AlertDraft, existing: AlertRecord[] = readAlerts(paths), now = new Date()): AlertRecord {
  const last = existing.at(-1);
  const base = { ...d, evidence: d.evidence.slice(-MAX_EVIDENCE), seq: last ? last.seq + 1 : 1, ts: now.toISOString(), prev: last ? last.hash : GENESIS };
  const hash = alertHash(base.prev, base);
  const key = readTextIfExists(paths.auditKey);
  let sig = "";
  if (key) {
    try { sig = signBytes(Buffer.from(key, "base64"), Buffer.from(hash, "utf8")).toString("base64"); } catch { sig = ""; }
  }
  const record: AlertRecord = { ...base, hash, sig };
  appendDurable(alertsPath(paths), JSON.stringify(record));
  existing.push(record);
  // Fixed text only: rule names are ours, never user data.
  process.stderr.write(`security alert: ${record.rule} (${record.severity}, ${record.response})\n`);
  return record;
}

export type AlertVerification = { ok: boolean; records: number; first_bad_seq: number | null; signatures_checked: boolean };

/** Verify chain, hashes and (when keys/audit.pub exists) every signature. */
export function verifyAlerts(paths: StatePaths): AlertVerification {
  const pubText = readTextIfExists(paths.auditPub);
  const pub = pubText ? Buffer.from(pubText, "base64") : undefined;
  let records: AlertRecord[];
  try { records = readAlerts(paths); } catch { return { ok: false, records: 0, first_bad_seq: 0, signatures_checked: pub !== undefined }; }
  let prev = GENESIS;
  for (let i = 0; i < records.length; i++) {
    const { hash, sig, ...rest } = records[i];
    const badSig = pub !== undefined && !verifyBytes(pub, Buffer.from(hash, "utf8"), Buffer.from(sig ?? "", "base64"));
    if (rest.seq !== i + 1 || rest.prev !== prev || alertHash(prev, rest) !== hash || badSig) {
      return { ok: false, records: records.length, first_bad_seq: i + 1, signatures_checked: pub !== undefined };
    }
    prev = hash;
  }
  return { ok: true, records: records.length, first_bad_seq: null, signatures_checked: pub !== undefined };
}

function raise(paths: StatePaths, drafts: AlertDraft[], opts: LiveOptions, now: Date): AlertRecord[] {
  if (drafts.length === 0) return [];
  let existing: AlertRecord[];
  try { existing = readAlerts(paths); } catch { existing = []; } // a damaged alert log must not stop new alerts
  const written: AlertRecord[] = [];
  for (const d of drafts) {
    if (recentlyRaised(existing, d, now.getTime(), opts.dedupeMs)) continue;
    written.push(appendAlert(paths, d, existing, now));
  }
  return written;
}

// ---------------------------------------------------------------- hooks (never throw)

/** After a decision is recorded. The caller holds the state lock. */
export function onDecision(paths: StatePaths, records: readonly AuditRecord[], latest: AuditRecord, opts: LiveOptions = DEFAULT_LIVE, now = new Date()): AlertRecord[] {
  try {
    return raise(paths, evaluateDecision(records, latest, opts), opts, now);
  } catch {
    return [];
  }
}

/** Stored state or log failed an integrity check. `what` must be fixed text, never request data. */
export function onIntegrityFailure(paths: StatePaths, what: string, opts: LiveOptions = DEFAULT_LIVE, now = new Date()): AlertRecord[] {
  try {
    if (!existsSync(paths.root)) return [];
    return withLock(paths.root, () => raise(paths, [{
      rule: "integrity_failure", severity: "high", actor: null, evidence: [what.slice(0, 80)], count: 1, window_ms: 0,
      summary: "Stored state or the audit log failed an integrity check (tampering, rollback, truncation or corruption). All requests fail closed until an operator verifies the log and restores a verified backup.",
      response: "fail_closed",
    }], opts, now));
  } catch {
    return [];
  }
}

/** A request was rejected as malformed. `code` is our fixed error code. Only after setup. */
export function onInvalidRequest(paths: StatePaths, code: string, opts: LiveOptions = DEFAULT_LIVE, now = new Date()): AlertRecord[] {
  try {
    if (!existsSync(paths.state)) return [];
    return withLock(paths.root, () => {
      const nowMs = now.getTime();
      let seen: [number, string][] = [];
      try {
        const parsed: unknown = JSON.parse(readTextIfExists(invalidPath(paths)) ?? "[]");
        if (Array.isArray(parsed)) seen = parsed.filter((x): x is [number, string] => Array.isArray(x) && typeof x[0] === "number" && typeof x[1] === "string");
      } catch { seen = []; }
      seen = seen.filter(([t]) => nowMs - t <= opts.invalid.windowMs && t <= nowMs);
      seen.push([nowMs, code.slice(0, 40)]);
      atomicWriteFile(invalidPath(paths), JSON.stringify(seen.slice(-MAX_INVALID_KEPT)));
      if (seen.length < opts.invalid.count) return [];
      const codes = [...new Set(seen.map(([, c]) => c))];
      return raise(paths, [{
        rule: "malformed_burst", severity: "medium", actor: null, evidence: codes.slice(0, MAX_EVIDENCE), count: seen.length, window_ms: opts.invalid.windowMs,
        summary: `${seen.length} malformed requests within ${opts.invalid.windowMs / 1000} s (${codes.join(", ")}): fuzzing or injection attempt. All rejected with fixed error codes; no input echoed.`,
        response: "recorded",
      }], opts, now);
    });
  } catch {
    return [];
  }
}
