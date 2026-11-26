import { join } from "node:path";
import { appendAudit, readAudit } from "../audit/log.ts";
import type { AuditRecord } from "../audit/log.ts";
import { signBytes } from "../crypto/sign.ts";
import { appendDurable, atomicWriteFile, readTextIfExists, withLock } from "../store/fsx.ts";
import type { StatePaths } from "../store/paths.ts";

/**
 * Self-defence: the service watches its own traffic for attack patterns and
 * responds. Detection always runs and writes ML-DSA-signed `security_alert`
 * records into the audit log, with the rule, the identity and the evidence.
 *
 * Every alert names the **identity** (the actor, or "unauthenticated caller"),
 * the **service** that raised it and the triggering **event(s)** (request IDs,
 * the audit seq when one exists, or a count and time window for bursts), in a
 * fixed, parseable form:
 *   `<rule>: identity=<actor> service=file-service adapter events=<id,id,...> seq=<n> — <detail>`
 *
 * Automatic quarantine of a probing identity is opt-in (TRACK4_AUTO_QUARANTINE=1).
 * Actor IDs in this interface are caller-supplied, so quarantining by default
 * would let an attacker lock out a real user by impersonating them; operators
 * enable it where identities are authenticated (and in the demo console).
 */

const WINDOW_MS = 60_000;
const PROBE_DISTINCT_ASSETS = 3;
const MALFORMED_BURST = 10;
/** Request IDs kept as evidence per alert. */
const MAX_EVENTS = 10;

export const SERVICE = "file-service adapter";
export const UNAUTHENTICATED = "unauthenticated caller";

/** [actor, asset, time, request_id] for recent denials. */
type Denial = [string, string, number, string];
type Defense = { denials: Denial[]; invalid: number[]; quarantined: string[]; alerted: string[] };

const file = (paths: StatePaths) => join(paths.root, "defense.json");

function load(paths: StatePaths): Defense {
  try {
    const d = JSON.parse(readTextIfExists(file(paths)) ?? "") as Defense;
    if (Array.isArray(d.denials) && Array.isArray(d.invalid)) {
      // Older files stored [actor, asset, time]; keep them with an empty request ID.
      const denials = d.denials.map((x) => [x[0], x[1], x[2], typeof x[3] === "string" ? x[3] : ""] as Denial);
      return { quarantined: [], alerted: [], ...d, denials };
    }
  } catch {
    // missing or unreadable: start fresh (alerts already written stay in the signed log)
  }
  return { denials: [], invalid: [], quarantined: [], alerted: [] };
}

function save(paths: StatePaths, d: Defense, now: number): void {
  d.denials = d.denials.filter(([, , t]) => now - t <= WINDOW_MS);
  d.invalid = d.invalid.filter((t) => now - t <= WINDOW_MS);
  d.alerted = d.alerted.slice(-200);
  atomicWriteFile(file(paths), JSON.stringify(d));
}

/** The parseable alert text. Request IDs are caller data: JSON-escaped where needed, never on stderr. */
function alertText(rule: string, identity: string, events: string[], seq: number | null, detail: string): string {
  const ids = events.map((e) => (/^[\w.:-]+$/.test(e) ? e : JSON.stringify(e))).join(",");
  return `${rule}: identity=${identity} service=${SERVICE} events=${ids || "-"}${seq !== null ? ` seq=${seq}` : ""} — ${detail}`;
}

/** The decision record that triggered the alert(s), read lazily (only when an alert fires). */
type Trigger = () => AuditRecord | undefined;

function alert(paths: StatePaths, d: Defense, trigger: Trigger, key: string, rule: string, actor: string | null, asset: string | null, events: string[], detail: string): void {
  if (d.alerted.includes(key)) return; // one alert per rule, identity and minute
  d.alerted.push(key);
  const last = trigger(); // every alert raised by one decision points at that decision
  const evidence = events.filter((e) => e.length > 0).slice(-MAX_EVENTS);
  appendAudit(paths, {
    type: "security_alert",
    request_id: evidence.at(-1) ?? null, // the triggering request, as a structured field too
    actor,
    asset,
    decision: null,
    reason: alertText(rule, actor ?? UNAUTHENTICATED, evidence, last?.seq ?? null, detail),
    state_version: last?.state_version ?? 0,
  });
}

export const autoQuarantine = () => process.env.TRACK4_AUTO_QUARANTINE === "1";

export function isQuarantined(paths: StatePaths, actor: string): boolean {
  return autoQuarantine() && load(paths).quarantined.includes(actor);
}

/** Call inside the state lock after every access decision (after it is in the audit log). */
export function observeDecision(paths: StatePaths, actor: string, asset: string, decision: "allow" | "deny", reason: string, requestId = "", now = Date.now()): void {
  const d = load(paths);
  const minute = Math.floor(now / WINDOW_MS);
  let decisionRecord: AuditRecord | undefined | null = null;
  const trigger: Trigger = () => (decisionRecord === null ? (decisionRecord = readAudit(paths).at(-1)) : decisionRecord);
  if (decision === "deny") {
    d.denials.push([actor, asset, now, requestId]);
    const recent = d.denials.filter(([a, , t]) => a === actor && now - t <= WINDOW_MS);
    const probed = new Set(recent.map(([, s]) => s));
    if (probed.size >= PROBE_DISTINCT_ASSETS) {
      const ids = recent.map(([, , , id]) => id);
      alert(paths, d, trigger, `probe:${actor}:${minute}`, "probing", actor, null, ids, `denied on ${probed.size} different files within 60 s`);
      if (autoQuarantine() && !d.quarantined.includes(actor)) {
        d.quarantined.push(actor);
        alert(paths, d, trigger, `quarantine:${actor}`, "quarantined", actor, null, ids, "all further requests by this identity are refused until an operator reviews it");
      }
    }
  }
  if (reason === "revoked" || reason === "disabled") {
    alert(paths, d, trigger, `revoked-use:${actor}:${minute}`, "revoked_identity_used", actor, asset, [requestId], `request by a ${reason} identity (possible lost or stolen device)`);
  } else if (reason === "request_id_reused") {
    alert(paths, d, trigger, `reuse:${actor}:${minute}`, "request_id_reuse", actor, asset, [requestId], "a used request ID was presented again (possible replay)");
  } else if (reason === "integrity_failure") {
    alert(paths, d, trigger, `integrity:${asset}:${minute}`, "data_integrity", actor, asset, [requestId], "stored ciphertext failed authentication; access refused");
  }
  save(paths, d, now);
}

/**
 * Alerts raised when the audit log itself may be untrustworthy (tampered state,
 * malformed input before any verification) must never be appended to that log:
 * appending would write a fresh signed head over a possibly truncated log and
 * make it look valid again. They go to a separate, ML-DSA-signed side file.
 * Identity, service and event are inside the signed body.
 */
const sideFile = (paths: StatePaths) => join(paths.root, "security-alerts.jsonl");

type SideAlert = { ts: string; rule: string; identity: string; service: string; event: string; detail: string; sig: string };

function sideAlert(paths: StatePaths, d: Defense, key: string, rule: string, event: string, detail: string, now: number): void {
  if (d.alerted.includes(key)) return;
  d.alerted.push(key);
  const ts = new Date(now).toISOString();
  const identity = UNAUTHENTICATED; // these fire before (or instead of) any identity check
  const body = JSON.stringify(["tbv/alert/v2", ts, rule, identity, SERVICE, event, detail]);
  const key64 = readTextIfExists(paths.auditKey);
  const sig = key64 ? signBytes(Buffer.from(key64, "base64"), Buffer.from(body, "utf8")).toString("base64") : "";
  const record: SideAlert = { ts, rule, identity, service: SERVICE, event, detail, sig };
  appendDurable(sideFile(paths), JSON.stringify(record));
}

/** Record malformed or invalid requests and tampered state; never throws. */
export function observeFailure(paths: StatePaths, kind: "invalid" | "integrity", now = Date.now()): void {
  try {
    withLock(paths.root, () => {
      const d = load(paths);
      const minute = Math.floor(now / WINDOW_MS);
      const at = new Date(now).toISOString();
      if (kind === "integrity") {
        sideAlert(paths, d, `state-integrity:${minute}`, "state_integrity", `request at ${at} refused: state or audit log failed verification`, "state or audit log failed verification; service is fail-closed", now);
      } else {
        d.invalid.push(now);
        const recent = d.invalid.filter((t) => now - t <= WINDOW_MS);
        if (recent.length >= MALFORMED_BURST) {
          const from = new Date(Math.min(...recent)).toISOString();
          sideAlert(paths, d, `malformed:${minute}`, "malformed_input_burst", `${recent.length} invalid requests between ${from} and ${at}`, `${recent.length} invalid requests within 60 s`, now);
        }
      }
      save(paths, d, now);
    });
  } catch {
    // Monitoring must never turn a refused request into a crash.
  }
}

export type SecurityAlert = {
  seq: number | null;
  ts: string;
  actor: string | null;
  asset: string | null;
  rule: string;
  detail: string;
  /** who: the actor, or "unauthenticated caller" */
  identity: string;
  /** which service raised it */
  service: string;
  /** what triggered it: request IDs (+ audit seq), or a count and time window */
  events: string;
};

/** Parse `<rule>: identity=… service=… events=… [seq=n] — <detail>`; older records degrade gracefully. */
function parseReason(reason: string): { rule: string; events: string; detail: string } {
  const colon = reason.indexOf(": ");
  const rule = colon === -1 ? reason : reason.slice(0, colon);
  const rest = colon === -1 ? "" : reason.slice(colon + 2);
  const m = /^identity=.* service=.* events=(.*?)(?: seq=(\d+))? — ([\s\S]*)$/.exec(rest);
  if (!m) return { rule, events: "-", detail: rest };
  return { rule, events: m[2] ? `${m[1]} (audit seq ${m[2]})` : m[1], detail: m[3] };
}

export function securityAlerts(paths: StatePaths): SecurityAlert[] {
  let logged: SecurityAlert[] = [];
  try {
    logged = readAudit(paths)
      .filter((r) => r.type === "security_alert")
      .map(({ seq, ts, actor, asset, reason }) => {
        const p = parseReason(reason ?? "");
        return { seq, ts, actor, asset, rule: p.rule, detail: p.detail, identity: actor ?? UNAUTHENTICATED, service: SERVICE, events: p.events };
      });
  } catch {
    // the log itself failed verification; the side file still reports it
  }
  const side = (readTextIfExists(sideFile(paths)) ?? "")
    .split("\n")
    .filter((l) => l.length > 0)
    .flatMap((l) => {
      try {
        const a = JSON.parse(l) as Partial<SideAlert> & { ts: string; rule: string; detail: string };
        return [{
          seq: null, ts: a.ts, actor: null, asset: null, rule: a.rule, detail: a.detail,
          identity: a.identity ?? UNAUTHENTICATED, service: a.service ?? SERVICE, events: a.event ?? "-",
        }];
      } catch {
        return [];
      }
    });
  return [...logged, ...side].sort((a, b) => a.ts.localeCompare(b.ts));
}
