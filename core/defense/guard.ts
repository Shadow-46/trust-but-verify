import { join } from "node:path";
import { appendAudit, readAudit } from "../audit/log.ts";
import { signBytes } from "../crypto/sign.ts";
import { appendDurable, atomicWriteFile, readTextIfExists, withLock } from "../store/fsx.ts";
import type { StatePaths } from "../store/paths.ts";

/**
 * Self-defence: the service watches its own traffic for attack patterns and
 * responds. Detection always runs and writes ML-DSA-signed `security_alert`
 * records into the audit log, with the rule, the identity and the evidence.
 *
 * Automatic quarantine of a probing identity is opt-in (TRACK4_AUTO_QUARANTINE=1).
 * Actor IDs in this interface are caller-supplied, so quarantining by default
 * would let an attacker lock out a real user by impersonating them; operators
 * enable it where identities are authenticated (and in the demo console).
 */

const WINDOW_MS = 60_000;
const PROBE_DISTINCT_ASSETS = 3;
const MALFORMED_BURST = 10;

type Defense = { denials: [string, string, number][]; invalid: number[]; quarantined: string[]; alerted: string[] };

const file = (paths: StatePaths) => join(paths.root, "defense.json");

function load(paths: StatePaths): Defense {
  try {
    const d = JSON.parse(readTextIfExists(file(paths)) ?? "") as Defense;
    if (Array.isArray(d.denials) && Array.isArray(d.invalid)) return { quarantined: [], alerted: [], ...d };
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

function alert(paths: StatePaths, d: Defense, key: string, rule: string, actor: string | null, asset: string | null, detail: string): void {
  if (d.alerted.includes(key)) return; // one alert per rule, identity and minute
  d.alerted.push(key);
  const last = readAudit(paths).at(-1);
  appendAudit(paths, {
    type: "security_alert",
    request_id: null,
    actor,
    asset,
    decision: null,
    reason: `${rule}: ${detail}`,
    state_version: last?.state_version ?? 0,
  });
}

export const autoQuarantine = () => process.env.TRACK4_AUTO_QUARANTINE === "1";

export function isQuarantined(paths: StatePaths, actor: string): boolean {
  return autoQuarantine() && load(paths).quarantined.includes(actor);
}

/** Call inside the state lock after every access decision. */
export function observeDecision(paths: StatePaths, actor: string, asset: string, decision: "allow" | "deny", reason: string, now = Date.now()): void {
  const d = load(paths);
  const minute = Math.floor(now / WINDOW_MS);
  if (decision === "deny") {
    d.denials.push([actor, asset, now]);
    const probed = new Set(d.denials.filter(([a, , t]) => a === actor && now - t <= WINDOW_MS).map(([, s]) => s));
    if (probed.size >= PROBE_DISTINCT_ASSETS) {
      alert(paths, d, `probe:${actor}:${minute}`, "probing", actor, null, `denied on ${probed.size} different files within 60 s`);
      if (autoQuarantine() && !d.quarantined.includes(actor)) {
        d.quarantined.push(actor);
        alert(paths, d, `quarantine:${actor}`, "quarantined", actor, null, "all further requests by this identity are refused until an operator reviews it");
      }
    }
  }
  if (reason === "revoked" || reason === "disabled") {
    alert(paths, d, `revoked-use:${actor}:${minute}`, "revoked_identity_used", actor, asset, `request by a ${reason} identity (possible lost or stolen device)`);
  } else if (reason === "request_id_reused") {
    alert(paths, d, `reuse:${actor}:${minute}`, "request_id_reuse", actor, asset, "a used request ID was presented again (possible replay)");
  } else if (reason === "integrity_failure") {
    alert(paths, d, `integrity:${asset}:${minute}`, "data_integrity", actor, asset, "stored ciphertext failed authentication; access refused");
  }
  save(paths, d, now);
}

/**
 * Alerts raised when the audit log itself may be untrustworthy (tampered state,
 * malformed input before any verification) must never be appended to that log:
 * appending would write a fresh signed head over a possibly truncated log and
 * make it look valid again. They go to a separate, ML-DSA-signed side file.
 */
const sideFile = (paths: StatePaths) => join(paths.root, "security-alerts.jsonl");

function sideAlert(paths: StatePaths, d: Defense, key: string, rule: string, detail: string, now: number): void {
  if (d.alerted.includes(key)) return;
  d.alerted.push(key);
  const ts = new Date(now).toISOString();
  const body = JSON.stringify(["tbv/alert/v1", ts, rule, detail]);
  const key64 = readTextIfExists(paths.auditKey);
  const sig = key64 ? signBytes(Buffer.from(key64, "base64"), Buffer.from(body, "utf8")).toString("base64") : "";
  appendDurable(sideFile(paths), JSON.stringify({ ts, rule, detail, sig }));
}

/** Record malformed or invalid requests and tampered state; never throws. */
export function observeFailure(paths: StatePaths, kind: "invalid" | "integrity", now = Date.now()): void {
  try {
    withLock(paths.root, () => {
      const d = load(paths);
      const minute = Math.floor(now / WINDOW_MS);
      if (kind === "integrity") {
        sideAlert(paths, d, `state-integrity:${minute}`, "state_integrity", "state or audit log failed verification; service is fail-closed", now);
      } else {
        d.invalid.push(now);
        const recent = d.invalid.filter((t) => now - t <= WINDOW_MS).length;
        if (recent >= MALFORMED_BURST) sideAlert(paths, d, `malformed:${minute}`, "malformed_input_burst", `${recent} invalid requests within 60 s`, now);
      }
      save(paths, d, now);
    });
  } catch {
    // Monitoring must never turn a refused request into a crash.
  }
}

export function securityAlerts(paths: StatePaths) {
  let logged: { seq: number | null; ts: string; actor: string | null; asset: string | null; rule: string; detail: string }[] = [];
  try {
    logged = readAudit(paths)
      .filter((r) => r.type === "security_alert")
      .map(({ seq, ts, actor, asset, reason }) => ({ seq, ts, actor, asset, rule: (reason ?? "").split(":")[0], detail: (reason ?? "").split(": ").slice(1).join(": ") }));
  } catch {
    // the log itself failed verification; the side file still reports it
  }
  const side = (readTextIfExists(sideFile(paths)) ?? "")
    .split("\n")
    .filter((l) => l.length > 0)
    .flatMap((l) => {
      try {
        const a = JSON.parse(l) as { ts: string; rule: string; detail: string };
        return [{ seq: null, ts: a.ts, actor: null, asset: null, rule: a.rule, detail: a.detail }];
      } catch {
        return [];
      }
    });
  return [...logged, ...side].sort((a, b) => a.ts.localeCompare(b.ts));
}
