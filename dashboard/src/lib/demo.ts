/* eslint-disable @typescript-eslint/no-explicit-any -- operator API returns untyped JSON */

/** Shared helpers for the Live Monitor and the Attack Lab (plain-language, no secrets). */

export type Res = { ok: boolean; out: any; blocked?: boolean; ms?: number };

export async function api(action: string, extra: Record<string, unknown> = {}): Promise<Res> {
  const r = await fetch("/api/run", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action, ...extra }) });
  return r.json();
}

export const time = (iso: string | number) => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

const BECAUSE: Record<string, string> = {
  owner: "they own it and are not revoked",
  not_owner: "they do not own it",
  revoked: "their identity was revoked after the device was reported lost",
  disabled: "the account is disabled",
  unknown_asset: "the file does not exist",
  integrity_failure: "the stored data failed its integrity check",
  request_id_reused: "the request ID was already used",
  quarantined: "the identity is quarantined after probing",
};

const RULE: Record<string, string> = {
  probing: "Probing detected",
  quarantined: "Identity quarantined",
  revoked_identity_used: "Revoked identity used",
  request_id_reuse: "Request ID replayed",
  data_integrity: "Tampered file detected",
  state_integrity: "Tampered state or log detected",
  malformed_input_burst: "Flood of malformed requests",
  suspicious_identifier: "Injection attempt in an ID",
  encrypted_copy_refused: "Encrypted copy of another's file refused",
  replayed_request: "Replayed request",
  request_for_another_node: "Request replayed to another node",
  bad_request_signature: "Forged request signature",
  revoked_device_used: "Revoked device still in use",
  stale_request: "Stale or future request",
  unknown_device: "Unknown device",
  forged_or_old_policy: "Forged or old policy refused",
};

export const ruleLabel = (rule: string) => RULE[rule] ?? rule.replace(/_/g, " ");

/** `service` is set on rows from a cluster node's own signed log ("node-a"…); absent for the file service. */
export type Row = { seq: number; ts: string; type: string; actor: string | null; asset: string | null; decision: string | null; reason: string | null; hash: string; service?: string; request_id?: string | null };

const NODE_BECAUSE: Record<string, string> = {
  authorized: "device enrolled, signature valid, addressed here, fresh nonce",
  device_revoked: "the device was revoked",
  actor_revoked: "the identity was revoked",
  replayed_request: "its nonce was already used (replay)",
  wrong_node: "it was signed for another node",
  bad_signature: "its ML-DSA signature is invalid",
  stale_or_future_request: "its timestamp is outside ±30 s",
  unknown_device: "the device was never enrolled",
  device_owner_mismatch: "the device belongs to someone else",
  key_version_retired: "its key version is retired",
  in_flight_transfer: "an in-flight transfer on its original key version",
};

/** A record from a node's own signed log as a sentence. */
function describeNode(r: Row): { text: string; tone: "good" | "bad" | "warn" | "neutral" } {
  const node = r.service ?? "node";
  switch (r.type) {
    case "node_decision":
      return r.decision === "allow"
        ? { text: `${node} allowed ${r.actor}'s ${r.asset}: ${NODE_BECAUSE[r.reason ?? ""] ?? r.reason}`, tone: "good" }
        : { text: `${node} refused ${r.actor}'s ${r.asset}: ${NODE_BECAUSE[r.reason ?? ""] ?? r.reason}`, tone: "bad" };
    case "policy_adopted":
      return { text: `${node} verified and adopted ${r.reason?.replace("adopted ", "") ?? "a new policy"}`, tone: "neutral" };
    case "policy_rejected":
      return { text: `${node} refused a policy (${r.request_id ?? "?"}): ${r.reason === "bad_signature" ? "not signed by the control plane" : "older than the one it holds"}`, tone: "bad" };
    default:
      return describe({ ...r, service: undefined });
  }
}

export { describeNode };

/** One audit record as a sentence an operator (or judge) can read aloud. */
export function describe(r: Row): { text: string; tone: "good" | "bad" | "warn" | "neutral" } {
  if (r.service && r.type !== "security_alert") return describeNode(r);
  const who = r.actor ?? "someone";
  switch (r.type) {
    case "access_decision":
      return r.decision === "allow"
        ? { text: `${who} opened ${r.asset} — ${BECAUSE[r.reason ?? ""] ?? r.reason}`, tone: "good" }
        : { text: `${who} was denied ${r.asset} — ${BECAUSE[r.reason ?? ""] ?? r.reason}`, tone: "bad" };
    case "revoke":
      return { text: `${who}'s access revoked everywhere (device reported lost)`, tone: "warn" };
    case "setup":
      return { text: "Demo set up: files encrypted, signed audit log started", tone: "neutral" };
    case "key_rotation":
      return { text: "Data key rotated; every file re-encrypted in one atomic step", tone: "neutral" };
    case "backup_restored":
      return { text: "Service recovered from a signed backup (later revocations kept)", tone: "good" };
    case "duplicate_request_id":
      return { text: `Replayed request ID from ${who} refused`, tone: "bad" };
    case "security_alert": {
      const [rule, ...rest] = (r.reason ?? "").split(": ");
      // "identity=… service=… events=… [seq=n] — detail" (older records: just the detail)
      const m = /^identity=(.*) service=(.*?) events=(.*?)(?: seq=(\d+))? — ([\s\S]*)$/.exec(rest.join(": "));
      return m
        ? { text: `${ruleLabel(rule)}: ${m[5]} (identity ${m[1]}, ${m[2]}, event ${m[3]}${m[4] ? `, audit #${m[4]}` : ""})`, tone: "bad" }
        : { text: `${ruleLabel(rule)}${r.actor ? ` (${r.actor})` : ""}: ${rest.join(": ")}`, tone: "bad" };
    }
    default:
      return { text: r.type.replace(/_/g, " "), tone: "neutral" };
  }
}
