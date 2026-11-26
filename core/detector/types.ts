// Detector input/output shapes (goals 6-8). Local to the detector until
// core/types.ts exists; then the shared parts move there by agreement.

/** One access-log record, exactly as received. Raw fields are never rewritten. */
export interface LogEvent {
  event_id: string;
  event_time_utc: string;
  received_time_utc: string;
  source_clock_offset_ms: number;
  actor: string;
  source_service: string;
  target_service: string;
  action: string;
  role_before: string;
  role_after: string;
  outcome: string;
  approval_id: string;
  session_id: string;
  correlation_id: string;
}

export interface GrantApproval {
  approval_id: string;
  approved_by: string;
  subject: string;
  operation: "grant_role";
  role: string;
  scope: string[];
  valid_from_utc: string;
  /** Exclusive. */
  valid_until_utc: string;
}

export interface RevokeApproval {
  approval_id: string;
  approved_by: string;
  subject: string;
  operation: "revoke_role";
  role: string;
  effective_at_utc: string;
}

export type Approval = GrantApproval | RevokeApproval;

/** Expected-behaviour baseline, written by hand (core/detector/policy.json). */
export interface Policy {
  /** role -> services that role may normally reach */
  roles: Map<string, Set<string>>;
  /** "source->target" keys of service edges seen in normal operation */
  knownEdges: Set<string>;
  outOfScopeServices: Set<string>;
  /** "target:action" keys that are outside expected scope */
  outOfScopeActions: Set<string>;
  lateral: { minDistinctEdges: number; windowMs: number };
  reviewAfterRoleChangeWindowMs: number;
  clock: { uncertaintyMs: number; maxSupportedSkewMs: number };
}

export type Label =
  | "routine"
  | "approved_change"
  | "unexpected_role_change"
  | "review_after_role_change"
  | "lateral_movement_candidate"
  | "routine_delayed_delivery"
  | "routine_clock_offset"
  | "routine_denial"
  | "isolated_denial"
  | "unexpected_access"
  | "access_outside_approval"
  | "unapproved_admin_action"
  | "duplicate_event";

export type Flag =
  | "unexpected_edge"
  | "out_of_scope"
  | "delayed_delivery"
  | "clock_offset"
  | "negative_raw_delay"
  | "ambiguous_order"
  | "unsupported_skew"
  | "duplicate_event_id"
  | "after_revocation";

/** Time facts for one event, kept next to (never instead of) the raw timestamps. */
export interface TimeInfo {
  raw_event_ms: number;
  received_ms: number;
  /** event time on the collector clock: event_time - source offset */
  corrected_event_ms: number;
  corrected_event_utc: string;
  /** received - corrected event time */
  collector_delay_ms: number;
  uncertainty_ms: number;
}

export interface Classification {
  event_id: string;
  /** position in the input (receipt order), 0-based */
  receipt_index: number;
  label: Label;
  reason: string;
  flags: Flag[];
  time: TimeInfo;
  /** alert IDs this event supports */
  alert_ids: string[];
}

export type AlertRule =
  | "unexpected_role_change"
  | "lateral_movement_candidate"
  | "unexpected_access"
  | "access_outside_approval"
  | "unapproved_admin_action";

/** A MITRE ATT&CK reference (Enterprise matrix): exact ID and name. */
export interface AttackRef {
  id: string;
  name: string;
}

/** ATT&CK tactics and techniques an alert is consistent with (context for analysts, not proof). */
export interface AttackMapping {
  tactics: AttackRef[];
  techniques: AttackRef[];
}

export interface Alert {
  alert_id: string;
  rule: AlertRule;
  /** MITRE ATT&CK mapping for this rule */
  attack: AttackMapping;
  severity: "high" | "medium" | "low";
  actor: string;
  session_ids: string[];
  correlation_ids: string[];
  /** supporting events, in corrected event-time order */
  event_ids: string[];
  /** service path for lateral movement (source, then each target), else the edge */
  services: string[];
  summary: string;
  /** what the evidence does NOT show (e.g. denied != compromised) */
  limits: string;
  /** collector time of the event that made the rule fire (time-to-alert basis) */
  detected_at_received_utc: string;
  detected_by_event_id: string;
}

export interface DetectionReport {
  /** one entry per input event, in receipt order */
  events: Classification[];
  alerts: Alert[];
  /** event IDs sorted by corrected event time (ties: receipt order) */
  timeline: string[];
}
