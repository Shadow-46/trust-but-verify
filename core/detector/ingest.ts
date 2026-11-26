// Strict loaders for events, approvals and policy. Every ID stays an opaque
// string; anything keyed by an ID uses Map/Set.

import { readFileSync } from "node:fs";
import { parseCsvRecords } from "./csv.ts";
import type { Approval, LogEvent, Policy } from "./types.ts";

export const EVENT_COLUMNS = [
  "event_id",
  "event_time_utc",
  "received_time_utc",
  "source_clock_offset_ms",
  "actor",
  "source_service",
  "target_service",
  "action",
  "role_before",
  "role_after",
  "outcome",
  "approval_id",
  "session_id",
  "correlation_id",
] as const;

const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;

export function parseUtc(value: unknown, what: string): number {
  if (typeof value !== "string" || !ISO_UTC.test(value)) {
    throw new Error(`${what}: expected an ISO-8601 UTC timestamp`);
  }
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) throw new Error(`${what}: invalid timestamp`);
  return ms;
}

export function parseEventsCsv(text: string): LogEvent[] {
  const records = parseCsvRecords(text);
  if (records.length > 0) {
    for (const col of EVENT_COLUMNS) {
      if (!records[0].has(col)) throw new Error(`events: missing column "${col}"`);
    }
  }
  return records.map((r, n) => {
    const get = (k: string) => (r.get(k) ?? "").trim();
    const where = `events row ${n + 1}`;
    const eventId = get("event_id");
    if (eventId === "") throw new Error(`${where}: empty event_id`);
    const offsetText = get("source_clock_offset_ms");
    const offset = offsetText === "" ? 0 : Number(offsetText);
    if (!Number.isSafeInteger(offset)) throw new Error(`${where}: source_clock_offset_ms must be an integer`);
    parseUtc(get("event_time_utc"), `${where} event_time_utc`);
    parseUtc(get("received_time_utc"), `${where} received_time_utc`);
    return {
      event_id: eventId,
      event_time_utc: get("event_time_utc"),
      received_time_utc: get("received_time_utc"),
      source_clock_offset_ms: offset,
      actor: get("actor"),
      source_service: get("source_service"),
      target_service: get("target_service"),
      action: get("action"),
      role_before: get("role_before"),
      role_after: get("role_after"),
      outcome: get("outcome"),
      approval_id: get("approval_id"),
      session_id: get("session_id"),
      correlation_id: get("correlation_id"),
    };
  });
}

function str(o: Record<string, unknown>, k: string, where: string): string {
  const v = o[k];
  if (typeof v !== "string" || v === "") throw new Error(`${where}: "${k}" must be a non-empty string`);
  return v;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Returns approvals keyed by approval_id (first occurrence wins; duplicates rejected). */
export function parseApprovals(json: unknown): Map<string, Approval> {
  if (!isObject(json) || !Array.isArray(json.changes)) {
    throw new Error('approvals: expected an object with a "changes" array');
  }
  const out = new Map<string, Approval>();
  json.changes.forEach((c: unknown, n: number) => {
    const where = `approvals.changes[${n}]`;
    if (!isObject(c)) throw new Error(`${where}: expected an object`);
    const id = str(c, "approval_id", where);
    if (out.has(id)) throw new Error(`${where}: duplicate approval_id`);
    const op = str(c, "operation", where);
    const base = {
      approval_id: id,
      approved_by: str(c, "approved_by", where),
      subject: str(c, "subject", where),
      role: str(c, "role", where),
    };
    if (op === "grant_role") {
      if (!Array.isArray(c.scope) || !c.scope.every((s) => typeof s === "string")) {
        throw new Error(`${where}: "scope" must be an array of strings`);
      }
      const from = str(c, "valid_from_utc", where);
      const until = str(c, "valid_until_utc", where);
      if (parseUtc(until, `${where} valid_until_utc`) <= parseUtc(from, `${where} valid_from_utc`)) {
        throw new Error(`${where}: valid_until_utc must be after valid_from_utc`);
      }
      out.set(id, { ...base, operation: "grant_role", scope: [...c.scope], valid_from_utc: from, valid_until_utc: until });
    } else if (op === "revoke_role") {
      const at = str(c, "effective_at_utc", where);
      parseUtc(at, `${where} effective_at_utc`);
      out.set(id, { ...base, operation: "revoke_role", effective_at_utc: at });
    } else {
      throw new Error(`${where}: unsupported operation`);
    }
  });
  return out;
}

const edgeKey = (src: string, dst: string) => `${src}->${dst}`;
export { edgeKey };

function posInt(o: Record<string, unknown>, k: string, where: string): number {
  const v = o[k];
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) {
    throw new Error(`${where}: "${k}" must be a non-negative integer`);
  }
  return v;
}

function stringList(v: unknown, where: string): string[] {
  if (!Array.isArray(v) || !v.every((s) => typeof s === "string")) {
    throw new Error(`${where}: expected an array of strings`);
  }
  return v;
}

export function parsePolicy(json: unknown): Policy {
  if (!isObject(json)) throw new Error("policy: expected an object");
  if (!Array.isArray(json.roles)) throw new Error('policy: "roles" must be an array');
  const roles = new Map<string, Set<string>>();
  json.roles.forEach((r: unknown, n: number) => {
    const where = `policy.roles[${n}]`;
    if (!isObject(r)) throw new Error(`${where}: expected an object`);
    roles.set(str(r, "role", where), new Set(stringList(r.targets, `${where}.targets`)));
  });
  if (!Array.isArray(json.known_edges)) throw new Error('policy: "known_edges" must be an array');
  const knownEdges = new Set<string>();
  json.known_edges.forEach((e: unknown, n: number) => {
    const pair = stringList(e, `policy.known_edges[${n}]`);
    if (pair.length !== 2) throw new Error(`policy.known_edges[${n}]: expected [source, target]`);
    knownEdges.add(edgeKey(pair[0], pair[1]));
  });
  const outOfScopeActions = new Set<string>();
  const acts = json.out_of_scope_actions ?? [];
  if (!Array.isArray(acts)) throw new Error('policy: "out_of_scope_actions" must be an array');
  acts.forEach((a: unknown, n: number) => {
    const where = `policy.out_of_scope_actions[${n}]`;
    if (!isObject(a)) throw new Error(`${where}: expected an object`);
    outOfScopeActions.add(`${str(a, "target", where)}:${str(a, "action", where)}`);
  });
  if (!isObject(json.lateral)) throw new Error('policy: "lateral" must be an object');
  if (!isObject(json.clock)) throw new Error('policy: "clock" must be an object');
  const minDistinctEdges = posInt(json.lateral, "min_distinct_edges", "policy.lateral");
  if (minDistinctEdges < 2) throw new Error("policy.lateral: min_distinct_edges must be at least 2");
  return {
    roles,
    knownEdges,
    outOfScopeServices: new Set(stringList(json.out_of_scope_services ?? [], "policy.out_of_scope_services")),
    outOfScopeActions,
    lateral: { minDistinctEdges, windowMs: posInt(json.lateral, "window_ms", "policy.lateral") },
    reviewAfterRoleChangeWindowMs: posInt(json, "review_after_role_change_window_ms", "policy"),
    clock: {
      uncertaintyMs: posInt(json.clock, "uncertainty_ms", "policy.clock"),
      maxSupportedSkewMs: posInt(json.clock, "max_supported_skew_ms", "policy.clock"),
    },
  };
}

export const DEFAULT_POLICY_PATH = new URL("./policy.json", import.meta.url);

export function loadPolicy(path: string | URL = DEFAULT_POLICY_PATH): Policy {
  return parsePolicy(JSON.parse(readFileSync(path, "utf8")));
}
