import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, test } from "node:test";
import { parseCsv } from "../core/detector/csv.ts";
import { detect } from "../core/detector/detect.ts";
import { loadPolicy, parseApprovals, parseEventsCsv, parsePolicy } from "../core/detector/ingest.ts";
import type { Approval, LogEvent } from "../core/detector/types.ts";

const policy = loadPolicy();

// ---- practice data (read from the sibling toolkit; never copied into this repo) ----
const toolkit = resolve(process.env.TRACK4_TOOLKIT_DIR ?? join(import.meta.dirname, "..", "..", "Track-4-Toolkit"));
const practice = join(toolkit, "practice");
const havePractice = existsSync(join(practice, "events.csv"));

describe("practice data (toolkit evt-001..022)", { skip: havePractice ? false : `toolkit not found at ${toolkit} (set TRACK4_TOOLKIT_DIR)` }, () => {
  const load = () => {
    const events = parseEventsCsv(readFileSync(join(practice, "events.csv"), "utf8"));
    const approvals = parseApprovals(JSON.parse(readFileSync(join(practice, "approvals.json"), "utf8")));
    return { events, report: detect(events, approvals, policy) };
  };

  test("reproduces every public label", () => {
    const { report } = load();
    // Labels are loaded only here, for comparison — never by the detector.
    const expected = new Map(
      parseCsv(readFileSync(join(practice, "labels.csv"), "utf8")).slice(1).map((r) => [r[0], r[1]] as const),
    );
    assert.equal(report.events.length, expected.size);
    const mismatches = report.events
      .filter((c) => expected.get(c.event_id) !== c.label)
      .map((c) => `${c.event_id}: got ${c.label}, expected ${expected.get(c.event_id)}`);
    assert.deepEqual(mismatches, []);
  });

  test("raises exactly the two documented alerts with supporting evidence", () => {
    const { report } = load();
    assert.equal(report.alerts.length, 2);
    const [role, lateral] = report.alerts;
    assert.equal(role.rule, "unexpected_role_change");
    assert.equal(role.actor, "user-blair");
    assert.deepEqual(role.event_ids, ["evt-008", "evt-009"]);
    assert.equal(lateral.rule, "lateral_movement_candidate");
    assert.deepEqual(lateral.event_ids, ["evt-010", "evt-011", "evt-012"]);
    assert.deepEqual(lateral.services, ["reports", "billing", "archive", "identity"]);
    assert.equal(lateral.severity, "medium"); // all denied: candidate, not compromise
    assert.match(lateral.limits, /not successful access/);
    assert.equal(lateral.detected_at_received_utc, "2026-01-15T09:04:02.100Z");
  });

  test("keeps receipt order and raw timestamps, orders the timeline by corrected time", () => {
    const { events, report } = load();
    assert.deepEqual(report.events.map((c) => c.event_id), events.map((e) => e.event_id));
    const i13 = report.timeline.indexOf("evt-013");
    assert.ok(i13 < report.timeline.indexOf("evt-014"));
    const e15 = report.events.find((c) => c.event_id === "evt-015")!;
    assert.equal(e15.time.corrected_event_utc, "2026-01-15T09:06:01.000Z");
    assert.equal(e15.time.collector_delay_ms, 200);
    assert.equal(events.find((e) => e.event_id === "evt-015")!.event_time_utc, "2026-01-15T09:06:03.000Z");
  });
});

// ---- synthetic unit cases ------------------------------------------------------------
let seq = 0;
function ev(p: Partial<LogEvent>): LogEvent {
  seq++;
  const t = p.event_time_utc ?? `2026-02-01T10:00:${String(seq % 60).padStart(2, "0")}.000Z`;
  return {
    event_id: `e-${seq}`,
    event_time_utc: t,
    received_time_utc: p.received_time_utc ?? t.replace(/\.000Z$/, ".100Z"),
    source_clock_offset_ms: 0,
    actor: "user-x",
    source_service: "portal",
    target_service: "catalog",
    action: "read",
    role_before: "viewer",
    role_after: "viewer",
    outcome: "allow",
    approval_id: "",
    session_id: "s-1",
    correlation_id: "f-1",
    ...p,
  };
}
const at = (s: string) => `2026-02-01T10:${s}Z`;
const none = new Map<string, Approval>();
const labelOf = (r: ReturnType<typeof detect>, id: string) => r.events.find((c) => c.event_id === id)!.label;

describe("role changes (goal 6)", () => {
  const approvals = parseApprovals({
    changes: [{
      approval_id: "chg-1", approved_by: "user-admin", subject: "user-x", operation: "grant_role",
      role: "report-reader", scope: ["reports"], valid_from_utc: at("00:00.000"), valid_until_utc: at("05:00.000"),
    }],
  });
  const change = (t: string, extra: Partial<LogEvent> = {}) =>
    ev({ event_time_utc: at(t), action: "role_change", role_after: "report-reader", source_service: "admin-console", target_service: "identity", ...extra });

  test("matching subject, role and time -> approved", () => {
    const e = change("01:00.000");
    assert.equal(labelOf(detect([e], approvals, policy), e.event_id), "approved_change");
  });

  test("valid_until is exclusive", () => {
    const e = change("05:00.000");
    const r = detect([e], approvals, policy);
    assert.equal(labelOf(r, e.event_id), "unexpected_role_change");
    assert.equal(r.alerts[0].rule, "unexpected_role_change");
  });

  test("citing the wrong approval is not authorization", () => {
    const e = change("01:00.000", { approval_id: "chg-999" });
    assert.equal(labelOf(detect([e], approvals, policy), e.event_id), "unexpected_role_change");
  });

  test("allowed activity after an unexpected change in the same session needs review; other sessions do not", () => {
    const c = change("01:00.000", { role_after: "operator" });
    const same = ev({ event_time_utc: at("01:01.000"), role_before: "operator", role_after: "operator" });
    const other = ev({ event_time_utc: at("01:02.000"), session_id: "s-2" });
    const r = detect([c, same, other], approvals, policy);
    assert.equal(labelOf(r, same.event_id), "review_after_role_change");
    assert.equal(labelOf(r, other.event_id), "routine");
    assert.deepEqual(r.alerts[0].event_ids, [c.event_id, same.event_id]);
  });

  test("admin action without a matching approval raises an alert", () => {
    const e = ev({ actor: "user-admin", action: "approve_role_change", approval_id: "chg-1", role_before: "operator", role_after: "operator", source_service: "admin-console", target_service: "identity" });
    const wrongActor = ev({ actor: "user-mallory", action: "approve_role_change", approval_id: "chg-1", role_before: "operator", role_after: "operator", source_service: "admin-console", target_service: "identity" });
    const r = detect([e, wrongActor], approvals, policy);
    assert.equal(labelOf(r, e.event_id), "approved_change");
    assert.equal(labelOf(r, wrongActor.event_id), "unapproved_admin_action");
  });

  test("reports access outside the approval window is flagged", () => {
    const e = ev({ event_time_utc: at("06:00.000"), target_service: "reports", role_before: "report-reader", role_after: "report-reader" });
    const r = detect([e], approvals, policy);
    assert.equal(labelOf(r, e.event_id), "access_outside_approval");
  });
});

describe("lateral movement (goal 7)", () => {
  const hop = (t: string, src: string, dst: string, extra: Partial<LogEvent> = {}) =>
    ev({ event_time_utc: at(t), actor: "svc-a", source_service: src, target_service: dst, outcome: "deny", session_id: "s-w", correlation_id: "f-w", ...extra });

  test("two distinct unexpected edges in one session within the window -> candidate", () => {
    const a = hop("00:00.000", "reports", "billing");
    const b = hop("02:00.000", "billing", "archive");
    const r = detect([a, b], none, policy);
    assert.equal(labelOf(r, a.event_id), "lateral_movement_candidate");
    assert.equal(r.alerts[0].severity, "medium");
  });

  test("edges further apart than the window are separate isolated denials", () => {
    const a = hop("00:00.000", "reports", "billing");
    const b = hop("06:00.000", "billing", "archive");
    const r = detect([a, b], none, policy);
    assert.equal(labelOf(r, a.event_id), "isolated_denial");
    assert.equal(labelOf(r, b.event_id), "isolated_denial");
    assert.equal(r.alerts.length, 0);
  });

  test("the same edge repeated is not movement", () => {
    const r = detect([hop("00:00.000", "reports", "billing"), hop("00:10.000", "reports", "billing")], none, policy);
    assert.equal(r.alerts.length, 0);
  });

  test("different sessions and flows are not grouped", () => {
    const a = hop("00:00.000", "reports", "billing");
    const b = hop("00:10.000", "billing", "archive", { session_id: "s-other", correlation_id: "f-other" });
    assert.equal(detect([a, b], none, policy).alerts.length, 0);
  });

  test("grouping by correlation ID alone works across sessions", () => {
    const a = hop("00:00.000", "reports", "billing");
    const b = hop("00:10.000", "billing", "archive", { session_id: "s-other" });
    assert.equal(detect([a, b], none, policy).alerts.length, 1);
  });

  test("an allowed hop raises severity to high", () => {
    const r = detect([hop("00:00.000", "reports", "billing"), hop("00:10.000", "billing", "archive", { outcome: "allow" })], none, policy);
    assert.equal(r.alerts[0].severity, "high");
    assert.match(r.alerts[0].summary, /ALLOWED/);
  });
});

describe("clocks and ordering (goal 8)", () => {
  test("neighbours in a session inside 2 x uncertainty are ambiguous, not guessed", () => {
    const a = ev({ event_time_utc: at("00:00.000") });
    const b = ev({ event_time_utc: at("00:00.400") });
    const r = detect([a, b], none, policy);
    for (const c of r.events) assert.ok(c.flags.includes("ambiguous_order"), c.event_id);
  });

  test("small reorder within uncertainty is ambiguous, larger reorder is delayed delivery", () => {
    const late = ev({ event_time_utc: at("00:05.000"), session_id: "s-a" });
    const close = ev({ event_time_utc: at("00:04.700"), received_time_utc: at("00:06.000"), session_id: "s-b" });
    const far = ev({ event_time_utc: at("00:01.000"), received_time_utc: at("00:07.000"), session_id: "s-c" });
    const r = detect([late, close, far], none, policy);
    assert.ok(r.events[1].flags.includes("ambiguous_order"));
    assert.equal(r.events[1].label, "routine");
    assert.equal(r.events[2].label, "routine_delayed_delivery");
  });

  test("offset beyond the supported skew is flagged unsupported", () => {
    const e = ev({ source_clock_offset_ms: 10 * 60_000 });
    const c = detect([e], none, policy).events[0];
    assert.ok(c.flags.includes("unsupported_skew"));
    assert.ok(c.flags.includes("ambiguous_order"));
    assert.match(c.reason, /unreliable/);
  });

  test("duplicate event IDs keep the first record only", () => {
    const a = ev({});
    const r = detect([a, { ...a }], none, policy);
    assert.equal(r.events[1].label, "duplicate_event");
    assert.deepEqual(r.timeline, [a.event_id]);
  });
});

describe("input handling", () => {
  test("CSV quoting, escaped quotes, CRLF and BOM", () => {
    assert.deepEqual(parseCsv('﻿a,b\r\n"x,1","say ""hi"""\r\n'), [["a", "b"], ["x,1", 'say "hi"']]);
  });

  test("rejects malformed events and approvals", () => {
    const header = "event_id,event_time_utc,received_time_utc,source_clock_offset_ms,actor,source_service,target_service,action,role_before,role_after,outcome,approval_id,session_id,correlation_id";
    assert.throws(() => parseEventsCsv(`${header}\nx,not-a-time,2026-01-01T00:00:00Z,0,a,b,c,d,e,f,g,,s,c`), /timestamp/);
    assert.throws(() => parseEventsCsv(`${header}\nx,2026-01-01T00:00:00Z,2026-01-01T00:00:00Z,1.5,a,b,c,d,e,f,g,,s,c`), /integer/);
    assert.throws(() => parseEventsCsv("event_id,actor\nx,y"), /missing column/);
    assert.throws(() => parseApprovals({ changes: [{ approval_id: "a", operation: "delete_everything" }] }));
    assert.throws(() => parsePolicy({ roles: [], known_edges: [], lateral: { min_distinct_edges: 1, window_ms: 1 }, clock: {} }), /at least 2/);
  });

  test("prototype-like IDs are treated as plain data", () => {
    const a = ev({ actor: "__proto__", session_id: "constructor", source_service: "reports", target_service: "billing", outcome: "deny" });
    const b = ev({ actor: "__proto__", session_id: "constructor", source_service: "billing", target_service: "archive", outcome: "deny" });
    const r = detect([a, b], none, policy);
    assert.equal(r.alerts[0].actor, "__proto__");
    assert.equal(({} as Record<string, unknown>).polluted, undefined);
  });
});
