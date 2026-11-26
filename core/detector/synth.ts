/**
 * Seeded synthetic access-log generator with ground truth (T5).
 *
 * Produces events in the same CSV format as the toolkit's practice events.csv,
 * approvals in the practice approvals.json format, and — separately — the ground
 * truth. The detector only ever receives the CSV and approvals; truth is used by
 * the evaluator alone. Traffic follows the documented environment (roles, known
 * service edges) and adds realistic noise: delayed delivery, source clock offsets,
 * receipt order different from event order, approved administration and isolated
 * denials. Injected incidents: unapproved privilege gain with follow-up access,
 * and lateral-movement chains through out-of-scope services.
 */

export type IncidentKind = "unapproved_role_change" | "lateral_movement" | "borrowed_approval" | "successful_lateral";
export type Incident = { id: string; kind: IncidentKind; event_ids: string[] };
export type SynthResult = {
  csv: string;
  approvals: { synthetic: true; changes: Record<string, unknown>[] };
  incidents: Incident[];
  /** event_id -> incident id for malicious events; benign events are absent. */
  truth: Map<string, string>;
  events: number;
};
/** `hard` adds borrowed approvals, successful (allowed) lateral hops, and approvals delivered after the change they authorize. */
export type SynthOptions = { seed?: number; users?: number; incidents?: number; start?: string; hard?: boolean };

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

type Row = {
  t: number; // true event time (ms)
  offset: number; // source clock offset (ms): recorded event time = t + offset
  delay: number; // collector delay (ms): received time = t + delay
  actor: string;
  src: string;
  dst: string;
  action: string;
  before: string;
  after: string;
  outcome: string;
  approval: string;
  session: string;
  flow: string;
  incident: string | null;
};

const iso = (ms: number) => new Date(ms).toISOString();

export function generate(opts: SynthOptions = {}): SynthResult {
  const rnd = mulberry32(opts.seed ?? 1);
  const int = (lo: number, hi: number) => lo + Math.floor(rnd() * (hi - lo + 1));
  const pick = <T>(xs: T[]) => xs[int(0, xs.length - 1)];
  const users = opts.users ?? 40;
  const incidentCount = opts.incidents ?? 12;
  const start = Date.parse(opts.start ?? "2026-02-01T08:00:00Z");
  const rows: Row[] = [];
  const changes: Record<string, unknown>[] = [];
  let flowN = 0;

  const noise = () => {
    const delay = rnd() < 0.04 ? int(2_000, 6_000) : int(50, 400); // occasional delayed delivery
    const offset = rnd() < 0.05 ? pick([-1, 1]) * int(500, 3_000) : 0; // some sources drift
    return { delay, offset };
  };
  const add = (r: Omit<Row, "delay" | "offset">, extraDelay = 0) => {
    const n = noise();
    rows.push({ ...r, ...n, delay: n.delay + extraDelay });
  };
  const hard = opts.hard === true;

  // Routine user sessions.
  for (let u = 0; u < users; u++) {
    const user = `user-${String(u).padStart(3, "0")}`;
    for (let s = int(1, 3); s > 0; s--) {
      let t = start + int(0, 8 * 3_600_000);
      const session = `sess-${user}-${s}`;
      const flow = `flow-${++flowN}`;
      add({ t, actor: user, src: "portal", dst: "identity", action: "sign_in", before: "viewer", after: "viewer", outcome: "success", approval: "", session, flow, incident: null });
      for (let i = int(2, 8); i > 0; i--) {
        t += int(5_000, 120_000);
        add({ t, actor: user, src: "portal", dst: "catalog", action: "read", before: "viewer", after: "viewer", outcome: "allow", approval: "", session, flow, incident: null });
      }
      if (rnd() < 0.1) {
        t += int(5_000, 60_000); // isolated denial: tried reports without the role
        add({ t, actor: user, src: "portal", dst: "reports", action: "read", before: "viewer", after: "viewer", outcome: "deny", approval: "", session, flow, incident: null });
      }
    }
    // Approved administration: approved by an operator, applied, then used within validity.
    if (rnd() < 0.15) {
      const id = `change-${u}`;
      const from = start + int(0, 6 * 3_600_000);
      const until = from + 3_600_000;
      changes.push({ approval_id: id, approved_by: "user-admin", subject: user, operation: "grant_role", role: "report-reader", scope: ["reports", "reports-node-a", "reports-node-b"], valid_from_utc: iso(from), valid_until_utc: iso(until) });
      const session = `sess-${user}-adm`;
      const flow = `flow-${++flowN}`;
      // Hard mode: the approval record is delivered late, after the role change it authorizes.
      add({ t: from + 1_000, actor: "user-admin", src: "admin-console", dst: "identity", action: "approve_role_change", before: "operator", after: "operator", outcome: "success", approval: id, session: "sess-admin", flow, incident: null }, hard ? 90_000 : 0);
      let t = from + int(5_000, 60_000);
      add({ t, actor: user, src: "admin-console", dst: "identity", action: "role_change", before: "viewer", after: "report-reader", outcome: "success", approval: id, session, flow, incident: null });
      for (let i = int(1, 4); i > 0; i--) {
        t += int(5_000, 300_000);
        if (t >= until) break;
        add({ t, actor: user, src: "portal", dst: pick(["reports", "reports-node-a", "reports-node-b"]), action: "read", before: "report-reader", after: "report-reader", outcome: "allow", approval: id, session, flow, incident: null });
      }
    }
  }
  // Routine service traffic on its known edge.
  for (let i = 0; i < users * 2; i++) {
    add({ t: start + int(0, 8 * 3_600_000), actor: "svc-report-worker", src: "reports", dst: "catalog", action: "read", before: "service-reader", after: "service-reader", outcome: "allow", approval: "", session: "sess-worker", flow: `flow-${++flowN}`, incident: null });
  }

  // Injected incidents.
  const incidents: { id: string; kind: IncidentKind }[] = [];
  for (let k = 0; k < incidentCount; k++) {
    const id = `inc-${k}`;
    const t0 = start + int(0, 8 * 3_600_000);
    const flow = `flow-${++flowN}`;
    const variant = hard ? k % 4 : k % 2;
    if (variant === 2) {
      // Borrowed approval: cites a real approval that belongs to another subject.
      const user = `user-${String(int(0, users - 1)).padStart(3, "0")}`;
      const other = changes.find((c) => c.subject !== user);
      const session = `sess-${user}-b${k}`;
      incidents.push({ id, kind: "borrowed_approval" });
      add({ t: t0, actor: user, src: "admin-console", dst: "identity", action: "role_change", before: "viewer", after: "report-reader", outcome: "success", approval: String(other?.approval_id ?? "change-none"), session, flow, incident: id });
      add({ t: t0 + int(1_000, 30_000), actor: user, src: "portal", dst: "reports", action: "read", before: "report-reader", after: "report-reader", outcome: "allow", approval: String(other?.approval_id ?? ""), session, flow, incident: id });
    } else if (variant === 3) {
      // Successful lateral movement: valid credentials, allowed hops into out-of-scope services.
      const session = `sess-worker-s${k}`;
      incidents.push({ id, kind: "successful_lateral" });
      let t = t0;
      for (const [src, dst] of [["reports", "billing"], ["billing", "archive"]]) {
        add({ t, actor: "svc-report-worker", src, dst, action: "read", before: "service-reader", after: "service-reader", outcome: "allow", approval: "", session, flow, incident: id });
        t += int(500, 20_000);
      }
    } else if (variant === 0) {
      const user = `user-${String(int(0, users - 1)).padStart(3, "0")}`;
      const session = `sess-${user}-x${k}`;
      incidents.push({ id, kind: "unapproved_role_change" });
      add({ t: t0, actor: user, src: "admin-console", dst: "identity", action: "role_change", before: "viewer", after: "operator", outcome: "success", approval: "", session, flow, incident: id });
      let t = t0;
      for (let i = int(1, 3); i > 0; i--) {
        t += int(1_000, 60_000);
        add({ t, actor: user, src: "portal", dst: "reports", action: "read", before: "operator", after: "operator", outcome: "allow", approval: "", session, flow, incident: id });
      }
    } else {
      const session = `sess-worker-x${k}`;
      incidents.push({ id, kind: "lateral_movement" });
      let t = t0;
      for (const [src, dst, action] of [["reports", "billing", "read"], ["billing", "archive", "read"], ["archive", "identity", "list_roles"]]) {
        add({ t, actor: "svc-report-worker", src, dst, action, before: "service-reader", after: "service-reader", outcome: "deny", approval: "", session, flow, incident: id });
        t += int(500, 20_000);
      }
    }
  }

  // Assign IDs in true event order, then emit in receipt order (as a collector would).
  rows.sort((a, b) => a.t - b.t);
  const ids = rows.map((_, i) => `evt-${String(i + 1).padStart(6, "0")}`);
  const truth = new Map<string, string>();
  const byIncident = new Map<string, string[]>();
  rows.forEach((r, i) => {
    if (r.incident) {
      truth.set(ids[i], r.incident);
      byIncident.set(r.incident, [...(byIncident.get(r.incident) ?? []), ids[i]]);
    }
  });
  const order = rows.map((r, i) => ({ r, id: ids[i], received: r.t + r.delay }));
  order.sort((a, b) => a.received - b.received || a.id.localeCompare(b.id));

  const header = "event_id,event_time_utc,received_time_utc,source_clock_offset_ms,actor,source_service,target_service,action,role_before,role_after,outcome,approval_id,session_id,correlation_id";
  const lines = order.map(({ r, id, received }) =>
    [id, iso(r.t + r.offset), iso(received), r.offset, r.actor, r.src, r.dst, r.action, r.before, r.after, r.outcome, r.approval, r.session, r.flow].join(","),
  );
  return {
    csv: `${header}\n${lines.join("\n")}\n`,
    approvals: { synthetic: true, changes },
    incidents: incidents.map((i) => ({ ...i, event_ids: byIncident.get(i.id) ?? [] })),
    truth,
    events: rows.length,
  };
}
