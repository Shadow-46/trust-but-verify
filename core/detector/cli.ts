// Run the detector on files:
//   node core/detector/cli.ts --events events.csv --approvals approvals.json [--policy policy.json] [--text]
// Prints the JSON report (or a readable summary with --text) to stdout.

import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { detect } from "./detect.ts";
import { loadPolicy, parseApprovals, parseEventsCsv } from "./ingest.ts";
import type { DetectionReport } from "./types.ts";

export function formatText(report: DetectionReport): string {
  const lines: string[] = [];
  lines.push(`ALERTS (${report.alerts.length})`);
  for (const a of report.alerts) {
    lines.push(`  ${a.alert_id} [${a.severity}] ${a.rule} — ${a.actor}`);
    lines.push(`    MITRE ATT&CK: ${[...a.attack.tactics, ...a.attack.techniques].map((t) => `${t.id} ${t.name}`).join(", ")}`);
    lines.push(`    ${a.summary}`);
    lines.push(`    events: ${a.event_ids.join(", ")} | services: ${a.services.join(" -> ")}`);
    lines.push(`    limits: ${a.limits}`);
    lines.push(`    detected at ${a.detected_at_received_utc} (on ${a.detected_by_event_id})`);
  }
  lines.push("", "EVENTS (receipt order)");
  for (const c of report.events) {
    const flags = c.flags.length ? ` {${c.flags.join(",")}}` : "";
    lines.push(`  ${c.event_id.padEnd(9)} ${c.label.padEnd(27)} ${c.reason}${flags}`);
  }
  lines.push("", `TIMELINE (corrected event time): ${report.timeline.join(" ")}`);
  return lines.join("\n");
}

function main() {
  const { values } = parseArgs({
    options: {
      events: { type: "string" },
      approvals: { type: "string" },
      policy: { type: "string" },
      text: { type: "boolean", default: false },
    },
  });
  if (!values.events || !values.approvals) {
    process.stderr.write("usage: node core/detector/cli.ts --events <csv> --approvals <json> [--policy <json>] [--text]\n");
    process.exit(2);
  }
  const events = parseEventsCsv(readFileSync(values.events, "utf8"));
  const approvals = parseApprovals(JSON.parse(readFileSync(values.approvals, "utf8")));
  const policy = values.policy ? loadPolicy(values.policy) : loadPolicy();
  const report = detect(events, approvals, policy);
  process.stdout.write(values.text ? formatText(report) + "\n" : JSON.stringify(report, null, 2) + "\n");
}

if (import.meta.main) {
  try {
    main();
  } catch (err) {
    process.stderr.write(`detector: ${(err as Error).message}\n`);
    process.exit(1);
  }
}
