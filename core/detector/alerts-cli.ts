// Operator view of live security alerts (T13). JSON output, never secrets.
//   node dist/core/detector/alerts-cli.js           list alerts + verification
//   node dist/core/detector/alerts-cli.js verify    verification only
// State directory: TRACK4_STATE_DIR, else <os temp>/trust-but-verify.

import { statePaths } from "../store/paths.ts";
import { readAlerts, verifyAlerts } from "./live.ts";

export function alertsReport(cmd?: string): { code: number; out: unknown } {
  const paths = statePaths();
  const verification = verifyAlerts(paths);
  if (cmd === "verify") return { code: verification.ok ? 0 : 1, out: verification };
  let alerts: unknown[] = [];
  try {
    alerts = readAlerts(paths).map(({ prev, hash, sig, ...a }) => a);
  } catch {
    alerts = [];
  }
  return { code: verification.ok ? 0 : 1, out: { verification, alerts } };
}

if (import.meta.main) {
  const { code, out } = alertsReport(process.argv[2]);
  process.stdout.write(JSON.stringify(out, null, 2) + "\n");
  process.exitCode = code;
}
