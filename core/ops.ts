import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readAudit, verifyAudit } from "./audit/log.ts";
import { detect } from "./detector/detect.ts";
import { loadPolicy, parseApprovals, parseEventsCsv } from "./detector/ingest.ts";
import { generate } from "./detector/synth.ts";
import { openContext } from "./vault.ts";
import { securityAlerts } from "./defense/guard.ts";
import { listAttacks, runAttack } from "./demo/attacks.ts";
import { messagingDemo } from "./demo/messagingDemo.ts";
import { netClusterBench, netMessagingDemo } from "./demo/network.ts";
import { labCatalog, labRuns, labStart, labStep } from "./demo/liveLab.ts";
import { clusterEnrol, clusterInit, clusterRevoke, clusterStatus } from "./demo/liveCluster.ts";
import { createBackup, restoreBackup } from "./backup.ts";
import { rotateStoredDataKey } from "./keys/rotation.ts";
import { statePaths } from "./store/paths.ts";

/**
 * Operator commands (JSON output, never secrets):
 *   npm run ops -- verify-log        verify audit chain + ML-DSA signatures
 *   npm run ops -- backup <file>     signed, digested backup of state + audit log
 *   npm run ops -- restore <file>    verify, then restore (revocations are kept)
 *   npm run ops -- rotate            rotate the stored data key
 * State directory: TRACK4_STATE_DIR, else <os temp>/trust-but-verify.
 */
export function runOps(argv: string[]): { code: number; out: unknown } {
  const [cmd, arg] = argv;
  const paths = statePaths();
  switch (cmd) {
    case "verify-log": {
      const v = verifyAudit(paths);
      return { code: v.ok ? 0 : 1, out: v };
    }
    case "backup":
      if (!arg) break;
      return { code: 0, out: createBackup(paths, resolve(arg)) };
    case "restore": {
      if (!arg) break;
      const r = restoreBackup(paths, resolve(arg));
      return { code: r.ok ? 0 : 1, out: r };
    }
    case "audit-log":
      // Metadata only (no bodies, no keys): what the operator sees.
      return {
        code: 0,
        out: readAudit(paths)
          .slice(-60)
          .map(({ seq, ts, type, request_id, actor, asset, decision, reason, hash }) => ({ seq, ts, type, request_id, actor, asset, decision, reason, hash: hash.slice(0, 12) })),
      };
    case "state-summary": {
      const { state } = openContext(paths);
      return {
        code: 0,
        out: {
          version: state.version,
          active_key: state.activeKeyVersion,
          keys: state.keys.map((k) => ({ version: k.version, status: k.status, created_at: k.created_at })),
          owners: [...state.owners].map(([asset, owner]) => ({ asset, owner })),
          revoked: [...state.revoked],
          disabled: [...state.disabled],
        },
      };
    }
    case "detect-sample": {
      const data = generate({ seed: Number(arg ?? 1), users: 8, incidents: 4, hard: true });
      const report = detect(parseEventsCsv(data.csv), parseApprovals(data.approvals), loadPolicy());
      return {
        code: 0,
        out: {
          events: data.events,
          incidents: data.incidents.map((i) => ({ id: i.id, kind: i.kind, events: i.event_ids })),
          alerts: report.alerts.map((a) => ({ id: a.alert_id, rule: a.rule, attack: a.attack, severity: a.severity, actor: a.actor, summary: a.summary, events: a.event_ids, services: a.services, limits: a.limits, detected_at: a.detected_at_received_utc })),
        },
      };
    }
    case "cluster-init":
      if (!arg) break;
      return { code: 0, out: clusterInit(resolve(arg)) };
    case "cluster-status":
      if (!arg) break;
      return { code: 0, out: clusterStatus(resolve(arg)) };
    case "cluster-revoke":
      if (!arg) break;
      return { code: 0, out: clusterRevoke(resolve(arg)) };
    case "cluster-enrol":
      if (!arg) break;
      return { code: 0, out: clusterEnrol(resolve(arg)) };
    case "messaging":
      return { code: 0, out: messagingDemo(arg) };
    case "attacks":
      return { code: 0, out: listAttacks() };
    case "attack": {
      const results = runAttack(arg ?? "all");
      return { code: results.every((r) => r.blocked) ? 0 : 1, out: results };
    }
    case "alerts":
      return { code: 0, out: securityAlerts(paths) };
    case "lab-catalog":
      return { code: 0, out: labCatalog() };
    case "lab-start":
      if (!arg) break;
      return { code: 0, out: labStart(arg) };
    case "lab-step":
      if (!arg) break;
      return { code: 0, out: labStep(arg) };
    case "lab-runs":
      return { code: 0, out: labRuns() };
    case "monitor": {
      // One read-only snapshot for the Live Monitor (each part fails independently, never secrets).
      const part = <T>(fn: () => T) => {
        try {
          return fn();
        } catch (err) {
          return { error: (err as { code?: string }).code ?? "unavailable" };
        }
      };
      return {
        code: 0,
        out: {
          at: Date.now(),
          state: part(() => runOps(["state-summary"]).out),
          log: part(() => runOps(["audit-log"]).out),
          alerts: part(() => securityAlerts(paths).slice(-20)),
          cluster: arg ? part(() => clusterStatus(resolve(arg))) : null,
        },
      };
    }
    case "rotate":
      return { code: 0, out: rotateStoredDataKey(paths) };
  }
  return { code: 2, out: { error: "usage: ops verify-log | backup <file> | restore <file> | rotate" } };
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  try {
    const argv = process.argv.slice(2);
    // Network demos are asynchronous (real processes over loopback HTTP/TCP).
    const { code, out } =
      argv[0] === "net-cluster-bench"
        ? { code: 0, out: await netClusterBench() }
        : argv[0] === "net-messaging"
          ? await netMessagingDemo(argv[1]).then((r) => ({ code: r.attacks.every((a) => a.blocked) ? 0 : 1, out: r }))
          : runOps(argv);
    process.stdout.write(JSON.stringify(out) + "\n");
    process.exitCode = code;
  } catch (err) {
    process.stdout.write(JSON.stringify({ error: (err as { code?: string }).code ?? "failed" }) + "\n");
    process.exitCode = 1;
  }
}
