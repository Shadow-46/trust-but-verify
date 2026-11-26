import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyAudit } from "./audit/log.ts";
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
    case "rotate":
      return { code: 0, out: rotateStoredDataKey(paths) };
  }
  return { code: 2, out: { error: "usage: ops verify-log | backup <file> | restore <file> | rotate" } };
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  try {
    const { code, out } = runOps(process.argv.slice(2));
    process.stdout.write(JSON.stringify(out) + "\n");
    process.exitCode = code;
  } catch (err) {
    process.stdout.write(JSON.stringify({ error: (err as { code?: string }).code ?? "failed" }) + "\n");
    process.exitCode = 1;
  }
}
