import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

/**
 * Where persistent state lives. The local checker sets TRACK4_STATE_DIR; the
 * judging container has a read-only root, so fall back to the OS temp dir.
 */
export function stateDir(): string {
  const fromEnv = process.env.TRACK4_STATE_DIR;
  return resolve(fromEnv && fromEnv.length > 0 ? fromEnv : join(tmpdir(), "trust-but-verify"));
}

export type StatePaths = {
  root: string;
  state: string;
  audit: string;
  keysDir: string;
  masterKey: string;
  auditKey: string;
  auditPub: string;
  auditHead: string;
};

export function statePaths(root: string = stateDir()): StatePaths {
  const keysDir = join(root, "keys");
  return {
    root,
    state: join(root, "state.json"),
    audit: join(root, "audit.jsonl"),
    keysDir,
    masterKey: join(keysDir, "master.key"),
    auditKey: join(keysDir, "audit.key"),
    auditPub: join(keysDir, "audit.pub"),
    auditHead: join(root, "audit.head.json"),
  };
}
