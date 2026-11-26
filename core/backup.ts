import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { appendAudit } from "./audit/log.ts";
import { signBytes, verifyBytes } from "./crypto/sign.ts";
import { deriveKeys, loadMasterKey } from "./keys/keystore.ts";
import { loadState, saveState } from "./state.ts";
import { atomicWriteFile, readTextIfExists, withLock } from "./store/fsx.ts";
import { statePaths } from "./store/paths.ts";
import type { StatePaths } from "./store/paths.ts";
import { openContext } from "./vault.ts";
import { RequestError } from "./errors.ts";

/**
 * Backups contain the authenticated state (bodies already AES-GCM encrypted)
 * and the signed audit log — never the master key. A backup carries a SHA-256
 * digest and an ML-DSA-65 signature; restore verifies both, then verifies the
 * state MAC with the live master key, before anything live is touched.
 */

type BackupFile = { format: 1; payload: string; sha256: string; signature: string };
type Payload = { created_at: string; state: string; audit: string };

export type BackupResult = { file: string; sha256: string; created_at: string };
export type RestoreResult =
  | { ok: true; restored_version: number; carried_revocations: number }
  | { ok: false; reason: "unreadable" | "digest_mismatch" | "bad_signature" | "state_invalid" };

const sha256 = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");

export function createBackup(paths: StatePaths, file: string): BackupResult {
  return withLock(paths.root, () => {
    const state = readTextIfExists(paths.state);
    const key = readTextIfExists(paths.auditKey);
    if (!state || !key) throw new RequestError("not_initialized");
    const created_at = new Date().toISOString();
    const payload = JSON.stringify({ created_at, state, audit: readTextIfExists(paths.audit) ?? "" } satisfies Payload);
    const digest = sha256(payload);
    const signature = signBytes(Buffer.from(key, "base64"), Buffer.from(payload, "utf8")).toString("base64");
    atomicWriteFile(file, JSON.stringify({ format: 1, payload, sha256: digest, signature } satisfies BackupFile));
    return { file, sha256: digest, created_at };
  });
}

/**
 * Restore only verified key material and state. Revocations present in the live
 * state are carried into the restored state, so restoring an older backup can
 * never re-enable a revoked identity.
 */
export function restoreBackup(paths: StatePaths, file: string): RestoreResult {
  return withLock(paths.root, () => {
    let backup: BackupFile;
    try {
      backup = JSON.parse(readTextIfExists(file) ?? "") as BackupFile;
      if (typeof backup.payload !== "string") throw new Error("shape");
    } catch {
      return { ok: false, reason: "unreadable" };
    }
    if (sha256(backup.payload) !== backup.sha256) return { ok: false, reason: "digest_mismatch" };
    const pub = readTextIfExists(paths.auditPub);
    if (!pub || !verifyBytes(Buffer.from(pub, "base64"), Buffer.from(backup.payload, "utf8"), Buffer.from(backup.signature ?? "", "base64"))) {
      return { ok: false, reason: "bad_signature" };
    }
    const payload = JSON.parse(backup.payload) as Payload;

    // Authenticate the backed-up state with the live master key in a scratch directory.
    const scratch = join(paths.root, `.restore-${randomBytes(6).toString("hex")}`);
    mkdirSync(scratch, { mode: 0o700 });
    try {
      const tmp = statePaths(scratch);
      atomicWriteFile(tmp.state, payload.state);
      atomicWriteFile(tmp.audit, payload.audit);
      atomicWriteFile(tmp.auditPub, pub); // the key that just verified the backup signature
      let restored;
      let keys;
      try {
        const body = JSON.parse(JSON.parse(payload.state).body) as { salt: string };
        const master = loadMasterKey(paths);
        keys = deriveKeys(master, Buffer.from(body.salt, "base64"));
        master.fill(0);
        restored = loadState(tmp, keys.stateMac, { verifiedSnapshot: true });
      } catch {
        return { ok: false, reason: "state_invalid" };
      }

      let carried = 0;
      try {
        for (const actor of openContext(paths).state.revoked) {
          if (!restored.revoked.has(actor)) carried++;
          restored.revoked.add(actor);
        }
      } catch {
        // Live state unreadable (that may be why we restore): nothing to carry over.
      }

      atomicWriteFile(paths.audit, payload.audit);
      rmSync(paths.auditHead, { force: true }); // the restored log defines a new head
      saveState(paths, keys.stateMac, restored);
      appendAudit(paths, {
        type: "backup_restored",
        request_id: null,
        actor: null,
        asset: null,
        decision: null,
        reason: `carried_revocations=${carried}`,
        state_version: restored.version,
      });
      return { ok: true, restored_version: restored.version, carried_revocations: carried };
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });
}
