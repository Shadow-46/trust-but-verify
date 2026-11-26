import { open as openSealed, seal } from "../crypto/aead.ts";
import { appendAudit } from "../audit/log.ts";
import { saveState } from "../state.ts";
import { withLock } from "../store/fsx.ts";
import type { StatePaths } from "../store/paths.ts";
import { assetAad, dataKey, openContext } from "../vault.ts";
import { newDataKey, wrapDataKey } from "./keystore.ts";

export type RotationResult = { from: number; to: number; reencrypted: number };

/**
 * Rotate the data key for stored (at-rest) assets: create version n+1, re-encrypt
 * every asset under it, and mark version n retired. The new state is written in
 * one atomic replace, so readers see either the complete old keyring and
 * ciphertexts or the complete new ones — never a mix. Revocations and ownership
 * are carried over unchanged.
 */
export function rotateStoredDataKey(paths: StatePaths): RotationResult {
  return withLock(paths.root, () => {
    const ctx = openContext(paths);
    const { state } = ctx;
    const from = state.activeKeyVersion;
    const to = Math.max(...state.keys.map((k) => k.version)) + 1;
    const newKey = newDataKey(state.salt, to);
    let reencrypted = 0;
    try {
      for (const [asset, record] of state.assets) {
        const oldKey = dataKey(ctx, record.version);
        try {
          const body = openSealed(oldKey, record.sealed, assetAad(state.setupId, asset, record.version), "asset");
          state.assets.set(asset, { version: to, sealed: seal(newKey, body, assetAad(state.setupId, asset, to)) });
          body.fill(0);
          reencrypted++;
        } finally {
          oldKey.fill(0);
        }
      }
      state.keys = [
        ...state.keys.map((k) => (k.version === from ? { ...k, status: "retired" as const } : k)),
        wrapDataKey(ctx.keys.kek, state.setupId, to, newKey),
      ];
      state.activeKeyVersion = to;
    } finally {
      newKey.fill(0);
    }
    saveState(paths, ctx.keys.stateMac, state);
    appendAudit(paths, {
      type: "key_rotation",
      request_id: null,
      actor: null,
      asset: null,
      decision: null,
      reason: `v${from}->v${to}`,
    });
    return { from, to, reencrypted };
  });
}
