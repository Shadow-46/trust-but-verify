import { aad, open as openSealed } from "./crypto/aead.ts";
import { deriveKeys, loadMasterKey, unwrapDataKey } from "./keys/keystore.ts";
import type { DerivedKeys } from "./keys/keystore.ts";
import { loadState, readSalt } from "./state.ts";
import type { State } from "./state.ts";
import type { StatePaths } from "./store/paths.ts";
import { IntegrityError } from "./errors.ts";

/** Authenticated state plus the keys derived for it. */
export type Context = { state: State; keys: DerivedKeys };

export function openContext(paths: StatePaths): Context {
  const master = loadMasterKey(paths);
  const keys = deriveKeys(master, readSalt(paths));
  master.fill(0);
  return { state: loadState(paths, keys.stateMac), keys };
}

/** Associated data binding a ciphertext to its setup, asset and key version. */
export function assetAad(setupId: string, asset: string, version: number): Buffer {
  return aad("tbv/asset/v1", setupId, asset, version);
}

/** Data key for `version`, unwrapped with the KEK (caller must zero it after use). */
export function dataKey(ctx: Context, version: number): Buffer {
  const record = ctx.state.keys.find((k) => k.version === version);
  if (!record) throw new IntegrityError("asset key version");
  return unwrapDataKey(ctx.keys.kek, ctx.state.setupId, record);
}

export function readBody(ctx: Context, asset: string): string {
  const record = ctx.state.assets.get(asset);
  if (!record) throw new IntegrityError("asset");
  const dek = dataKey(ctx, record.version);
  try {
    return openSealed(dek, record.sealed, assetAad(ctx.state.setupId, asset, record.version), "asset").toString("utf8");
  } finally {
    dek.fill(0);
  }
}
