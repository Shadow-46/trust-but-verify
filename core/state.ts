import { createHmac, timingSafeEqual } from "node:crypto";
import type { Sealed } from "./crypto/aead.ts";
import type { WrappedDataKey } from "./keys/keystore.ts";
import { atomicWriteFile, readTextIfExists } from "./store/fsx.ts";
import type { StatePaths } from "./store/paths.ts";
import { IntegrityError, RequestError } from "./errors.ts";

export type AssetRecord = { version: number; sealed: Sealed };

/** In-memory state. External IDs only ever live in Map/Set keys, never object keys. */
export type State = {
  setupId: string;
  salt: Buffer;
  owners: Map<string, string>;
  disabled: Set<string>;
  revoked: Set<string>;
  activeKeyVersion: number;
  keys: WrappedDataKey[];
  assets: Map<string, AssetRecord>;
};

type StateBody = {
  format: 1;
  setup_id: string;
  salt: string;
  owners: [string, string][];
  disabled: string[];
  revoked: string[];
  keyring: { active: number; keys: WrappedDataKey[] };
  assets: [string, AssetRecord][];
};

type StateFile = { body: string; mac: string };

function mac(key: Buffer, body: string): Buffer {
  return createHmac("sha256", key).update(body, "utf8").digest();
}

/** Plaintext header fields needed before keys can be derived (salt), read without trusting them. */
export function readSalt(paths: StatePaths): Buffer {
  const file = readStateFile(paths);
  try {
    const body = JSON.parse(file.body) as Partial<StateBody>;
    if (typeof body.salt !== "string") throw new Error("no salt");
    return Buffer.from(body.salt, "base64");
  } catch {
    throw new IntegrityError("state");
  }
}

function readStateFile(paths: StatePaths): StateFile {
  const text = readTextIfExists(paths.state);
  if (text === undefined) throw new RequestError("not_initialized");
  try {
    const file = JSON.parse(text) as StateFile;
    if (typeof file.body !== "string" || typeof file.mac !== "string") throw new Error("shape");
    return file;
  } catch {
    throw new IntegrityError("state");
  }
}

/** Load and authenticate state; any tampering or corruption fails closed. */
export function loadState(paths: StatePaths, macKey: Buffer): State {
  const file = readStateFile(paths);
  const expected = mac(macKey, file.body);
  const given = Buffer.from(file.mac, "hex");
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
    throw new IntegrityError("state");
  }
  const b = JSON.parse(file.body) as StateBody;
  if (b.format !== 1) throw new IntegrityError("state");
  return {
    setupId: b.setup_id,
    salt: Buffer.from(b.salt, "base64"),
    owners: new Map(b.owners),
    disabled: new Set(b.disabled),
    revoked: new Set(b.revoked),
    activeKeyVersion: b.keyring.active,
    keys: b.keyring.keys,
    assets: new Map(b.assets),
  };
}

export function saveState(paths: StatePaths, macKey: Buffer, s: State): void {
  const body: StateBody = {
    format: 1,
    setup_id: s.setupId,
    salt: s.salt.toString("base64"),
    owners: [...s.owners],
    disabled: [...s.disabled],
    revoked: [...s.revoked],
    keyring: { active: s.activeKeyVersion, keys: s.keys },
    assets: [...s.assets],
  };
  const bodyJson = JSON.stringify(body);
  const file: StateFile = { body: bodyJson, mac: mac(macKey, bodyJson).toString("hex") };
  atomicWriteFile(paths.state, JSON.stringify(file));
}
