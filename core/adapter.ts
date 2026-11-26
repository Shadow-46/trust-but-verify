import { createHmac, randomBytes } from "node:crypto";
import { rmSync } from "node:fs";
import { join } from "node:path";
import { seal } from "./crypto/aead.ts";
import { decodeBase64Strict } from "./crypto/encoding.ts";
import { encapsulate, importMlKem768PublicKey } from "./crypto/kem.ts";
import { generateSigningKeyPair } from "./crypto/sign.ts";
import { createMasterKey, deriveKeys, newDataKey, wrapDataKey } from "./keys/keystore.ts";
import { decide } from "./access/policy.ts";
import type { Decision } from "./access/policy.ts";
import { appendAudit, findDecision, readAudit } from "./audit/log.ts";
import { saveState } from "./state.ts";
import type { State } from "./state.ts";
import { assetAad, openContext, readBody } from "./vault.ts";
import { isQuarantined, observeDecision, observeFailure } from "./defense/guard.ts";
import type { Context } from "./vault.ts";
import { atomicWriteFile, withLock } from "./store/fsx.ts";
import { statePaths } from "./store/paths.ts";
import type { StatePaths } from "./store/paths.ts";
import { IntegrityError, RequestError } from "./errors.ts";

/**
 * Track 4 adapter contract v1: one JSON request in, one JSON response out.
 * Responses never contain key material, and denied requests never contain a body.
 */

type Json = Record<string, unknown>;
export type Reply = { status: 0 | 1; body: Json };

const MAX_ID = 256;
const MAX_CHALLENGE = 4096;
const MAX_KEY_MATERIAL = 64 * 1024;
const MAX_TOTAL_CONTENT = 16 * 1024 * 1024;
const MAX_ENTRIES = 10_000;

// ---------- input validation (fixed error codes; never echo input) ----------

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function field(req: Record<string, unknown>, name: string): unknown {
  return Object.hasOwn(req, name) ? req[name] : undefined;
}

function requireId(req: Record<string, unknown>, name: string): string {
  const v = field(req, name);
  if (typeof v !== "string" || v.length === 0 || v.length > MAX_ID) throw new RequestError(`invalid_${name}`);
  return v;
}

function stringMap(req: Record<string, unknown>, name: string, maxValue: number): Map<string, string> {
  const v = field(req, name);
  if (!isObject(v)) throw new RequestError(`invalid_${name}`);
  const entries = Object.entries(v);
  if (entries.length > MAX_ENTRIES) throw new RequestError(`invalid_${name}`);
  const out = new Map<string, string>();
  for (const [k, value] of entries) {
    if (k.length === 0 || k.length > MAX_ID || typeof value !== "string" || value.length > maxValue) {
      throw new RequestError(`invalid_${name}`);
    }
    out.set(k, value);
  }
  return out;
}

function stringList(req: Record<string, unknown>, name: string): Set<string> {
  const v = field(req, name);
  if (v === undefined || v === null) return new Set();
  if (!Array.isArray(v) || v.length > MAX_ENTRIES) throw new RequestError(`invalid_${name}`);
  const out = new Set<string>();
  for (const item of v) {
    if (typeof item !== "string" || item.length === 0 || item.length > MAX_ID) throw new RequestError(`invalid_${name}`);
    out.add(item);
  }
  return out;
}

// ---------- access ----------

/** Decide, decrypt on allow (fail closed on integrity errors), and durably record the decision. */
function authorizeAndRecord(
  paths: StatePaths,
  ctx: Context,
  actor: string,
  asset: string,
  requestId: string,
): { decision: Decision; body?: string } {
  const records = readAudit(paths);
  const first = findDecision(records, requestId);
  let decision = decide(ctx.state, actor, asset);
  // A reused request ID is honoured only as an idempotent retry of an earlier allow for the
  // same actor and asset. Anything else is refused, so a body can never be returned under a
  // request ID whose recorded decision is "deny".
  if (first && !(first.decision === "allow" && first.actor === actor && first.asset === asset)) {
    decision = { decision: "deny", reason: "request_id_reused" };
  }
  if (decision.decision === "allow" && isQuarantined(paths, actor)) decision = { decision: "deny", reason: "quarantined" };
  let body: string | undefined;
  if (decision.decision === "allow") {
    try {
      body = readBody(ctx, asset);
    } catch (err) {
      if (!(err instanceof IntegrityError)) throw err;
      decision = { decision: "deny", reason: "integrity_failure" };
    }
  }
  appendAudit(
    paths,
    {
      type: first ? "duplicate_request_id" : "access_decision",
      request_id: requestId,
      actor,
      asset,
      decision: decision.decision,
      reason: decision.reason,
      state_version: ctx.state.version,
    },
    records,
  );
  observeDecision(paths, actor, asset, decision.decision, decision.reason);
  return decision.decision === "allow" ? { decision, body } : { decision };
}

// ---------- operations ----------

function opSetup(req: Record<string, unknown>, paths: StatePaths): Json {
  const owners = stringMap(req, "owners", MAX_ID);
  for (const actor of owners.values()) if (actor.length === 0) throw new RequestError("invalid_owners");
  const contents = stringMap(req, "contents", MAX_TOTAL_CONTENT);
  let total = 0;
  for (const body of contents.values()) total += Buffer.byteLength(body, "utf8");
  if (total > MAX_TOTAL_CONTENT) throw new RequestError("invalid_contents");
  const disabled = stringList(req, "disabled");
  const keyMaterial = field(req, "key_material");
  if (keyMaterial !== undefined && (typeof keyMaterial !== "string" || keyMaterial.length > MAX_KEY_MATERIAL)) {
    throw new RequestError("invalid_key_material");
  }

  return withLock(paths.root, () => {
    // A new setup replaces all previous state, keys and audit history.
    rmSync(paths.state, { force: true });
    rmSync(paths.audit, { force: true });
    rmSync(join(paths.root, "defense.json"), { force: true });
    rmSync(paths.keysDir, { recursive: true, force: true });

    const master = createMasterKey(paths);
    const auditKeys = generateSigningKeyPair();
    atomicWriteFile(paths.auditKey, auditKeys.privateKey.toString("base64"));
    atomicWriteFile(paths.auditPub, auditKeys.publicKey.toString("base64"));
    const salt = randomBytes(32);
    const setupId = randomBytes(16).toString("hex");
    const keys = deriveKeys(master, salt);
    master.fill(0);
    const dek = newDataKey(salt, 1, keyMaterial as string | undefined);
    const state: State = {
      setupId,
      salt,
      owners,
      disabled,
      revoked: new Set(),
      activeKeyVersion: 1,
      keys: [wrapDataKey(keys.kek, setupId, 1, dek)],
      assets: new Map(),
      version: 0,
      auditSeq: 0,
      auditHash: "",
    };
    for (const [asset, body] of contents) {
      state.assets.set(asset, { version: 1, sealed: seal(dek, Buffer.from(body, "utf8"), assetAad(setupId, asset, 1)) });
    }
    dek.fill(0);
    saveState(paths, keys.stateMac, state);
    appendAudit(
      paths,
      { type: "setup", request_id: null, actor: null, asset: null, decision: null, reason: null, state_version: state.version },
      [],
    );
    return { ready: true };
  });
}

function opRead(req: Record<string, unknown>, paths: StatePaths): Json {
  const actor = requireId(req, "actor");
  const asset = requireId(req, "asset");
  const requestId = requireId(req, "request_id");
  return withLock(paths.root, () => {
    const result = authorizeAndRecord(paths, openContext(paths), actor, asset, requestId);
    return result.decision.decision === "allow" ? { decision: "allow", body: result.body } : { decision: "deny" };
  });
}

function opRevoke(req: Record<string, unknown>, paths: StatePaths): Json {
  const actor = requireId(req, "actor");
  return withLock(paths.root, () => {
    const ctx = openContext(paths);
    ctx.state.revoked.add(actor);
    saveState(paths, ctx.keys.stateMac, ctx.state); // persisted before acknowledging
    appendAudit(paths, {
      type: "revoke",
      request_id: null,
      actor,
      asset: null,
      decision: null,
      reason: "revoked",
      state_version: ctx.state.version,
    });
    return { revoked: true };
  });
}

function opAudit(req: Record<string, unknown>, paths: StatePaths): Json {
  const requestId = requireId(req, "request_id");
  return withLock(paths.root, () => {
    const found = findDecision(readAudit(paths), requestId);
    return found ? { request_id: found.request_id, decision: found.decision } : { request_id: requestId, found: false };
  });
}

function opProtectedRead(req: Record<string, unknown>, paths: StatePaths): Json {
  const actor = requireId(req, "actor");
  const asset = requireId(req, "asset");
  const challenge = field(req, "challenge");
  if (typeof challenge !== "string" || challenge.length === 0 || challenge.length > MAX_CHALLENGE) {
    throw new RequestError("invalid_challenge");
  }
  const publicKeyB64 = field(req, "public_key");
  if (typeof publicKeyB64 !== "string") throw new RequestError("invalid_public_key");
  // Validate the key before any decision is recorded, so a malformed request has no side effects.
  const publicKey = importMlKem768PublicKey(decodeBase64Strict(publicKeyB64, "invalid_public_key"));
  const suppliedId = field(req, "request_id");
  const requestId =
    typeof suppliedId === "string" && suppliedId.length > 0 && suppliedId.length <= MAX_ID
      ? suppliedId
      : `pr-${randomBytes(12).toString("hex")}`;

  return withLock(paths.root, () => {
    const result = authorizeAndRecord(paths, openContext(paths), actor, asset, requestId);
    if (result.decision.decision !== "allow" || result.body === undefined) return { decision: "deny" };
    const { ciphertext, sharedKey } = encapsulate(publicKey);
    try {
      const proof = createHmac("sha256", sharedKey)
        .update(Buffer.from(challenge + result.body, "utf8"))
        .digest("hex");
      return { decision: "allow", ciphertext: ciphertext.toString("base64"), proof };
    } finally {
      sharedKey.fill(0);
    }
  });
}

// ---------- entry ----------

function failure(code: string): Reply {
  return { status: 1, body: { error: code } };
}

export function handle(input: string, paths: StatePaths = statePaths()): Reply {
  let req: unknown;
  try {
    req = JSON.parse(input);
  } catch {
    observeFailure(paths, "invalid");
    return failure("invalid_json");
  }
  if (!isObject(req)) {
    observeFailure(paths, "invalid");
    return failure("invalid_request");
  }
  const op = field(req, "op");
  try {
    switch (op) {
      case "setup":
        return { status: 0, body: opSetup(req, paths) };
      case "read":
        return { status: 0, body: opRead(req, paths) };
      case "revoke":
        return { status: 0, body: opRevoke(req, paths) };
      case "audit":
        return { status: 0, body: opAudit(req, paths) };
      case "protected_read":
        return { status: 0, body: opProtectedRead(req, paths) };
      default:
        return failure("unsupported_operation");
    }
  } catch (err) {
    if (err instanceof RequestError) {
      if (err.code !== "not_initialized") observeFailure(paths, "invalid");
      return failure(err.code);
    }
    if (err instanceof IntegrityError) {
      observeFailure(paths, "integrity");
      process.stderr.write("integrity check failed; request refused\n");
      return failure(err.code);
    }
    // Never print the error message or stack: they could include request data.
    process.stderr.write(`internal error (${err instanceof Error ? err.name : "unknown"})\n`);
    return failure("internal_error");
  }
}
