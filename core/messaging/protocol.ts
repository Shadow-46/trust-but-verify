import { createHash, createPublicKey, diffieHellman, generateKeyPairSync, randomBytes } from "node:crypto";
import { aad, open, seal } from "../crypto/aead.ts";
import { hkdf } from "../crypto/kdf.ts";
import { decapsulate, encapsulate, exportMlKem768PublicKeyRaw, importMlKem768PublicKey } from "../crypto/kem.ts";
import { generateSigningKeyPair, signBytes, verifyBytes } from "../crypto/sign.ts";
import type { SigningKeyPair } from "../crypto/sign.ts";
import { IntegrityError } from "../errors.ts";

/**
 * End-to-end encrypted messaging (goals 9–12).
 *
 * Handshake: both sides use fresh ephemeral X25519 + ML-KEM-768 keys; the session
 * secret is HKDF(X25519 shared ‖ ML-KEM shared, salt = transcript hash), so it is
 * safe unless BOTH the classical and the post-quantum exchange are broken.
 * Long-term identities (ML-DSA-65) only sign the handshake transcript, binding
 * each party to its ephemeral keys. Ephemeral private keys exist only inside the
 * handshake functions and session keys are zeroed on close: later exposure of
 * an identity key does not reveal earlier sessions (forward secrecy).
 */

export type Identity = { id: string; keys: SigningKeyPair };
/** Trusted identity public keys (e.g. from the signed control-plane policy). */
export type Directory = Map<string, Buffer>;

export function newIdentity(id: string): Identity {
  return { id, keys: generateSigningKeyPair() };
}

export type Hello = { type: "hello"; session_id: string; from: string; to: string; x25519: string; mlkem: string; sig: string };
export type Reply = { type: "reply"; session_id: string; from: string; to: string; x25519: string; kem_ct: string; sig: string };
export type Envelope = {
  session_id: string;
  from: string;
  to: string;
  msg_id: string;
  seq: number;
  index: number;
  total: number;
  n: string;
  c: string;
  t: string;
};
export type ReceiveResult =
  | { status: "delivered"; msg_id: string; data: Buffer }
  | { status: "buffered"; msg_id: string; have: number; total: number }
  | { status: "rejected"; reason: string };
export type DeliveryFailure = { msg_id: string; reason: string };

const MAX_CHUNKS = 4096;
const b64 = (b: Buffer) => b.toString("base64");
const unb64 = (s: string) => Buffer.from(typeof s === "string" ? s : "", "base64");
const json = (v: unknown) => Buffer.from(JSON.stringify(v), "utf8");
const sha256 = (b: Buffer) => createHash("sha256").update(b).digest();

const helloBytes = (h: Hello) => json(["tbv/hello/v1", h.session_id, h.from, h.to, h.x25519, h.mlkem]);
// The reply signature covers the complete signed hello: the transcript binds both identities to all ephemeral keys.
const replyBytes = (h: Hello, r: Omit<Reply, "sig">) =>
  json(["tbv/reply/v1", h.session_id, h.from, h.to, h.x25519, h.mlkem, h.sig, r.from, r.to, r.x25519, r.kem_ct]);

function deriveSessionKeys(dh: Buffer, kemShared: Buffer, h: Hello, r: Reply) {
  const transcript = sha256(Buffer.concat([helloBytes(h), Buffer.from(h.sig), replyBytes(h, r), Buffer.from(r.sig)]));
  const okm = hkdf(Buffer.concat([dh, kemShared]), transcript, "tbv/msg/session/v1", 96);
  dh.fill(0);
  kemShared.fill(0);
  return { initiatorToResponder: okm.subarray(0, 32), responderToInitiator: okm.subarray(32, 64), resume: okm.subarray(64, 96) };
}

function x25519Public(spkiB64: string) {
  try {
    const key = createPublicKey({ key: unb64(spkiB64), format: "der", type: "spki" });
    if (key.asymmetricKeyType !== "x25519") throw new Error("type");
    return key;
  } catch {
    throw new IntegrityError("handshake x25519 key");
  }
}

function requirePeer(dir: Directory, id: string): Buffer {
  const pub = dir.get(id);
  if (!pub) throw new IntegrityError("unknown peer identity");
  return pub;
}

/** Initiator step 1: create the signed hello. `finish` completes the handshake with the reply. */
export function initiate(me: Identity, peer: string): { hello: Hello; finish: (reply: Reply, dir: Directory) => Session } {
  const x = generateKeyPairSync("x25519");
  const k = generateKeyPairSync("ml-kem-768" as never);
  const unsigned = {
    type: "hello" as const,
    session_id: randomBytes(16).toString("hex"),
    from: me.id,
    to: peer,
    x25519: b64(x.publicKey.export({ type: "spki", format: "der" })),
    mlkem: b64(exportMlKem768PublicKeyRaw(k.publicKey)),
  };
  const hello: Hello = { ...unsigned, sig: b64(signBytes(me.keys.privateKey, helloBytes({ ...unsigned, sig: "" }))) };
  return {
    hello,
    finish(reply: Reply, dir: Directory): Session {
      if (reply.type !== "reply" || reply.session_id !== hello.session_id || reply.from !== peer || reply.to !== me.id) {
        throw new IntegrityError("handshake reply mismatch");
      }
      const { sig, ...rest } = reply;
      if (!verifyBytes(requirePeer(dir, peer), replyBytes(hello, rest), unb64(sig))) throw new IntegrityError("handshake signature");
      const dh = diffieHellman({ privateKey: x.privateKey, publicKey: x25519Public(reply.x25519) });
      const keys = deriveSessionKeys(dh, decapsulate(k.privateKey, unb64(reply.kem_ct)), hello, reply);
      return new Session(hello.session_id, me.id, peer, keys.initiatorToResponder, keys.responderToInitiator, keys.resume);
    },
  };
}

/** Responder: verify the hello, answer with a signed reply, and derive the session. */
export function respond(me: Identity, hello: Hello, dir: Directory): { reply: Reply; session: Session } {
  if (hello.type !== "hello" || hello.to !== me.id) throw new IntegrityError("hello not addressed to us");
  if (!verifyBytes(requirePeer(dir, hello.from), helloBytes(hello), unb64(hello.sig))) throw new IntegrityError("hello signature");
  const x = generateKeyPairSync("x25519");
  const { ciphertext, sharedKey } = encapsulate(importMlKem768PublicKey(unb64(hello.mlkem)));
  const unsigned = {
    type: "reply" as const,
    session_id: hello.session_id,
    from: me.id,
    to: hello.from,
    x25519: b64(x.publicKey.export({ type: "spki", format: "der" })),
    kem_ct: b64(ciphertext),
  };
  const reply: Reply = { ...unsigned, sig: b64(signBytes(me.keys.privateKey, replyBytes(hello, unsigned))) };
  const dh = diffieHellman({ privateKey: x.privateKey, publicKey: x25519Public(hello.x25519) });
  const keys = deriveSessionKeys(dh, sharedKey, hello, reply);
  const session = new Session(hello.session_id, me.id, hello.from, keys.responderToInitiator, keys.initiatorToResponder, keys.resume);
  return { reply, session };
}

type Pending = { total: number; seq: number; chunks: Map<number, Buffer>; first_at: number };

export class Session {
  readonly id: string;
  readonly self: string;
  readonly peer: string;
  private readonly sendKey: Buffer;
  private readonly recvKey: Buffer;
  /** Secret for resuming this session; held by both ends, zeroed on close. */
  readonly resumeSecret: Buffer;
  private sendSeq = 0;
  private readonly seen = new Set<string>();
  private readonly pending = new Map<string, Pending>();
  readonly failures: DeliveryFailure[] = [];
  closed = false;

  constructor(id: string, self: string, peer: string, sendKey: Buffer, recvKey: Buffer, resumeSecret: Buffer) {
    this.id = id;
    this.self = self;
    this.peer = peer;
    this.sendKey = Buffer.from(sendKey);
    this.recvKey = Buffer.from(recvKey);
    this.resumeSecret = Buffer.from(resumeSecret);
  }

  private chunkAad(from: string, to: string, msgId: string, seq: number, index: number, total: number): Buffer {
    return aad("tbv/msg/v1", this.id, from, to, msgId, seq, index, total);
  }

  /** Encrypt `data` as one message split into authenticated chunks. */
  send(data: Buffer, chunkSize = 1024): Envelope[] {
    if (this.closed) throw new Error("session closed");
    const msgId = randomBytes(12).toString("hex");
    const seq = ++this.sendSeq;
    const total = Math.max(1, Math.ceil(data.length / chunkSize));
    const out: Envelope[] = [];
    for (let index = 0; index < total; index++) {
      const part = data.subarray(index * chunkSize, (index + 1) * chunkSize);
      const sealed = seal(this.sendKey, part, this.chunkAad(this.self, this.peer, msgId, seq, index, total));
      out.push({ session_id: this.id, from: this.self, to: this.peer, msg_id: msgId, seq, index, total, ...sealed });
    }
    return out;
  }

  /**
   * Accept one chunk. The AAD is rebuilt from THIS session's view (sender = peer,
   * recipient = self), so a chunk whose recipient, sender, position or message ID
   * was altered fails authentication. Messages are delivered only when every chunk
   * has authenticated, each message ID at most once.
   */
  receive(env: Envelope, now = Date.now()): ReceiveResult {
    if (this.closed) return { status: "rejected", reason: "session_closed" };
    if (env.session_id !== this.id) return { status: "rejected", reason: "wrong_session" };
    if (env.to !== this.self || env.from !== this.peer) return { status: "rejected", reason: "wrong_recipient" };
    if (this.seen.has(env.msg_id)) return { status: "rejected", reason: "duplicate_message" };
    const { index, total } = env;
    if (!Number.isInteger(total) || total < 1 || total > MAX_CHUNKS || !Number.isInteger(index) || index < 0 || index >= total) {
      return { status: "rejected", reason: "invalid_chunk_position" };
    }
    let plain: Buffer;
    try {
      plain = open(this.recvKey, env, this.chunkAad(this.peer, this.self, env.msg_id, env.seq, index, total), "message chunk");
    } catch {
      if (this.pending.delete(env.msg_id)) this.failures.push({ msg_id: env.msg_id, reason: "authentication_failed" });
      return { status: "rejected", reason: "authentication_failed" };
    }
    let p = this.pending.get(env.msg_id);
    if (!p) {
      p = { total, seq: env.seq, chunks: new Map(), first_at: now };
      this.pending.set(env.msg_id, p);
    } else if (p.total !== total || p.seq !== env.seq) {
      return { status: "rejected", reason: "inconsistent_chunk" };
    }
    if (p.chunks.has(index)) return { status: "rejected", reason: "duplicate_chunk" };
    p.chunks.set(index, plain);
    if (p.chunks.size < p.total) return { status: "buffered", msg_id: env.msg_id, have: p.chunks.size, total: p.total };
    this.pending.delete(env.msg_id);
    this.seen.add(env.msg_id);
    const done = p;
    const data = Buffer.concat(Array.from({ length: done.total }, (_, i) => done.chunks.get(i) as Buffer));
    return { status: "delivered", msg_id: env.msg_id, data };
  }

  /** Discard messages still incomplete after `maxAgeMs` and report them as delivery failures. */
  expire(now = Date.now(), maxAgeMs = 30_000): DeliveryFailure[] {
    const failed: DeliveryFailure[] = [];
    for (const [id, p] of this.pending) {
      if (now - p.first_at > maxAgeMs) {
        this.pending.delete(id);
        failed.push({ msg_id: id, reason: `incomplete (${p.chunks.size}/${p.total} chunks)` });
      }
    }
    this.failures.push(...failed);
    return failed;
  }

  /** Erase all session secrets. */
  close(): void {
    this.sendKey.fill(0);
    this.recvKey.fill(0);
    this.resumeSecret.fill(0);
    this.pending.clear();
    this.closed = true;
  }

  /** True when every secret has been erased (used by tests and evidence). */
  secretsErased(): boolean {
    return [this.sendKey, this.recvKey, this.resumeSecret].every((b) => b.every((x) => x === 0));
  }
}

// ---------- session resumption (goal 12) ----------

export type ResumeRequest = { session_id: string; from: string; nonce: string; ts: number; sig: string };
type ResumeEntry = { peer: string; peerKeyFingerprint: string; secret: Buffer; expires_at: number };

const resumeBytes = (r: Omit<ResumeRequest, "sig">) => json(["tbv/resume/v1", r.session_id, r.from, r.nonce, r.ts]);
const fingerprint = (pub: Buffer) => sha256(pub).toString("hex");

export function resumeRequest(me: Identity, sessionId: string, now = Date.now()): ResumeRequest {
  const unsigned = { session_id: sessionId, from: me.id, nonce: randomBytes(16).toString("hex"), ts: now };
  return { ...unsigned, sig: b64(signBytes(me.keys.privateKey, resumeBytes(unsigned))) };
}

function resumedKeys(secret: Buffer, req: ResumeRequest) {
  const okm = hkdf(secret, Buffer.from(req.nonce, "hex"), `tbv/msg/resume/v1/${req.session_id}`, 96);
  return { i2r: okm.subarray(0, 32), r2i: okm.subarray(32, 64), resume: okm.subarray(64, 96) };
}

/**
 * Server-side resumption store. A ticket is bound to the authenticated peer's
 * identity AND its identity-key fingerprint: presenting the same session ID with
 * a different identity (or a re-keyed identity) is refused, and the current
 * access policy is re-checked on every resume.
 */
export class ResumptionStore {
  private readonly entries = new Map<string, ResumeEntry>();
  private readonly usedNonces = new Set<string>();

  remember(session: Session, dir: Directory, lifetimeMs = 10 * 60_000, now = Date.now()): void {
    this.entries.set(session.id, {
      peer: session.peer,
      peerKeyFingerprint: fingerprint(requirePeer(dir, session.peer)),
      secret: Buffer.from(session.resumeSecret),
      expires_at: now + lifetimeMs,
    });
  }

  resume(
    me: Identity,
    req: ResumeRequest,
    dir: Directory,
    isAuthorized: (identity: string) => boolean = () => true,
    now = Date.now(),
  ): { ok: true; session: Session } | { ok: false; reason: string } {
    const e = this.entries.get(req.session_id);
    if (!e) return { ok: false, reason: "unknown_session" };
    if (now > e.expires_at) {
      e.secret.fill(0);
      this.entries.delete(req.session_id);
      return { ok: false, reason: "ticket_expired" };
    }
    if (req.from !== e.peer) return { ok: false, reason: "identity_mismatch" };
    const pub = dir.get(req.from);
    if (!pub || fingerprint(pub) !== e.peerKeyFingerprint) return { ok: false, reason: "identity_key_changed" };
    if (!verifyBytes(pub, resumeBytes(req), unb64(req.sig))) return { ok: false, reason: "bad_signature" };
    if (Math.abs(now - req.ts) > 30_000 || this.usedNonces.has(req.nonce)) return { ok: false, reason: "stale_or_replayed" };
    if (!isAuthorized(req.from)) return { ok: false, reason: "not_authorized" };
    this.usedNonces.add(req.nonce);
    const k = resumedKeys(e.secret, req);
    e.secret.set(k.resume); // the next resumption uses a fresh secret
    return { ok: true, session: new Session(req.session_id, me.id, e.peer, k.r2i, k.i2r, k.resume) };
  }
}

/** Client side of resumption: derive the same keys from its copy of the resume secret. */
export function resumeAsClient(old: Session, req: ResumeRequest): Session {
  const k = resumedKeys(old.resumeSecret, req);
  return new Session(req.session_id, old.self, old.peer, k.i2r, k.r2i, k.resume);
}
