import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { initiate, newIdentity, respond, resumeAsClient, resumeRequest, ResumptionStore } from "../core/messaging/protocol.ts";
import type { Directory } from "../core/messaging/protocol.ts";

function pair() {
  const alice = newIdentity("alice");
  const bob = newIdentity("bob");
  const carol = newIdentity("carol");
  const dir: Directory = new Map([
    ["alice", alice.keys.publicKey],
    ["bob", bob.keys.publicKey],
    ["carol", carol.keys.publicKey],
  ]);
  const { hello, finish } = initiate(alice, "bob");
  const { reply, session: bobS } = respond(bob, hello, dir);
  const aliceS = finish(reply, dir);
  return { alice, bob, carol, dir, hello, reply, aliceS, bobS };
}

test("hybrid handshake: both sides derive the same keys and messages arrive intact in any order", () => {
  const { aliceS, bobS } = pair();
  const data = randomBytes(3000);
  const chunks = aliceS.send(data, 1024);
  assert.equal(chunks.length, 3);
  assert.equal(bobS.receive(chunks[2]).status, "buffered");
  assert.equal(bobS.receive(chunks[0]).status, "buffered");
  const r = bobS.receive(chunks[1]);
  assert.ok(r.status === "delivered" && r.data.equals(data));
  const got = aliceS.receive(bobS.send(Buffer.from("ack"))[0]);
  assert.ok(got.status === "delivered" && got.data.toString() === "ack");
});

test("replay and recipient binding: duplicates and re-addressed or altered chunks are rejected", () => {
  const { alice, carol, dir, aliceS, bobS } = pair();
  const [env] = aliceS.send(Buffer.from("for bob only"));
  assert.equal(bobS.receive(env).status, "delivered");
  assert.deepEqual(bobS.receive(env), { status: "rejected", reason: "duplicate_message" });

  const [env2] = aliceS.send(Buffer.from("second"));
  assert.deepEqual(bobS.receive({ ...env2, to: "carol" }), { status: "rejected", reason: "wrong_recipient" });
  assert.deepEqual(bobS.receive({ ...env2, seq: env2.seq + 1 }), { status: "rejected", reason: "authentication_failed" });
  assert.deepEqual(bobS.receive({ ...env2, msg_id: "forged" }), { status: "rejected", reason: "authentication_failed" });

  // Carol, even with her own valid session to alice, cannot read alice→bob traffic re-addressed to her.
  const h = initiate(alice, "carol");
  const carolS = respond(carol, h.hello, dir).session;
  h.finish(respond(carol, h.hello, dir).reply, dir);
  assert.equal(carolS.receive({ ...env2, to: "carol" }).status, "rejected");
});

test("loss and tampering: incomplete messages expire as reported failures; a bad chunk discards the message", () => {
  const { aliceS, bobS } = pair();
  const chunks = aliceS.send(randomBytes(3000), 1024);
  bobS.receive(chunks[0], 1_000);
  bobS.receive(chunks[1], 1_000);
  assert.deepEqual(bobS.expire(1_000 + 31_000), [{ msg_id: chunks[0].msg_id, reason: "incomplete (2/3 chunks)" }]);
  assert.equal(bobS.receive(chunks[2]).status, "buffered", "an expired message cannot complete later");

  const more = aliceS.send(randomBytes(2048), 1024);
  bobS.receive(more[0]);
  const flipped = { ...more[1], c: Buffer.from(more[1].c, "base64").map((b, i) => (i === 0 ? b ^ 1 : b)).toString("base64") };
  assert.deepEqual(bobS.receive(flipped), { status: "rejected", reason: "authentication_failed" });
  assert.ok(bobS.failures.some((f) => f.msg_id === more[0].msg_id && f.reason === "authentication_failed"));
});

test("handshake tampering (key substitution) is detected by transcript signatures", () => {
  const { alice, bob, dir } = pair();
  const { hello, finish } = initiate(alice, "bob");
  const attacker = initiate(newIdentity("alice"), "bob").hello; // different ephemeral keys
  assert.throws(() => respond(bob, { ...hello, x25519: attacker.x25519 }, dir), /hello signature/);
  assert.throws(() => respond(bob, { ...hello, mlkem: attacker.mlkem }, dir), /hello signature/);
  const { reply } = respond(bob, hello, dir);
  const otherReply = respond(bob, initiate(alice, "bob").hello, dir).reply;
  assert.throws(() => finish({ ...reply, kem_ct: otherReply.kem_ct }, dir), /handshake signature/);
});

test("forward secrecy: after close, stolen identity keys plus the recorded transcript do not decrypt", () => {
  const { bob, dir, hello, aliceS, bobS } = pair();
  const recorded = aliceS.send(Buffer.from("top secret"));
  assert.equal(bobS.receive(recorded[0]).status, "delivered");
  aliceS.close();
  bobS.close();
  assert.ok(aliceS.secretsErased() && bobS.secretsErased());
  // The attacker holds bob's long-term identity key and replays the recorded hello. Without the
  // erased ephemeral secrets the result is a NEW session with unrelated keys.
  const stolen = respond(bob, hello, dir).session;
  assert.deepEqual(stolen.receive(recorded[0]), { status: "rejected", reason: "authentication_failed" });
});

test("session resumption stays bound to the authenticated peer", () => {
  const { alice, bob, dir, aliceS, bobS } = pair();
  const mallory = newIdentity("mallory");
  dir.set("mallory", mallory.keys.publicKey);
  const store = new ResumptionStore();
  store.remember(bobS, dir);

  const req = resumeRequest(alice, aliceS.id);
  const resumed = store.resume(bob, req, dir);
  const [env] = resumeAsClient(aliceS, req).send(Buffer.from("after resume"));
  assert.ok(resumed.ok && resumed.session.receive(env).status === "delivered");

  assert.deepEqual(store.resume(bob, resumeRequest(mallory, aliceS.id), dir), { ok: false, reason: "identity_mismatch" });
  const forged = { ...resumeRequest(mallory, aliceS.id), from: "alice" };
  assert.deepEqual(store.resume(bob, forged, dir), { ok: false, reason: "bad_signature" });
  assert.deepEqual(store.resume(bob, req, dir), { ok: false, reason: "stale_or_replayed" });
  assert.deepEqual(store.resume(bob, resumeRequest(alice, aliceS.id), dir, () => false), { ok: false, reason: "not_authorized" });
  dir.set("alice", newIdentity("alice").keys.publicKey); // re-keyed identity, e.g. after device loss
  assert.deepEqual(store.resume(bob, resumeRequest(alice, aliceS.id), dir), { ok: false, reason: "identity_key_changed" });
});

// ---------- per-message symmetric ratchet (forward secrecy within a session) ----------
import { createHmac } from "node:crypto";
import { open as openSealed } from "../core/crypto/aead.ts";
import { MAX_SKIPPED_KEYS } from "../core/messaging/protocol.ts";

const chainOf = (s: unknown, dir: "sendChain" | "recvChain") => Buffer.from((s as Record<string, Buffer>)[dir]);
const step = (ck: Buffer) => ({ mk: createHmac("sha256", ck).update(Buffer.from([1])).digest(), next: createHmac("sha256", ck).update(Buffer.from([2])).digest() });
const aadFor = (e: { session_id: string; from: string; to: string; msg_id: string; seq: number; index: number; total: number }) =>
  Buffer.from(JSON.stringify(["tbv/msg/v2", e.session_id, e.from, e.to, e.msg_id, e.seq, e.index, e.total]), "utf8");

test("ratchet: stealing the current chain state does not decrypt earlier messages of the same session", () => {
  const { aliceS, bobS } = pair();
  const sent = [1, 2, 3, 4, 5].map((i) => aliceS.send(Buffer.from(`message ${i}`))[0]);
  for (const e of sent) assert.equal(bobS.receive(e).status, "delivered");
  // The attacker steals bob's live receive chain (and alice's send chain) right now.
  const stolen = [chainOf(bobS, "recvChain"), chainOf(aliceS, "sendChain")];
  assert.ok(stolen[0].equals(stolen[1]), "both ends are in step");
  // Every key the attacker can derive going forward fails on messages 1..5 (HMAC is one-way).
  let ck = stolen[0];
  for (let k = 0; k < 50; k++) {
    const { mk, next } = step(ck);
    for (const e of sent) assert.throws(() => openSealed(mk, e, aadFor(e), "m"), undefined, `derived key ${k} must not open seq ${e.seq}`);
    ck = next;
  }
  // Honest limit (no DH ratchet): the stolen state does reveal the NEXT message.
  const [sixth] = aliceS.send(Buffer.from("message 6"));
  assert.equal(openSealed(step(stolen[0]).mk, sixth, aadFor(sixth), "m").toString(), "message 6");
});

test("ratchet: out-of-order delivery still reassembles, and each message key is erased after use", () => {
  const { aliceS, bobS } = pair();
  const m = [1, 2, 3, 4].map((i) => aliceS.send(Buffer.alloc(2500, i), 1024)); // 3 chunks each
  // Deliver message 4 first (skips keys 1..3), then the others with their chunks shuffled.
  for (const c of [m[3][2], m[3][0], m[3][1]]) bobS.receive(c);
  assert.equal(bobS.heldKeyCount, 3, "keys for 1..3 held, key 4 erased after delivery");
  const order = [m[1][1], m[0][2], m[2][0], m[1][0], m[0][0], m[2][2], m[1][2], m[0][1], m[2][1]];
  const delivered = order.map((c) => bobS.receive(c)).filter((r) => r.status === "delivered");
  assert.equal(delivered.length, 3);
  for (const r of delivered) assert.ok(r.status === "delivered" && r.data.length === 2500);
  assert.equal(bobS.heldKeyCount, 0, "every message key used once and erased");
});

test("ratchet: the skipped-key cap holds; a far-ahead or forged sequence burns no keys", () => {
  const { aliceS, bobS } = pair();
  const [first] = aliceS.send(Buffer.from("first"));
  const forged = { ...first, seq: 10_000 };
  assert.deepEqual(bobS.receive(forged), { status: "rejected", reason: "too_far_ahead" });
  const justInside = { ...first, seq: MAX_SKIPPED_KEYS - 1 };
  assert.deepEqual(bobS.receive(justInside), { status: "rejected", reason: "authentication_failed" }); // tentative, not committed
  assert.equal(bobS.heldKeyCount, 0, "no keys stored for unauthenticated envelopes");
  assert.equal(bobS.receive(first).status, "delivered", "the genuine message still decrypts");
});

test("ratchet: a replayed message is rejected, also with a fresh message ID; close erases chains and held keys", () => {
  const { aliceS, bobS } = pair();
  const [a, b] = [aliceS.send(Buffer.from("a"))[0], aliceS.send(Buffer.from("b"))[0]];
  assert.equal(bobS.receive(b).status, "delivered"); // key 1 is now held (skipped)
  assert.equal(bobS.receive(a).status, "delivered");
  assert.deepEqual(bobS.receive(a), { status: "rejected", reason: "duplicate_message" });
  assert.deepEqual(bobS.receive({ ...a, msg_id: "fresh-id" }), { status: "rejected", reason: "duplicate_message" });
  aliceS.send(Buffer.from("c")); // advances alice's chain
  const [d] = aliceS.send(Buffer.from("d"));
  assert.equal(bobS.receive(d).status, "delivered"); // holds key for "c"
  assert.equal(bobS.heldKeyCount, 1);
  bobS.close();
  aliceS.close();
  assert.ok(bobS.secretsErased() && aliceS.secretsErased());
  assert.equal(bobS.heldKeyCount, 0);
});

test("ratchet: a resumed session starts fresh chains (never reuses the old chain)", () => {
  const { alice, bob, dir, aliceS, bobS } = pair();
  const store = new ResumptionStore();
  store.remember(bobS, dir);
  const req = resumeRequest(alice, aliceS.id);
  const resumed = store.resume(bob, req, dir);
  const client = resumeAsClient(aliceS, req);
  assert.ok(resumed.ok);
  assert.ok(!chainOf(client, "sendChain").equals(chainOf(aliceS, "sendChain")), "new chain, not the old one");
  const [env] = client.send(Buffer.from("after resume"));
  assert.deepEqual(bobS.receive(env), { status: "rejected", reason: "authentication_failed" }, "old session cannot read resumed traffic");
  assert.ok(resumed.ok && resumed.session.receive(env).status === "delivered");
});
