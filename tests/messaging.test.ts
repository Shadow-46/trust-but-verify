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
