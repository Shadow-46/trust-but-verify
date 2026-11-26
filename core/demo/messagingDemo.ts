import { initiate, newIdentity, respond, resumeAsClient, resumeRequest, ResumptionStore } from "../messaging/protocol.ts";
import type { Directory, Envelope, Session } from "../messaging/protocol.ts";

/**
 * One complete, real messaging run for the operator console: hybrid handshake,
 * a short conversation, and the attacks goals 9–12 defend against. Returns a
 * transcript (ciphertext previews only, never keys).
 */
export function messagingDemo(text = "Can you review the Q3 design doc?") {
  const alice = newIdentity("alice");
  const bob = newIdentity("bob");
  const mallory = newIdentity("mallory");
  const dir: Directory = new Map([["alice", alice.keys.publicKey], ["bob", bob.keys.publicKey], ["mallory", mallory.keys.publicKey]]);
  const h = initiate(alice, "bob");
  const { reply, session: bobS } = respond(bob, h.hello, dir);
  const aliceS = h.finish(reply, dir);

  const messages: { from: string; to: string; text: string; msg_id: string; chunks: number; ciphertext_preview: string }[] = [];
  const deliver = (from: Session, to: Session, body: string) => {
    const envs = from.send(Buffer.from(body, "utf8"), 24);
    let out = "";
    for (const e of [...envs].reverse()) { // deliberately out of order
      const r = to.receive(e);
      if (r.status === "delivered") out = r.data.toString("utf8");
    }
    messages.push({ from: from.self, to: from.peer, text: out, msg_id: envs[0].msg_id, chunks: envs.length, ciphertext_preview: envs[0].c.slice(0, 44) + "…" });
    return envs;
  };
  const first = deliver(aliceS, bobS, text.slice(0, 200));
  deliver(bobS, aliceS, "On it. Sending comments within the hour.");
  const third = aliceS.send(Buffer.from("Thanks!", "utf8"));

  const attacks: { name: string; blocked: boolean; evidence: string }[] = [];
  const add = (name: string, r: { status: string; reason?: string }) => attacks.push({ name, blocked: r.status === "rejected", evidence: r.status === "rejected" ? `rejected: ${r.reason}` : r.status });

  add("Replay a delivered message", bobS.receive(first[0]));
  add("Re-address a message to someone else", bobS.receive({ ...third[0], to: "mallory" } as Envelope));
  const flipped = { ...third[0], c: Buffer.from(third[0].c, "base64").map((b, i) => (i === 0 ? b ^ 1 : b)).toString("base64") };
  add("Tamper with one ciphertext byte", bobS.receive(flipped));
  add("Change the sequence number", bobS.receive({ ...third[0], seq: third[0].seq + 7 }));

  // Session resumption: only the same authenticated identity may resume.
  const store = new ResumptionStore();
  store.remember(bobS, dir);
  const hijack = store.resume(bob, resumeRequest(mallory, aliceS.id), dir);
  attacks.push({ name: "Hijack the session ID with another identity", blocked: !hijack.ok, evidence: hijack.ok ? "resumed" : `rejected: ${hijack.reason}` });
  const req = resumeRequest(alice, aliceS.id);
  const resumed = store.resume(bob, req, dir);
  const resumedOk = resumed.ok && resumed.session.receive(resumeAsClient(aliceS, req).send(Buffer.from("back again"))[0]).status === "delivered";

  // Forward secrecy: after both sides close, stolen identity keys + recorded traffic do not decrypt.
  aliceS.close();
  bobS.close();
  const stolen = respond(bob, h.hello, dir).session;
  add("Decrypt recorded traffic later with stolen identity keys", stolen.receive(first[0]));

  return {
    handshake: { session: aliceS.id.slice(0, 12) + "…", algorithms: "X25519 + ML-KEM-768 → HKDF-SHA-256, transcript signed with ML-DSA-65, AES-256-GCM under a per-message HMAC-SHA-256 ratchet", resumption_for_alice: resumedOk ? "allowed" : "failed", keys_erased: aliceS.secretsErased() && bobS.secretsErased() },
    messages,
    attacks,
  };
}
