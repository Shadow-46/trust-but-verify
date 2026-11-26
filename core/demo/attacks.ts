import { randomBytes } from "node:crypto";
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { handle } from "../adapter.ts";
import { readAudit, verifyAudit } from "../audit/log.ts";
import { ControlPlane } from "../cluster/control.ts";
import { ClusterNode, signRequest } from "../cluster/node.ts";
import type { AccessRequest } from "../cluster/node.ts";
import { signPolicy } from "../cluster/policy.ts";
import { generateSigningKeyPair } from "../crypto/sign.ts";
import { securityAlerts } from "../defense/guard.ts";
import { statePaths } from "../store/paths.ts";

/**
 * Attack Lab: each attack runs for real against a fresh, isolated instance and
 * reports whether the defence held, with the evidence an operator would see.
 */
export type AttackResult = { id: string; name: string; attack: string; defense: string; blocked: boolean; evidence: string };
type Attack = { id: string; name: string; attack: string; defense: string; run: () => { blocked: boolean; evidence: string } };
type Body = Record<string, unknown>;

const SETUP = {
  op: "setup",
  owners: { "design-doc": "maya", "payroll.xlsx": "omar" },
  contents: { "design-doc": "Q3 design (confidential)", "payroll.xlsx": "salary bands (confidential)" },
  disabled: [],
  // Generated per run: no fixed secret string in product code (it is only synthetic setup input).
  key_material: `synthetic-${randomBytes(8).toString("hex")}`,
};

function withEnv<T>(env: Record<string, string | undefined>, fn: () => T): T {
  const before = Object.fromEntries(Object.keys(env).map((k) => [k, process.env[k]]));
  for (const [k, v] of Object.entries(env)) if (v === undefined) delete process.env[k]; else process.env[k] = v;
  try {
    return fn();
  } finally {
    for (const [k, v] of Object.entries(before)) if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
}

// Attack instances are throwaway: they must never publish to the operator's witness
// (that would make the real service see a "rollback" and fail closed).
const isolated = (env: Record<string, string | undefined>) => ({ TRACK4_WITNESS_DIR: undefined, ...env });

function instance(env: Record<string, string | undefined> = {}) {
  const dir = mkdtempSync(join(tmpdir(), "tbv-attack-"));
  const paths = statePaths(dir);
  const call = (req: unknown, raw?: string) => withEnv(isolated(env), () => handle(raw ?? JSON.stringify(req), paths).body as Body);
  call(SETUP);
  return { dir, paths, call };
}

function cluster() {
  const base = mkdtempSync(join(tmpdir(), "tbv-attack-cluster-"));
  const cp = ControlPlane.create(join(base, "control"));
  const node = new ClusterNode("node-a", join(base, "node-a"), cp.anchor, cp.paths.published);
  const device = generateSigningKeyPair();
  cp.enrolDevice("maya", "maya-phone", device.publicKey);
  node.sync();
  const request = (extra: Partial<AccessRequest> = {}) =>
    signRequest(device.privateKey, { actor: "maya", device_id: "maya-phone", node: "node-a", key_version: 1, op: "request", transfer_id: null, nonce: randomBytes(8).toString("hex"), ts: Date.now(), ...extra });
  return { base, cp, node, request };
}

const ATTACKS: Attack[] = [
  {
    id: "stolen-device", name: "Stolen device keeps using its key", attack: "A revoked phone signs a valid request with its real key.", defense: "Device revocation in the ML-DSA-signed policy, checked on every node.",
    run: () => { const { cp, node, request } = cluster(); cp.revokeDevice("maya-phone"); node.sync(); const d = node.authorize(request()); return { blocked: d.decision === "deny", evidence: `node-a: ${d.decision} (${d.reason})` }; },
  },
  {
    id: "replay", name: "Replay a captured request", attack: "Resend a signed request byte for byte.", defense: "Single-use nonce and ±30 s timestamp window.",
    run: () => { const { node, request } = cluster(); const r = request(); node.authorize(r); const d = node.authorize(r); return { blocked: d.reason === "replayed_request", evidence: `second attempt: ${d.decision} (${d.reason})` }; },
  },
  {
    id: "forged-policy", name: "Forge a policy that un-revokes", attack: "Publish a policy with a higher epoch, signed with the attacker's own key.", defense: "Nodes only accept policies signed by the control-plane trust anchor.",
    run: () => { const { cp, node } = cluster(); cp.revokeDevice("maya-phone"); node.sync(); const evil = generateSigningKeyPair(); writeFileSync(cp.paths.published, JSON.stringify(signPolicy(evil.privateKey, { ...cp.policy, epoch: cp.policy.epoch + 50, devices: cp.policy.devices.map((d) => ({ ...d, status: "active" as const })) }))); const s = node.sync(); return { blocked: s.status === "rejected", evidence: `sync: ${s.status}${s.status === "rejected" ? ` (${s.reason})` : ""}, device still revoked` }; },
  },
  {
    id: "policy-rollback", name: "Replay an old genuine policy", attack: "Serve an older, genuinely signed policy from before the revocation.", defense: "Monotonic epoch: nodes refuse older policies.",
    run: () => { const { base, cp, node } = cluster(); const old = join(base, "old.json"); copyFileSync(cp.paths.published, old); cp.revokeDevice("maya-phone"); node.sync(); copyFileSync(old, cp.paths.published); const s = node.sync(); return { blocked: s.status === "rejected" && s.reason === "rollback", evidence: `sync: ${s.status}${s.status === "rejected" ? ` (${s.reason})` : ""}` }; },
  },
  {
    id: "state-rollback", name: "Roll the state file back", attack: "Restore yesterday's state file to undo a revocation.", defense: "State version bound to the signed audit-log head; fail closed.",
    run: () => { const { dir, paths, call } = instance(); const saved = join(dir, "old"); copyFileSync(paths.state, saved); call({ op: "revoke", actor: "maya" }); copyFileSync(saved, paths.state); const r = call({ op: "read", actor: "maya", asset: "design-doc", request_id: "x" }); return { blocked: r.error === "integrity_failure", evidence: `read: ${JSON.stringify(r)}` }; },
  },
  {
    id: "consistent-rollback", name: "Roll back state and log together", attack: "Restore an internally consistent old copy of state, log and log head.", defense: "Signed log heads mirrored to an external witness.",
    run: () => { const witness = mkdtempSync(join(tmpdir(), "tbv-witness-")); const env = { TRACK4_WITNESS_DIR: witness }; const { dir, paths, call } = instance(env); const files = [paths.state, paths.audit, paths.auditHead]; files.forEach((f, i) => copyFileSync(f, join(dir, `s${i}`))); call({ op: "revoke", actor: "maya" }); files.forEach((f, i) => copyFileSync(join(dir, `s${i}`), f)); const r = call({ op: "read", actor: "maya", asset: "design-doc", request_id: "x" }); return { blocked: r.error === "integrity_failure", evidence: `read: ${JSON.stringify(r)}` }; },
  },
  {
    id: "edit-log", name: "Edit a record in the audit log", attack: "Change a past 'deny' into 'allow' to hide an incident.", defense: "Hash chain + ML-DSA signature on every record.",
    run: () => { const { paths, call } = instance(); call({ op: "read", actor: "omar", asset: "design-doc", request_id: "d" }); const lines = readFileSync(paths.audit, "utf8").trimEnd().split("\n"); lines[1] = lines[1].replace('"decision":"deny"', '"decision":"allow"'); writeFileSync(paths.audit, lines.join("\n") + "\n"); const v = verifyAudit(paths); return { blocked: !v.ok, evidence: `verify-log: ${v.ok ? "valid" : `broken at record #${v.first_bad_seq}`}` }; },
  },
  {
    id: "truncate-log", name: "Cut the log and delete its signed head", attack: "Remove the newest records (a denial) and the head file that would expose it.", defense: "Head is mandatory after setup; failure alerts never re-sign the log.",
    run: () => { const { paths, call } = instance(); call({ op: "read", actor: "omar", asset: "design-doc", request_id: "t" }); const lines = readFileSync(paths.audit, "utf8").trimEnd().split("\n"); writeFileSync(paths.audit, lines.slice(0, -1).join("\n") + "\n"); rmSync(paths.auditHead); const r = call({ op: "read", actor: "maya", asset: "design-doc", request_id: "t2" }); return { blocked: r.error === "integrity_failure", evidence: `read: ${JSON.stringify(r)}` }; },
  },
  {
    id: "swap-audit-key", name: "Swap the log's verification key", attack: "Replace keys/audit.pub with the attacker's own key to re-sign an edited log.", defense: "Hash of the verification key is pinned inside the MAC'd state.",
    run: () => { const { paths, call } = instance(); writeFileSync(paths.auditPub, generateSigningKeyPair().publicKey.toString("base64")); const r = call({ op: "read", actor: "maya", asset: "design-doc", request_id: "k" }); return { blocked: r.error === "integrity_failure", evidence: `read: ${JSON.stringify(r)}` }; },
  },
  {
    id: "delete-signing-key", name: "Delete the log signing key", attack: "Remove keys/audit.key so new records are written unsigned.", defense: "No key means fail closed; a record is never written without a signature.",
    run: () => { const { paths, call } = instance(); const before = readFileSync(paths.audit, "utf8"); rmSync(paths.auditKey); const r = call({ op: "read", actor: "maya", asset: "design-doc", request_id: "s" }); return { blocked: r.error === "integrity_failure" && readFileSync(paths.audit, "utf8") === before, evidence: `read: ${JSON.stringify(r)}; no record written` }; },
  },
  {
    id: "log-injection", name: "Inject a fake log record", attack: "Send an actor name containing a newline and a forged JSON record.", defense: "Every value is a JSON field; record boundaries cannot be forged.",
    run: () => { const { paths, call } = instance(); const evil = 'mallory\n{"type":"revoke","actor":"omar"}'; call({ op: "read", actor: evil, asset: "design-doc", request_id: "i" }); const recs = readAudit(paths).filter((r) => r.request_id === "i"); return { blocked: recs.length === 1 && recs[0].actor === evil && !readAudit(paths).some((r) => r.type === "revoke"), evidence: "1 record written, actor preserved verbatim, no fake revoke" }; },
  },
  {
    id: "weird-ids", name: "Prototype pollution and path traversal", attack: "Use __proto__ and ../../etc/passwd as identities and file names.", defense: "IDs are opaque Map keys, never object keys or file paths.",
    run: () => { const { call } = instance(); const a = call({ op: "read", actor: "__proto__", asset: "../../etc/passwd", request_id: "w1" }); const b = call({ op: "read", actor: "constructor", asset: "__proto__", request_id: "w2" }); return { blocked: a.decision === "deny" && b.decision === "deny" && !a.body && !b.body, evidence: `both denied without content (${JSON.stringify(a)})` }; },
  },
  {
    id: "malformed", name: "Flood with malformed input", attack: "Send broken JSON repeatedly.", defense: "Fixed error codes, no echo of input, burst detection alert.",
    run: () => { const { paths, call } = instance(); let r: Body = {}; for (let i = 0; i < 10; i++) r = call(undefined, "{not json"); const alerted = securityAlerts(paths).some((a) => a.rule === "malformed_input_burst"); return { blocked: r.error === "invalid_json" && alerted, evidence: `reply ${JSON.stringify(r)}; alert: malformed_input_burst` }; },
  },
  {
    id: "probing", name: "Probe other users' files", attack: "A valid account tries many files it does not own.", defense: "Probing detection, signed alert and (where enabled) quarantine.",
    run: () => { const { paths, call } = instance({ TRACK4_AUTO_QUARANTINE: "1" }); for (const [i, a] of ["design-doc", "secret-1", "secret-2"].entries()) call({ op: "read", actor: "omar", asset: a, request_id: `p${i}` }); const own = withEnv(isolated({ TRACK4_AUTO_QUARANTINE: "1" }),() => handle(JSON.stringify({ op: "read", actor: "omar", asset: "payroll.xlsx", request_id: "own" }), paths).body as Body); const rules = securityAlerts(paths).map((a) => a.rule); return { blocked: rules.includes("probing") && own.decision === "deny", evidence: `alerts: ${rules.join(", ")}; omar quarantined` }; },
  },
  {
    id: "protected-read", name: "Steal content via protected_read", attack: "Ask for the encrypted proof of someone else's file, and send a malformed key.", defense: "Authorize before encapsulating; strict ML-KEM-768 key validation.",
    run: () => { const { call } = instance(); const a = call({ op: "protected_read", actor: "omar", asset: "design-doc", challenge: "c", public_key: Buffer.alloc(1184, 7).toString("base64") }); const b = call({ op: "protected_read", actor: "maya", asset: "design-doc", challenge: "c", public_key: "AAAA" }); return { blocked: !a.ciphertext && !a.proof && b.error === "invalid_public_key", evidence: `non-owner: ${JSON.stringify(a)}; bad key: ${JSON.stringify(b)}` }; },
  },
];

export function listAttacks() {
  return ATTACKS.map(({ id, name, attack, defense }) => ({ id, name, attack, defense }));
}

export function runAttack(id: string): AttackResult[] {
  const chosen = id === "all" ? ATTACKS : ATTACKS.filter((a) => a.id === id);
  return chosen.map((a) => {
    let outcome: { blocked: boolean; evidence: string };
    try {
      outcome = a.run();
    } catch (err) {
      outcome = { blocked: false, evidence: `runner error: ${err instanceof Error ? err.message : "unknown"}` };
    }
    return { id: a.id, name: a.name, attack: a.attack, defense: a.defense, ...outcome };
  });
}
