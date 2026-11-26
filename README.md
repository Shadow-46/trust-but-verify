# Trust, but verify

Post-quantum, zero-trust protection for files and messages while keys, devices
and user permissions change — plus an explainable detector that shows an operator
when an identity gains unexpected privileges or moves between services.

Built for Yugaantar DevForge 2026, Track 4.

> Work in progress: the protected-resource service, key rotation and multi-node revocation are
> complete; crash recovery, backups, signed logs, messaging and the detector are complete; the operator console is included for the demo.

**Docs:** [Evidence for all 12 goals](docs/EVIDENCE.md) · [Threat model](docs/THREAT_MODEL.md)

## Clean-machine setup
Requirements: **Node.js 24.11.1 or newer**. Nothing else — the service uses only
Node built-ins, so there is no `npm install` for the core.

```sh
git clone https://github.com/Shadow-46/trust-but-verify.git
cd trust-but-verify
npm test                     # 94 tests (one is Linux-only and skipped on Windows)
```

Run one request (the judging worker does exactly this, one process per request):
```sh
echo '{"op":"setup","owners":{"brief":"maya"},"contents":{"brief":"demo note"},"disabled":[],"key_material":"synthetic-only"}' | node track4_service.mjs
echo '{"op":"read","actor":"maya","asset":"brief","request_id":"r01"}' | node track4_service.mjs
```
State is kept in `$TRACK4_STATE_DIR`, or `<os temp dir>/trust-but-verify` if unset.

### Dependencies
| Part | Needs | Install |
|---|---|---|
| Core service, tests, demos (`track4_service.mjs`, `core/`, `dist/`, `tests/`) | **Node.js 24.11.1+ only**, built-ins only (`node:crypto` = OpenSSL 3.5). Zero runtime dependencies. | nothing (no `npm install`) |
| Operator console (`dashboard/`, optional, demo only) | Next.js 16.4.6, React 19.3.0, Tailwind CSS 4.3.3, shadcn 4.23 with Base UI 1.9, motion 14.14, lucide-react 1.80, sonner 2.0, next-themes 0.4, zod 4.6, class-variance-authority 0.7, tw-animate-css 1.4 (exact ranges in `dashboard/package.json`, pinned by `dashboard/package-lock.json`) | `cd dashboard && npm install && npm run dev` → http://127.0.0.1:3000 |
| ML-KEM interop check (optional) | Python 3.12 + `pqcrypto==0.4.0` (same as the judging runtime) | `python -m pip install pqcrypto==0.4.0` |
| Judge-parity run (optional) | Docker, image `node:24.11.1` (pulled once, then runs offline) | install Docker Desktop / Engine |

Windows note for the console: if Next.js reports a missing `lightningcss.win32-x64-msvc.node`, run `npm install`
in `dashboard/` again and move `dashboard/.next` aside before `npm run dev`.

## Verify against the official toolkit
```sh
git clone https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit ../Track-4-Toolkit
python ../Track-4-Toolkit/validate.py --entry ./track4_service.mjs        # 22 checks
tools/judge-parity.sh ../Track-4-Toolkit   # tests + validator in Docker node:24.11.1, offline, read-only
python -m pip install pqcrypto==0.4.0 && python tools/check_protected_read.py   # ML-KEM interop
```

## Adapter operations (contract v1)
| Op | Behaviour |
|---|---|
| `setup` | Replaces all state. Bodies are encrypted at rest; `key_material` is mixed into the data-key derivation and never stored or printed. → `{"ready":true}` |
| `read` | Allow only if the asset exists and the actor owns it and is neither disabled nor revoked → `{"decision":"allow","body":…}`; otherwise `{"decision":"deny"}` with no content. Every decision is recorded before replying. |
| `revoke` | Persists the revocation before acknowledging; other actors keep access. → `{"revoked":true}` |
| `audit` | First recorded decision for a `request_id` (later duplicates never overwrite it). |
| `protected_read` | Authorizes, then ML-KEM-768-encapsulates to the caller's raw public key and returns the ciphertext and `HMAC-SHA-256(shared_secret, challenge ‖ body)`. The body itself is never returned. |

Malformed input returns a fixed error code such as `{"error":"invalid_actor"}` and never echoes input.

## Security design
- **Vetted primitives only** (`node:crypto` / OpenSSL 3.5): ML-KEM-768 (FIPS 203), AES-256-GCM,
  HKDF-SHA-256, HMAC-SHA-256, SHA-256. No custom cryptography.
- **Key hierarchy:** master key (`TRACK4_MASTER_KEY` from a KMS/HSM, else a 0600 file) → HKDF →
  key-encryption key (wraps versioned data keys) and state-MAC key.
- **Encrypted, authenticated state:** asset ciphertexts are bound to setup, asset ID and key
  version through AES-GCM associated data; the policy file carries an HMAC, so editing it (e.g. to
  undo a revocation) makes every request fail closed.
- **Tamper-evident audit log:** append-only JSON lines, each committing to the previous record's
  SHA-256; user text is always a JSON field value, so it cannot forge a record boundary or actor.
- **Hardened I/O:** IDs are opaque (stored in `Map`s, never used as paths or object keys); atomic
  writes (temp + fsync + rename); cross-process lock; the state directory must be a private,
  self-owned directory (planted symlinks are refused); secrets never reach stdout, stderr or errors.

## Key rotation and revocation across nodes (goals 1–2)
`core/cluster/`: a **control plane** is the only writer of policy (enrolled devices, revoked
identities and devices, key versions). Every change is published as a new **epoch signed with
ML-DSA-65**. Each **node** pulls the policy, verifies the signature against a trust anchor
provisioned out of band, and adopts it only if its epoch is higher than the one it holds, so a forged
policy or a replayed older one (e.g. from before a revocation) is refused. Nodes keep enforcing
their last verified policy if the control plane is unreachable, including after a restart.

Every request is signed by an enrolled **device key** (ML-DSA-65) and checked for owner, device
status, identity revocation, signature, **target node**, timestamp (±30 s) and nonce (replay), then key version.
The target node is inside the signed bytes (audience binding), so a captured request replayed to a *different*
node is refused there as `wrong_node`: rejected on one node means rejected on every node, also after restarts
(`tests/cluster-hardening.test.ts`).

- **Key rotation — grace period: yes.** Rotating activates version *n+1*; version *n* stays valid for
  new requests until `cutoff = rotation time + grace_ms` (30 s by default, 1.5 s in the demo).
  From the cutoff on, every node rejects new requests and new transfers that use version *n*
  (`key_version_retired`). Transfers that a node authorized **before** the cutoff may finish on
  version *n* (at most 120 s). Stored assets are re-encrypted under the new data key in one atomic
  state replace (`rotateStoredDataKey`).
- **Device loss:** revoking a device stops only that device on every node; the owner enrols a new
  device (new key pair) and other users keep access. Revoking an identity stops all its devices.
- **Measured propagation** (`evidence/t6-cluster.json`, Docker `node:24.11.1`, 3 node processes,
  20 ms polling, 15 samples): revocation published → last node enforcing **median 19 ms, max 21 ms**.
  Bound: one polling interval plus verification; all nodes share one host clock in this run.

```sh
npm run demo:cluster        # runs the scenario and rewrites evidence/t6-cluster.json
```

## Crash recovery, backups and log integrity (goals 3–5)
- **Crash recovery:** every multi-step change (setup, revoke, rotation, restore) ends in one atomic
  replace of the authenticated state file, so a crash leaves the complete old or the complete new
  state. Tested by killing the process just before and just after a rotation commits: reads
  succeed on a consistent key version, revoked identities stay revoked, and the dead process's
  lock is broken by PID check within milliseconds.
- **Rollback/truncation detection:** the state records a version counter and the audit-log head it
  was saved against; every audit record carries the state version it saw; a signed `audit.head.json`
  tracks the newest record. Restoring an older `state.json` (e.g. to undo a revocation) or cutting
  records off the log makes every request fail closed with `integrity_failure`.
- **Signed key-event log:** each record (setup, decision, revocation, rotation, restore) is
  hash-chained and signed with ML-DSA-65; user text is always a JSON field value, so it cannot
  create a fake record or change the recorded actor. Operators verify with `npm run ops -- verify-log`
  (only `keys/audit.pub` is needed to verify an exported log).
- **Backups:** `npm run ops -- backup <file>` writes state + log with a SHA-256 digest and ML-DSA
  signature (never the master key). `restore` verifies digest, signature and the state MAC before
  touching live data and reports `digest_mismatch`, `bad_signature` or `state_invalid`. Revocations
  made after the backup are carried into the restored state, so a restore never re-enables anyone.
- **Control plane:** refuses to load a published policy older than its private epoch high-water mark.

## End-to-end messaging (goals 9–12)
`core/messaging/protocol.ts`. Identities are ML-DSA-65 keys from the trusted directory (control-plane policy).
- **Handshake:** each side uses fresh ephemeral **X25519 + ML-KEM-768** keys; session keys =
  HKDF-SHA-256(X25519 secret ‖ ML-KEM secret, salt = transcript hash). Secure unless *both* exchanges
  are broken (hybrid). Both parties sign the full transcript with their identity key, so substituting
  any ephemeral key is detected.
- **Recipient binding & replay:** every chunk is AES-256-GCM with associated data (session, sender,
  recipient, message ID, sequence, chunk index/total) rebuilt from the receiver's own view, so a
  re-addressed or altered chunk fails authentication; a delivered message ID is never delivered again.
- **Forward secrecy:** identity keys only sign; ephemeral private keys live only inside the handshake
  and session keys are zeroed on `close()`. Tested: with both stolen identity keys and the recorded
  transcript, an attacker can only create a new session with unrelated keys and cannot decrypt.
- **Per-message ratchet (forward secrecy within a session):** each direction has a chain key CK;
  every message uses MK = HMAC-SHA-256(CK, 0x01) and moves on to CK' = HMAC-SHA-256(CK, 0x02), and MK and
  the old CK are zeroed right after use. Stealing the live chain state therefore does not decrypt
  earlier messages of the same session. Out-of-order delivery keeps at most 256 skipped message keys
  (each used once, then erased; unused ones expire after 5 min), and a far-ahead or forged sequence
  number is rejected without burning keys. Resumption starts fresh chains. Tests: `tests/messaging.test.ts`.
- **Loss / reordering:** chunks may arrive in any order; a message is delivered only when all chunks
  authenticate. A tampered chunk discards the whole message, and messages still incomplete after 30 s
  are discarded; both are reported as delivery failures.
- **Session resumption (supported):** a resume request must be signed by the same identity key the
  session was established with; a different identity, a re-keyed identity, a replayed request, or an
  identity the current policy no longer authorizes is refused. Each resumption derives fresh keys.

## Detector accuracy (goals 6–8)
`npm run demo:detector` scores the rule-based detector on seeded synthetic logs (practice CSV format; ground truth never given to the detector). Results in `evidence/t5-detector.json` and `docs/EVIDENCE.md`: per-incident F1 1 (standard) and 1 (hard: borrowed approvals, successful lateral hops, late-delivered approvals), median time-to-alert 1560.25 / 1092.25 ms, 0 false alerts per 1,000 benign events. These are upper bounds: the generator models the same documented environment the rules encode.

Every detector alert names the identity, services and events, and carries its **MITRE ATT&CK** mapping: unapproved role change → T1098 Account Manipulation + T1078 Valid Accounts (TA0004 Privilege Escalation); admin change without matching approval → T1098; unexpected service-edge sequence → TA0008 Lateral Movement / T1021 Remote Services; borrowed, expired or out-of-scope approval, and access outside a role's baseline → T1078 Valid Accounts. The mapping is context for analysts; it does not change detection (metrics identical).

## Operator console (demo)
```sh
cd dashboard && npm install && npm run dev     # http://localhost:3000
```
Runs the real adapter and ops CLI (whitelisted actions only, state in `<os temp>/tbv-dashboard`): lost-device flow with the signed decision trail and a reason for every allow/deny; log verification, key rotation and a live rollback attack that fails closed; cluster propagation evidence; detector metrics and explained alerts on a fresh synthetic log.

Three views, built for a two-laptop demo:
- **Console** (`/`): guided walkthrough and checklist (both kept server-side, so a refresh or a second
  screen sees the same session); the **Nodes** page is an interactive network map of the live cluster:
  three node processes pull the signed policy from the control plane over HTTP; drag nodes, click one to
  cut or restore its link or stop it, and watch signed updates travel and nodes switch allow/deny.
- **Attack Lab** (`/lab`, laptop A): 8 storyboards attack the *running* service one real step per key
  press (stolen phone, replay, forged policy, rolling back the disk, cutting the log and swapping its
  key, probing → quarantine, injection and `__proto__`, protected_read abuse), each showing the checks in
  the order the code runs them and the evidence; destructive ones end by recovering from a signed
  backup. 5 more replay sandboxed attacks. `npm run ops -- lab-catalog | lab-start <id> | lab-step <run>`.
- **Live Monitor** (`/monitor`, laptop B): read-only big screen: live/fail-closed status, the signed
  audit log in plain language as it lands, security alerts, the network map and the current Lab step.

Two laptops: the console binds to 127.0.0.1 only. On laptop A run `npm run dev` (or `npm run build &&
npm run start`) and `npm run lan`; laptop B opens the printed `http://<laptop-A-IP>:3001/monitor`
(allow Node through the firewall on a private network). The LAN gateway forwards pages and read-only
actions and refuses every state-changing action, so nobody else on the Wi-Fi can drive the demo.

## Self-defence, witness and Attack Lab
- **Detect and respond** (core/defense/guard.ts): the service watches its own traffic and writes ML-DSA-signed security_alert records for probing (one identity denied on 3+ files in 60 s), malformed-input bursts, use of a revoked identity, request-ID reuse and integrity failures (npm run ops -- alerts). With TRACK4_AUTO_QUARANTINE=1 a probing identity is also quarantined; this is off by default because actor IDs in the judged interface are caller-supplied, so automatic lockout could be abused to lock out a real user.
- **External witness** (core/audit/witness.ts): with TRACK4_WITNESS_DIR set, every signed audit-log head is mirrored to a location the service host does not control; rolling back state and log together is then detected and refused.
- **Attack scorecard** (npm run ops -- attack all, and the console page): 15 real attacks (stolen device key, replay, forged and rolled-back policy, state rollback, consistent state+log rollback, log edit, truncation with the head deleted, verification-key swap, signing-key deletion, log injection, prototype pollution and path traversal, malformed flood, probing, protected_read abuse) run against fresh instances; all are blocked, with evidence. The live Attack Lab (below) runs 8 of them against the running service. Regression tests keep both that way.

## Performance
One request = one Node process. Measured in Docker `node:24.11.1` on a native filesystem:
about **37 ms per `read` including process start** (bare `node` start-up is ~12 ms; ~11 ms of
that is the ML-DSA signature on the audit record and the signed log head). The
TypeScript in `core/` is shipped pre-stripped in `dist/` (`npm run build`), which halves start-up
compared with stripping types at runtime.

## Closed since the red-team review
- **Stale-lock race (F1) and Windows lock contention (F5):** a dead holder's lock is broken by exactly
  one waiter (exclusive `.lock.break`, re-checked), and a holder only removes a lock carrying its own
  random token. 4 rounds × 20 parallel requests over a dead-PID lock keep the chain valid.
- **Fail-open log checks (F2, F3, F4):** after `setup`, a missing signed head, a missing or swapped
  verification key (its SHA-256 is pinned inside the MAC'd state), a missing signing key, or a corrupt
  log line all give `integrity_failure`; no record is ever written unsigned. Alerts raised while the
  log is untrusted go to a signed side file, never into the log. Tests: `tests/redteam.test.ts`.
- **Cluster restarts and bootstrap:** replay nonces and in-flight transfers persist per node; a
  provisioned node (`trust.json`: anchor + epoch floor + policy hash) never trusts an older policy.
- **Network transport:** policy is distributed over HTTP (`core/cluster/transport.ts`) and messages
  travel over TCP between separate processes (`core/messaging/net.ts`); see
  `npm run ops -- net-cluster-bench` and `npm run ops -- net-messaging`.

## Known limitations
- The master key lives on the same host as the data unless `TRACK4_MASTER_KEY` is supplied by an
  external KMS; an attacker with full host access and the key file can decrypt. No HSM.
- `setup` is a trusted operator operation and resets all state.
- Rolling back state and log together is detected only when the external witness is configured
  (`TRACK4_WITNESS_DIR`); the audit signing key lives on the same host as the log.
- A reused `request_id` is only honoured as an identical retry of an earlier allow; any other reuse
  is denied without content.
- The network transports run over plain HTTP/TCP on loopback in the demo: integrity and
  confidentiality come from ML-DSA signatures and the hybrid handshake, not from TLS; mutual TLS
  and multi-host deployment are the next step. A node directory writable by an attacker can still
  lose its replay file (replays then stay bounded by the ±30 s timestamp window).
- Messaging forward secrecy and resumption rely on Node.js erasing secrets in memory.
- The messaging ratchet is symmetric only: there is no Diffie-Hellman ratchet, so a stolen chain state
  reveals the *later* messages of that session (no post-compromise security) until it is closed or resumed.
- The judged adapter identifies actors by ID only; per-device signatures exist in the cluster layer.
- Denial of service and side channels are out of scope.

## Layout
| Path | What |
|---|---|
| `track4_service.mjs` | Judging adapter (stdin JSON → stdout JSON) |
| `core/` | TypeScript source: adapter, crypto, keys, state, access policy, audit log, storage |
| `dist/` | Generated JavaScript actually executed (`npm run build`; a test fails if it is stale) |
| `tests/` | Node test runner suites |
| `tools/` | Build script, judge-parity container run, pqcrypto interop check |
| `dashboard/` | Operator console (Next.js) for the demo |
