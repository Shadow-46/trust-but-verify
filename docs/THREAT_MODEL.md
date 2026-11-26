# Threat model — Trust, but verify

**Scenario.** Users read protected files and exchange messages from enrolled devices. A device is
lost, a key must rotate, an identity's privileges change. The system must stop the lost device
everywhere, keep everyone else working, protect data against "harvest now, decrypt later", and
leave an auditable, understandable trail for every allow and every block.

## Assets (and the property that matters)
| Asset | Property |
|---|---|
| Protected file bodies | Confidentiality (also against future quantum attackers), integrity |
| Messages in transit | Confidentiality, integrity, recipient binding, freshness |
| Master key, data keys, audit and control-plane signing keys | Confidentiality |
| Access policy: owners, devices, revocations, key versions | Integrity, freshness (no rollback) |
| Audit / key-event log | Integrity, completeness, non-forgeable actor |
| Service availability during rotation and crashes | Availability, consistency |

## Adversaries
1. **Unauthorized caller** — sends arbitrary/malformed requests, other users' IDs, injection payloads.
2. **Holder of a lost or stolen device** — has the device key; tries to keep reading after revocation.
3. **Compromised but valid account** — legitimate credentials, unexpected privilege gain or lateral movement.
4. **Network attacker** — records, replays, reorders, drops, re-addresses or substitutes handshake keys; may later obtain a quantum computer or long-term identity keys.
5. **Local attacker with disk write but no keys** — edits, rolls back or truncates state, logs, backups, policy files; plants symlinks in shared temp.

## Trust boundaries
Request → adapter (validation, identity check, policy decision, audit) · control plane → nodes
(ML-DSA-signed policy, epoch check) · device → node (ML-DSA-signed request) · peer ↔ peer
(signed hybrid handshake) · storage (MAC'd state, AES-GCM bodies, signed log and backups).

## Assumptions
OpenSSL 3.5 primitives (ML-KEM-768, ML-DSA-65, X25519, AES-256-GCM, HKDF/HMAC-SHA-256) are correct;
the control-plane trust anchor and identity public keys are provisioned out of band; key files are
readable only by the service user (0600/0700) or the master key comes from a KMS
(`TRACK4_MASTER_KEY`); node clocks are within ±30 s; `setup` is a trusted operator action.

## Threat → defense → evidence
| Threat | Defense | Evidence |
|---|---|---|
| Lost device keeps access | Device/identity revocation in signed policy; every request re-checked | validator; goal 2 (≤21 ms to all nodes) |
| Harvest now, decrypt later | ML-KEM-768 hybrid with X25519; AES-256 at rest | goals 9–10, `protected_read` interop |
| Stolen keys expose past messages, even within a session | Ephemeral hybrid handshake per session; per-message HMAC-SHA-256 ratchet, message and old chain keys zeroed after use (no DH ratchet: later messages of a compromised session are exposed) | messaging tests (stolen identity keys; stolen live chain state cannot open messages 1..5) |
| Forged / replayed old policy | ML-DSA signature + monotonic epoch; control-plane high-water mark | cluster + recovery tests |
| Undo a revocation on disk | HMAC'd state, version counter bound to signed log head | rollback test → `integrity_failure` |
| Log tampering / fake records | Hash chain + ML-DSA signatures; JSON-field encoding of user text | injection, edit, truncation tests |
| Malformed input, `__proto__`, path tricks | Strict validation, fixed error codes, `Map` storage, no IDs as paths | adapter tests |
| Symlink planting in `/tmp` | Private-dir check (no symlink, owner, 0700) | Linux test in judge parity |
| Crash mid-operation | Single atomic commit, PID-based lock recovery | crash tests |
| Message replay / re-addressing / MITM | AAD binding, duplicate refusal, signed transcript | messaging tests |
| Unexpected privilege change / lateral movement | Explainable rules over approvals + service-edge graph | detector tests (goals 6–8) |
| Delete the log head or swap/delete the log keys to hide records | Head and key mandatory after setup; key hash pinned in MAC'd state; never write unsigned | red-team regression tests (F2–F4) |
| Concurrent requests racing a dead holder's lock | Exclusive, re-checked lock breaking; own-token unlock | 4 × 20 parallel requests test (F1/F5) |
| Node restart used to replay a request or drop a transfer | Nonces and transfers persisted per node | cluster-hardening tests |
| Attack on a node goes unrecorded or unnoticed | Each node keeps its own hash-chained, ML-DSA-signed decision log and raises signed alerts (replay, cross-node replay, bad signature, revoked device, forged/old policy) naming identity, node and event | node-audit tests; live Attack Lab |
| Captured request replayed to a different node | Target node signed into every request (audience binding); other nodes refuse it as `wrong_node` | cluster-hardening test (node-a → node-b/node-c, also after restart) |
| New node fed an old, genuinely signed policy | Provisioned epoch floor + policy hash (`trust.json`) | cluster-hardening tests |
| Network attacker on the policy or message wire | ML-DSA-signed policy over HTTP; signed hybrid handshake + AEAD over TCP; 64 KB frame cap | network tests (forged policy, replay, bit flip, oversize, partition) |

## Exclusions and remaining risks
- **Largest risk:** an attacker with full control of the host (keys + disk) can decrypt and can
  roll back state *and* log consistently unless the external witness is configured (implemented, TRACK4_WITNESS_DIR); master-key theft still needs an external KMS.
- No HSM; key erasure relies on process memory hygiene in Node.
- Network transports are plain HTTP/TCP on loopback in the prototype (security comes from signatures
  and the hybrid handshake, not TLS); multi-host deployment with mutual TLS is the next step.
- Detector accuracy is measured only on public practice data and our synthetic set, not production traffic.
- Denial of service and side channels (timing, power) are out of scope.
