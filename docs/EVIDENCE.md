# Evidence sheet — Trust, but verify

Runtime for all results: Docker `node:24.11.1` (OpenSSL 3.5.4), offline, read-only root, unless noted.
Reproduce: `npm test`, `bash tools/judge-parity.sh <Track-4-Toolkit>`, `python tools/check_protected_read.py`,
`npm run demo:cluster`. Status values follow the toolkit template: `measured`, `partial`, `not tested`.

| # | Goal | Expected behaviour (defined before the run) | Result / status / evidence |
|---|---|---|---|
| — | Judged adapter (lost device) | Owner allowed; after `revoke` the owner is denied with no content; peer unaffected; audit returns the recorded decision; fake key never printed | **measured** — official validator 22/22 PASS; `tests/adapter.test.ts` |
| — | `protected_read` | Authorized: ML-KEM-768 ciphertext to the caller's raw key + `HMAC-SHA-256(ss, challenge‖body)`; denied: no ciphertext/proof | **measured** — `tools/check_protected_read.py` (Python pqcrypto 0.4.0 decapsulates, proof matches) 3/3 PASS |
| 1 | Key rotation | New version active immediately; old version accepted for new requests until `cutoff = rotation + grace` (**grace applies**, 30 s default, 1.5 s in demo), then rejected on every node; transfers begun before cutoff finish (≤120 s); stored assets re-encrypted atomically | **measured** — `evidence/t6-cluster.json` steps "rotation grace period", "after cutoff", "in-flight transfer after cutoff", "new key" all PASS on 3 node processes; `tests/cluster.test.ts`, `tests/rotation.test.ts` |
| 2 | Revocation across nodes | A revoked device/identity is refused by every node; propagation = publish → last node adoption (after signature check and persistence); owner re-enrols, others keep access | **measured** — `evidence/t6-cluster.json`: median **19 ms**, max **21 ms** (15 samples, 20 ms polling, shared host clock); re-enrolment and unaffected-user steps PASS |
| 3 | Crash recovery | After a crash mid-rotation: consistent authorized key version, revocations kept, data readable, lock of the dead process recovered | **measured** — `tests/recovery.test.ts`: process SIGKILLed before and after the commit point → v1 / v2 respectively, revoked user still denied, read succeeds < 3 s; dead-PID lock test in `tests/adapter.test.ts` |
| 4 | Backup integrity | Damaged/unsigned backup is detected and reported; live state untouched; only verified material restored; later revocations survive restore | **measured** — `tests/recovery.test.ts`: `digest_mismatch`, `bad_signature`, `unreadable` reported; restore after revocation keeps it (`carried_revocations = 1`) |
| 5 | Log integrity | Each event keeps identity, action, record boundary; user text cannot forge a record or actor; operators can verify | **measured** — injection test (newline + JSON in actor → 1 record, actor preserved); edited record → `first_bad_seq`; truncation and state rollback → `integrity_failure`; ML-DSA signatures checked by `npm run ops -- verify-log` |
| 6 | Routine vs suspicious | Approved change (matching approval scope/time) not alerted; unexpected role change and follow-up access flagged with reasons | **measured** — `evidence/t5-detector.json` (`npm run demo:detector`, 10 seeds, per-incident): standard F1 **1**, precision 1, recall 1, median time-to-alert **1560.25 ms**, **0** false alerts / 1,000 benign (5990 benign, 120 incidents); hard mode (borrowed approvals, allowed lateral hops, approvals delivered 90 s late) F1 **1**, TTA 1092.25 ms, 0 FP/1k. Limit: synthetic data follows the same documented environment the rules encode, so these are upper bounds; practice labels also reproduced (`tests/detector.test.ts`) |
| 7 | Lateral movement | Unexpected service-edge sequence (evt-010..012) grouped by actor/session/window with identity, services, events and rule; denied ≠ compromised; isolated denial not a sequence | **measured** — practice tests PASS; synthetic denied chains and allowed (successful) hops through billing/archive all alerted with identity, services, events and rule (goal 6 evidence) |
| 8 | Clock differences | Raw timestamps preserved; corrected time = event − offset; delayed delivery and ambiguous order flagged, not guessed | **measured** — practice-data tests (evt-013/014 order, evt-015 offset) PASS; supported range documented in README |
| 9 | Replay + recipient binding | Only the intended recipient can read; duplicates and altered recipient/sender/position rejected | **measured** — `tests/messaging.test.ts` (duplicate, re-addressed, altered seq/msg id, third party); cluster nonce replay in `tests/cluster.test.ts` |
| 10 | Forward secrecy | Exposure of long-term identity keys after a session ends does not reveal its content | **measured (claim + test)** — ephemeral X25519 + ML-KEM-768, keys zeroed on close; test with stolen identity key + recorded transcript fails to decrypt. Limit: relies on erasure of process memory |
| 11 | Delivery under loss/reordering | Complete authenticated messages delivered in any order; incomplete or invalid discarded and reported | **measured** — `tests/messaging.test.ts` (out-of-order, tampered chunk, 30 s expiry → reported failures) |
| 12 | Session resumption | **Supported.** Bound to the authenticated peer; different/re-keyed identity, replayed request or revoked identity refused | **measured** — `tests/messaging.test.ts` resumption test |

## Performance
`read` ≈ 37 ms per request including Node process start (bare Node ≈ 12 ms), native Linux filesystem.
Revocation propagation: see goal 2.

## Known limitations
See README "Known limitations": master key and audit signing key share the host (KMS env var
supported); consistent rollback of state **and** log together needs an external witness; cluster
transport is a shared filesystem; messaging is a tested library without network transport.

## Live security assessment readiness
| Evidence | Result |
|---|---|
| Attack Lab: `npm run ops -- attack all`, `tests/attacks.test.ts` | 12/12 real attacks blocked (stolen device key, replay, forged policy, policy rollback, state rollback, consistent state+log rollback with witness, log edit, log injection, `__proto__`/path traversal, malformed flood, probing, protected_read abuse) |
| Self-defence: `tests/defense.test.ts` | Signed `security_alert` records for probing, malformed bursts, revoked-identity use, request-ID reuse, integrity failures; opt-in quarantine (`TRACK4_AUTO_QUARANTINE=1`) |
| External witness: `tests/witness.test.ts` | Consistent rollback of state and log detected with `TRACK4_WITNESS_DIR`; undetected without it (documented limitation) |
| Messaging run: `npm run ops -- messaging` | Conversation delivered out of order; replay, re-addressing, tampering, sequence change, session hijack and stolen-identity-key decryption all rejected |
