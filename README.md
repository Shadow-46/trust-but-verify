# Trust, but verify

Post-quantum, zero-trust protection for files and messages while keys, devices
and user permissions change — plus an explainable detector that shows an operator
when an identity gains unexpected privileges or moves between services.

Built for Yugaantar DevForge 2026, Track 4.

> Work in progress: the protected-resource service, key rotation and multi-node revocation are
> complete; crash recovery, backups, signed logs, messaging and the detector are being added.

## Clean-machine setup
Requirements: **Node.js 24.11.1 or newer**. Nothing else — the service uses only
Node built-ins, so there is no `npm install` for the core.

```sh
git clone https://github.com/Shadow-46/trust-but-verify.git
cd trust-but-verify
npm test                     # 26 tests (one is Linux-only and skipped on Windows)
```

Run one request (the judging worker does exactly this, one process per request):
```sh
echo '{"op":"setup","owners":{"brief":"maya"},"contents":{"brief":"demo note"},"disabled":[],"key_material":"synthetic-only"}' | node track4_service.mjs
echo '{"op":"read","actor":"maya","asset":"brief","request_id":"r01"}' | node track4_service.mjs
```
State is kept in `$TRACK4_STATE_DIR`, or `<os temp dir>/trust-but-verify` if unset.

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
status, identity revocation, signature, timestamp (±30 s) and nonce (replay), then key version.

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

## Performance
One request = one Node process. Measured in Docker `node:24.11.1` on a native filesystem:
about **26 ms per `read` including process start** (bare `node` start-up is ~12 ms). The
TypeScript in `core/` is shipped pre-stripped in `dist/` (`npm run build`), which halves start-up
compared with stripping types at runtime.

## Known limitations (so far)
- The master key lives on the same host as the data unless `TRACK4_MASTER_KEY` is supplied by an
  external KMS; an attacker with full host access and the key file can decrypt.
- `setup` is a trusted operator operation and resets all state.
- The audit chain detects edited or reordered records, but not a truncated tail, and a host
  attacker could rebuild an unsigned chain. Planned: ML-DSA-signed records with the chain head
  stored inside the authenticated state.
- The state HMAC detects edits but not **rollback** to an older, validly authenticated
  `state.json` (which could undo a revocation). Planned: a monotonic version counter bound to the
  audit chain head.
- A reused `request_id` is only honoured as an identical retry of an earlier allow; any other reuse
  is denied without content.
- Cluster demo: node processes sync policy over a shared filesystem (no network listener); requests
  are authorized against each node's own stored, re-verified policy. Replay nonces and the in-flight
  transfer table are in memory and are lost when a node restarts.
- A brand-new node accepts any genuinely signed policy as its first one (no freshness bound yet).
- The judged adapter identifies actors by ID only; per-device signatures exist in the cluster layer.
- A request killed while holding the state lock is detected by PID and its lock is broken
  immediately; a live but hung holder is broken after 3 s.

## Layout
| Path | What |
|---|---|
| `track4_service.mjs` | Judging adapter (stdin JSON → stdout JSON) |
| `core/` | TypeScript source: adapter, crypto, keys, state, access policy, audit log, storage |
| `dist/` | Generated JavaScript actually executed (`npm run build`; a test fails if it is stale) |
| `tests/` | Node test runner suites |
| `tools/` | Build script, judge-parity container run, pqcrypto interop check |
| `dashboard/` | Operator console (Next.js) for the demo |
