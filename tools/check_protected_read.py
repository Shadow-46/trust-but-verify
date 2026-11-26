"""Cross-implementation check of protected_read, playing the role of the judging worker.

Uses the same library as the judging runtime (Python pqcrypto 0.4.0, ML-KEM-768)
to generate a key pair, sends the raw public key to our Node adapter, then
decapsulates the returned ciphertext and recomputes the HMAC proof.

    python -m pip install pqcrypto==0.4.0
    python tools/check_protected_read.py
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

from pqcrypto.kem import ml_kem_768

ENTRY = Path(__file__).resolve().parent.parent / "track4_service.mjs"


def call(state_dir: str, request: dict) -> dict:
    env = {**os.environ, "TRACK4_STATE_DIR": state_dir}
    env.pop("TRACK4_MASTER_KEY", None)
    proc = subprocess.run(
        ["node", str(ENTRY)], input=json.dumps(request), capture_output=True, text=True, env=env, check=False
    )
    return json.loads(proc.stdout)


def main() -> int:
    failures = 0
    with tempfile.TemporaryDirectory() as state_dir:
        body = "protected body " + secrets.token_hex(8)
        assert call(state_dir, {
            "op": "setup", "owners": {"doc": "maya"}, "contents": {"doc": body},
            "disabled": [], "key_material": "synthetic-only",
        }) == {"ready": True}

        public_key, secret_key = ml_kem_768.generate_keypair()
        challenge = "challenge-" + secrets.token_hex(16)
        request = {
            "op": "protected_read", "actor": "maya", "asset": "doc",
            "challenge": challenge, "public_key": base64.b64encode(public_key).decode(),
        }

        reply = call(state_dir, request)
        shared = ml_kem_768.decrypt(secret_key, base64.b64decode(reply["ciphertext"]))
        expected = hmac.new(shared, (challenge + body).encode(), hashlib.sha256).hexdigest()
        ok = hmac.compare_digest(reply.get("proof", ""), expected) and "body" not in reply
        print(("PASS" if ok else "FAIL") + " authorized protected_read: pqcrypto decapsulation + HMAC proof match")
        failures += not ok

        denied = call(state_dir, {**request, "actor": "omar"})
        ok = denied == {"decision": "deny"}
        print(("PASS" if ok else "FAIL") + " unauthorized protected_read: deny without ciphertext or proof")
        failures += not ok

        call(state_dir, {"op": "revoke", "actor": "maya"})
        revoked = call(state_dir, request)
        ok = revoked == {"decision": "deny"}
        print(("PASS" if ok else "FAIL") + " revoked owner protected_read: deny")
        failures += not ok

    print("protected_read interoperability passed." if failures == 0 else f"{failures} check(s) failed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
