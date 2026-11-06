"""Browser → server interoperability: a signature produced by Web Crypto (apps/web/lib/crypto.ts)
must verify against the server's own reconstruction of the canonical bytes."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from app.security.protocol import SignedFields, encode_signed_message, load_public_key, verify_signature

REPO = Path(__file__).resolve().parents[3]
WEBCRYPTO_VECTOR = REPO / "docs" / "test-vectors" / "kg-auth-v1-webcrypto.json"


def _check(vec: dict) -> None:
    fields = SignedFields(**vec["fields"])
    message = encode_signed_message(fields)
    assert message.hex() == vec["message_hex"], "TS and Python disagree on canonical bytes"
    key, _ = load_public_key(vec["public_key_spki_b64url"])
    assert verify_signature(key, message, vec["signature"])
    flipped = "lock" if fields.action == "unlock" else "unlock"
    tampered = SignedFields(**{**vec["fields"], "action": flipped})
    assert not verify_signature(key, encode_signed_message(tampered), vec["signature"])


def test_committed_webcrypto_vector_verifies():
    _check(json.loads(WEBCRYPTO_VECTOR.read_text()))


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_fresh_webcrypto_signature_verifies(tmp_path):
    """Generate a brand-new Web Crypto key and signature now, so the committed vector can't go stale silently."""
    web = REPO / "apps" / "web"
    out = tmp_path / "vec.json"
    script = (
        "import { exportPublicKey, generateDeviceKey, signMessage } from './lib/crypto.ts';"
        "import { encodeSignedMessage, toHex } from './lib/encoding.ts';"
        "import { readFileSync, writeFileSync } from 'node:fs';"
        "const f = JSON.parse(readFileSync('../../docs/test-vectors/kg-auth-v1.json','utf8')).encoding[1].fields;"
        "const k = await generateDeviceKey();"
        "const m = encodeSignedMessage({vehicleId:f.vehicle_id,keyId:f.key_id,challengeId:f.challenge_id,"
        "nonce:f.nonce,action:f.action,expiresAt:f.expires_at});"
        "writeFileSync(process.argv[1], JSON.stringify({public_key_spki_b64url: await exportPublicKey(k.publicKey),"
        "fields:f, message_hex: toHex(m), signature: await signMessage(k.privateKey, m)}));"
    )
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", script, str(out)],
        cwd=web, capture_output=True, text=True, timeout=60,
    )
    if proc.returncode != 0 and "ERR_UNKNOWN_FILE_EXTENSION" in proc.stderr:
        pytest.skip("node too old for TypeScript type stripping")
    assert proc.returncode == 0, proc.stderr
    _check(json.loads(out.read_text()))
