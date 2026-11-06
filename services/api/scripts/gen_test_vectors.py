"""Generate docs/test-vectors/kg-auth-v1.json.

Run once; the committed JSON is the canonical vector set shared by the Python and
TypeScript test suites. Encoding vectors are deterministic. Verify vectors use a
freshly generated key (Web Crypto ECDSA is randomized, so signatures can't be reproduced),
and the private key is discarded.

    uv run python scripts/gen_test_vectors.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from app.security.encoding import b64url_decode, b64url_encode  # noqa: E402
from app.security.protocol import P256_N, SignedFields, encode_signed_message  # noqa: E402
from helpers import SimulatedClientKey  # noqa: E402

OUT = Path(__file__).resolve().parents[3] / "docs" / "test-vectors" / "kg-auth-v1.json"

BASE = {
    "vehicle_id": "veh_AAAAAAAAAAAAAAAAAAAAAA",
    "key_id": "key_BBBBBBBBBBBBBBBBBBBBBB",
    "challenge_id": "chl_CCCCCCCCCCCCCCCCCCCCCC",
    "nonce": b64url_encode(bytes(range(32))),
    "action": "unlock",
    "expires_at": 1793923200,
}


def encoding_vectors() -> list[dict]:
    cases = [
        ("unlock", BASE),
        ("lock", {**BASE, "action": "lock"}),
        ("non-ascii-vehicle-id", {**BASE, "vehicle_id": "veh_é"}),
        ("expiry-zero", {**BASE, "expires_at": 0}),
    ]
    return [
        {"name": name, "fields": f, "message_hex": encode_signed_message(SignedFields(**f)).hex()}
        for name, f in cases
    ]


def flip_last_byte(sig: str) -> str:
    raw = bytearray(b64url_decode(sig))
    raw[-1] ^= 0x01
    return b64url_encode(bytes(raw))


def high_s(sig: str) -> str:
    raw = b64url_decode(sig)
    s = int.from_bytes(raw[32:], "big")
    return b64url_encode(raw[:32] + (P256_N - s).to_bytes(32, "big"))


def verify_vectors() -> dict:
    key = SimulatedClientKey()
    msg = encode_signed_message(SignedFields(**BASE))
    other = encode_signed_message(SignedFields(**{**BASE, "action": "lock"}))
    sig = key.sign_p1363(msg)
    r_eq_n = b64url_encode(P256_N.to_bytes(32, "big") + b64url_decode(sig)[32:])
    return {
        "public_key_spki_b64url": key.spki_b64url,
        "cases": [
            {"name": "valid", "message_hex": msg.hex(), "signature": sig, "expected": "valid"},
            {"name": "valid-high-s-form", "message_hex": msg.hex(), "signature": high_s(sig), "expected": "valid"},
            {"name": "tampered-signature", "message_hex": msg.hex(), "signature": flip_last_byte(sig), "expected": "invalid"},
            {"name": "wrong-action-message", "message_hex": other.hex(), "signature": sig, "expected": "invalid"},
            {"name": "truncated-signature", "message_hex": msg.hex(), "signature": sig[:-4], "expected": "malformed"},
            {"name": "r-equals-n", "message_hex": msg.hex(), "signature": r_eq_n, "expected": "malformed"},
            {"name": "all-zero", "message_hex": msg.hex(), "signature": b64url_encode(bytes(64)), "expected": "malformed"},
        ],
    }


def main() -> None:
    doc = {
        "protocol": "kg-auth-v1",
        "spec": "docs/DECISIONS.md#d-001",
        "domain_tag_hex": b"KEYGUARD-AUTH\x00\x01".hex(),
        "encoding": encoding_vectors(),
        "verify": verify_vectors(),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
