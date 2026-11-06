"""kg-auth-v1 encoding, key parsing and signature verification (D-001)."""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from app.security.encoding import EncodingError, b64url_decode, b64url_encode, is_valid_id, new_id
from app.security.protocol import (
    DOMAIN_TAG,
    ProtocolError,
    SignedFields,
    encode_signed_message,
    load_public_key,
    verify_signature,
)

VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "docs" / "test-vectors" / "kg-auth-v1.json").read_text()
)
BASE = VECTORS["encoding"][0]["fields"]


# --- encoding ---------------------------------------------------------------


@pytest.mark.parametrize("vec", VECTORS["encoding"], ids=lambda v: v["name"])
def test_encoding_matches_vectors(vec):
    assert encode_signed_message(SignedFields(**vec["fields"])).hex() == vec["message_hex"]


def test_message_starts_with_domain_tag():
    assert encode_signed_message(SignedFields(**BASE)).startswith(DOMAIN_TAG)
    assert VECTORS["domain_tag_hex"] == DOMAIN_TAG.hex()


def test_fields_are_length_framed():
    msg = encode_signed_message(SignedFields(**BASE))
    (first_len,) = struct.unpack(">I", msg[len(DOMAIN_TAG) : len(DOMAIN_TAG) + 4])
    assert msg[len(DOMAIN_TAG) + 4 : len(DOMAIN_TAG) + 4 + first_len] == b"kg-auth-v1"


def test_framing_prevents_field_boundary_collisions():
    # Under naive concatenation these two would produce identical bytes.
    a = SignedFields(**{**BASE, "vehicle_id": "veh_AB", "key_id": "Ckey"})
    b = SignedFields(**{**BASE, "vehicle_id": "veh_A", "key_id": "BCkey"})
    assert encode_signed_message(a) != encode_signed_message(b)


def test_every_field_changes_the_message():
    base = encode_signed_message(SignedFields(**BASE))
    variants = {
        "vehicle_id": "veh_ZZZZZZZZZZZZZZZZZZZZZZ",
        "key_id": "key_ZZZZZZZZZZZZZZZZZZZZZZ",
        "challenge_id": "chl_ZZZZZZZZZZZZZZZZZZZZZZ",
        "nonce": b64url_encode(bytes(32)),
        "action": "lock",
        "expires_at": BASE["expires_at"] + 1,
    }
    for name, value in variants.items():
        assert encode_signed_message(SignedFields(**{**BASE, name: value})) != base, name


@pytest.mark.parametrize(
    "override, code",
    [
        ({"action": "open_trunk"}, "ACTION_INVALID"),
        ({"action": "UNLOCK"}, "ACTION_INVALID"),
        ({"expires_at": -1}, "EXPIRY_INVALID"),
        ({"expires_at": True}, "EXPIRY_INVALID"),
        ({"expires_at": "1793923200"}, "EXPIRY_INVALID"),
        ({"nonce": b64url_encode(bytes(31))}, "NONCE_INVALID"),
        ({"nonce": b64url_encode(bytes(32)) + "="}, "NONCE_INVALID"),
        ({"vehicle_id": ""}, "FIELD_INVALID"),
        ({"key_id": "x" * 257}, "FIELD_INVALID"),
    ],
)
def test_encoder_rejects_invalid_fields(override, code):
    with pytest.raises(ProtocolError) as exc:
        encode_signed_message(SignedFields(**{**BASE, **override}))
    assert exc.value.code == code


# --- base64url / ids --------------------------------------------------------


@pytest.mark.parametrize("bad", ["AAA=", "AA+A", "AA/A", "A", "AB", " AAAA", "AAAA\n"])
def test_b64url_decode_is_strict(bad):
    with pytest.raises(EncodingError):
        b64url_decode(bad)


def test_ids_are_opaque_and_validated():
    vid = new_id("veh")
    assert is_valid_id(vid, "veh")
    assert not is_valid_id(vid, "key")
    assert not is_valid_id("veh_1", "veh")
    assert new_id("veh") != new_id("veh")


# --- public keys ------------------------------------------------------------


def _spki(key) -> str:
    return b64url_encode(
        key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )


def test_accepts_p256_spki():
    key, der = load_public_key(VECTORS["verify"]["public_key_spki_b64url"])
    assert isinstance(key.curve, ec.SECP256R1)
    assert len(der) == 91


@pytest.mark.parametrize(
    "make, code",
    [
        (lambda: _spki(ec.generate_private_key(ec.SECP384R1())), "PUBLIC_KEY_UNSUPPORTED"),
        (lambda: _spki(ec.generate_private_key(ec.SECP256K1())), "PUBLIC_KEY_UNSUPPORTED"),
        (lambda: _spki(ed25519.Ed25519PrivateKey.generate()), "PUBLIC_KEY_UNSUPPORTED"),
        (lambda: b64url_encode(b"not a key"), "PUBLIC_KEY_INVALID"),
        (lambda: "%%%", "PUBLIC_KEY_INVALID"),
    ],
)
def test_rejects_unsupported_or_invalid_keys(make, code):
    with pytest.raises(ProtocolError) as exc:
        load_public_key(make())
    assert exc.value.code == code


# --- signatures -------------------------------------------------------------


@pytest.mark.parametrize("case", VECTORS["verify"]["cases"], ids=lambda c: c["name"])
def test_verify_vectors(case):
    key, _ = load_public_key(VECTORS["verify"]["public_key_spki_b64url"])
    message = bytes.fromhex(case["message_hex"])
    if case["expected"] == "malformed":
        with pytest.raises(ProtocolError) as exc:
            verify_signature(key, message, case["signature"])
        assert exc.value.code == "SIGNATURE_MALFORMED"
    else:
        assert verify_signature(key, message, case["signature"]) is (case["expected"] == "valid")
