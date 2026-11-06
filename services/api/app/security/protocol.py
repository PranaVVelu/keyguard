"""kg-auth-v1 signed-message encoding and ECDSA P-256 verification (D-001).

The server never verifies bytes supplied by the client: it rebuilds the canonical
message from its own stored challenge row and checks the client's signature over it.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from app.security.encoding import EncodingError, b64url_decode

DOMAIN_TAG = b"KEYGUARD-AUTH\x00\x01"
PROTOCOL_VERSION = "kg-auth-v1"
ACTIONS = frozenset({"unlock", "lock"})
NONCE_BYTES = 32
MAX_FIELD_BYTES = 256

# Order of the P-256 group.
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class ProtocolError(ValueError):
    """Input that cannot be part of a valid kg-auth-v1 exchange. ``code`` is a stable error code."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass(frozen=True)
class SignedFields:
    vehicle_id: str
    key_id: str
    challenge_id: str
    nonce: str  # unpadded base64url of NONCE_BYTES random bytes
    action: str
    expires_at: int  # Unix seconds


def _frame(value: str) -> bytes:
    raw = value.encode("utf-8")
    if not raw or len(raw) > MAX_FIELD_BYTES:
        raise ProtocolError("FIELD_INVALID", "field empty or too long")
    return struct.pack(">I", len(raw)) + raw


def encode_signed_message(fields: SignedFields) -> bytes:
    if fields.action not in ACTIONS:
        raise ProtocolError("ACTION_INVALID")
    if type(fields.expires_at) is not int or fields.expires_at < 0:
        raise ProtocolError("EXPIRY_INVALID")
    try:
        nonce_ok = len(b64url_decode(fields.nonce)) == NONCE_BYTES
    except EncodingError:
        nonce_ok = False
    if not nonce_ok:
        raise ProtocolError("NONCE_INVALID")

    return DOMAIN_TAG + b"".join(
        _frame(v)
        for v in (
            PROTOCOL_VERSION,
            fields.vehicle_id,
            fields.key_id,
            fields.challenge_id,
            fields.nonce,
            fields.action,
            str(fields.expires_at),
        )
    )


def load_public_key(spki_b64url: str) -> tuple[ec.EllipticCurvePublicKey, bytes]:
    """Parse an SPKI DER P-256 public key; returns (key, canonical SPKI bytes)."""
    try:
        der = b64url_decode(spki_b64url)
        key = serialization.load_der_public_key(der)
    except (EncodingError, ValueError, TypeError) as exc:
        raise ProtocolError("PUBLIC_KEY_INVALID") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ProtocolError("PUBLIC_KEY_UNSUPPORTED", "P-256 required")
    canonical = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if canonical != der:
        raise ProtocolError("PUBLIC_KEY_INVALID", "non-canonical SPKI")
    return key, canonical


def fingerprint(spki_der: bytes) -> str:
    return hashlib.sha256(spki_der).hexdigest()


def p1363_to_der(signature_b64url: str) -> bytes:
    """Convert a Web Crypto (IEEE P1363 ``r||s``) signature to DER, range-checking r and s."""
    try:
        raw = b64url_decode(signature_b64url)
    except EncodingError as exc:
        raise ProtocolError("SIGNATURE_MALFORMED") from exc
    if len(raw) != 64:
        raise ProtocolError("SIGNATURE_MALFORMED", "expected 64 bytes")
    r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    if not (0 < r < P256_N and 0 < s < P256_N):
        raise ProtocolError("SIGNATURE_MALFORMED", "r or s out of range")
    return encode_dss_signature(r, s)


def verify_signature(public_key: ec.EllipticCurvePublicKey, message: bytes, signature_b64url: str) -> bool:
    """True only for a valid signature. Malformed signatures raise ProtocolError.

    High-S and low-S forms are both accepted: single use is enforced by challenge
    ID, never by signature uniqueness (D-001).
    """
    der = p1363_to_der(signature_b64url)
    try:
        public_key.verify(der, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True
