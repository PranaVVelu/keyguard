"""Python stand-in for the browser client (mirrors Web Crypto behaviour). Used by tests and the matrix runner."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from app.security.encoding import b64url_encode


class SimulatedClientKey:
    """P-256 key pair, SPKI export, IEEE P1363 (r||s) signatures, as Web Crypto produces."""

    def __init__(self) -> None:
        self._private = ec.generate_private_key(ec.SECP256R1())

    @property
    def spki_b64url(self) -> str:
        der = self._private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return b64url_encode(der)

    def sign_p1363(self, message: bytes) -> str:
        r, s = decode_dss_signature(self._private.sign(message, ec.ECDSA(hashes.SHA256())))
        return b64url_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
