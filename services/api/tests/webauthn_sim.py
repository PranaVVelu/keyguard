"""A minimal software passkey authenticator for tests (D-012).

Builds real WebAuthn registration and authentication responses: CBOR attestation objects ("none" format),
COSE ES256 public keys, authenticator data with the right flags and counters, and ECDSA signatures over
authenticatorData || SHA-256(clientDataJSON). Knobs let tests produce the specific bad responses they need.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from app.security.encoding import b64url_decode, b64url_encode

UP, UV, AT = 0x01, 0x04, 0x40


class SoftPasskey:
    def __init__(self, *, rp_id: str = "localhost", origin: str = "http://localhost:3000", sign_count: int = 0):
        self.rp_id, self.origin = rp_id, origin
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = secrets.token_bytes(16)
        self.sign_count = sign_count
        self.user_handle: bytes | None = None

    @property
    def id(self) -> str:
        return b64url_encode(self.credential_id)

    def _cose_public_key(self) -> bytes:
        nums = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})

    def _client_data(self, kind: str, challenge: str, origin: str | None) -> bytes:
        return json.dumps(
            {"type": kind, "challenge": challenge, "origin": origin or self.origin, "crossOrigin": False}
        ).encode()

    def create(self, options: dict, *, origin: str | None = None, rp_id: str | None = None, uv: bool = True) -> dict:
        """navigator.credentials.create() → RegistrationResponseJSON."""
        self.user_handle = b64url_decode(options["user"]["id"])
        flags = UP | AT | (UV if uv else 0)
        auth_data = (
            hashlib.sha256((rp_id or self.rp_id).encode()).digest()
            + bytes([flags])
            + struct.pack(">I", self.sign_count)
            + b"\x00" * 16  # AAGUID
            + struct.pack(">H", len(self.credential_id))
            + self.credential_id
            + self._cose_public_key()
        )
        client_data = self._client_data("webauthn.create", options["challenge"], origin)
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": self.id,
            "rawId": self.id,
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url_encode(client_data),
                "attestationObject": b64url_encode(attestation),
                "transports": ["internal"],
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }

    def get(
        self,
        options: dict,
        *,
        origin: str | None = None,
        rp_id: str | None = None,
        uv: bool = True,
        bump: int = 1,
        user_handle: bytes | None | str = "own",
    ) -> dict:
        """navigator.credentials.get() → AuthenticationResponseJSON. `bump` advances the signature counter."""
        self.sign_count += bump
        auth_data = (
            hashlib.sha256((rp_id or self.rp_id).encode()).digest()
            + bytes([UP | (UV if uv else 0)])
            + struct.pack(">I", self.sign_count)
        )
        client_data = self._client_data("webauthn.get", options["challenge"], origin)
        signature = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        handle = self.user_handle if user_handle == "own" else user_handle
        response = {
            "clientDataJSON": b64url_encode(client_data),
            "authenticatorData": b64url_encode(auth_data),
            "signature": b64url_encode(signature),
        }
        if handle is not None:
            response["userHandle"] = b64url_encode(handle)
        return {
            "id": self.id,
            "rawId": self.id,
            "type": "public-key",
            "response": response,
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }
