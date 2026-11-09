"""A naive verifier with the classic replay bug. DO NOT USE OUTSIDE THE ATTACK LAB.

What it gets right: it verifies a real ECDSA P-256 signature over the same kg-auth-v1 bytes.
What it gets wrong, on purpose:
  * it never marks a challenge as used, so a captured valid response can be replayed forever;
  * it never checks expiry.

This shows the spec's invariant that cryptographic validity is necessary but not sufficient.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from app.security.encoding import b64url_encode, new_id
from app.security.protocol import ProtocolError, SignedFields, encode_signed_message, load_public_key, verify_signature


@dataclass(frozen=True)
class _Issued:
    fields: SignedFields
    spki: str


class VulnerableVerifier:
    """In-memory, per-scenario state only. One instance per scenario run."""

    def __init__(self) -> None:
        self._challenges: dict[str, _Issued] = {}
        self.lock_state = "locked"

    def issue(self, *, vehicle_id: str, key_id: str, spki_b64url: str, action: str, now: int, ttl: int = 30) -> SignedFields:
        fields = SignedFields(
            vehicle_id=vehicle_id,
            key_id=key_id,
            challenge_id=new_id("chl"),
            nonce=b64url_encode(secrets.token_bytes(32)),
            action=action,
            expires_at=now + ttl,
        )
        self._challenges[fields.challenge_id] = _Issued(fields, spki_b64url)
        return fields

    def verify(self, *, challenge_id: str, signature: str) -> tuple[str, str | None]:
        issued = self._challenges.get(challenge_id)
        if issued is None:
            return "deny", "CHALLENGE_NOT_FOUND"
        try:
            key, _ = load_public_key(issued.spki)
            ok = verify_signature(key, encode_signed_message(issued.fields), signature)
        except ProtocolError as exc:
            return "deny", exc.code
        if not ok:
            return "deny", "SIGNATURE_INVALID"
        # BUG (intentional): no single-use consumption, no expiry check.
        self.lock_state = "unlocked" if issued.fields.action == "unlock" else "locked"
        return "allow", None
