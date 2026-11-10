"""A verifier that trusts the client's signed bytes. DO NOT USE OUTSIDE THE ATTACK LAB.

What it gets right: challenges are single use (each challenge ID can be submitted once), and it checks a real
ECDSA P-256 signature with the public key bound to the challenge.
What it gets wrong, on purpose:
  * it verifies the signature over a message *the client sends*, instead of rebuilding the kg-auth-v1 bytes
    from the challenge it stored;
  * it then acts on the action parsed from that client message, and never checks that the message names the
    challenge being consumed.
So a captured (message, signature) pair for an old unlock can be attached to any fresh challenge ID and still
"verify". It also never checks expiry.

The hardened engine never accepts signed bytes from the client (see app.security.protocol).
"""

from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass

from app.security.encoding import EncodingError, b64url_decode, b64url_encode, new_id
from app.security.protocol import DOMAIN_TAG, ProtocolError, SignedFields, load_public_key, verify_signature

_FIELD_COUNT = 7  # version, vehicle_id, key_id, challenge_id, nonce, action, expires_at


@dataclass(frozen=True)
class _Issued:
    fields: SignedFields
    spki: str


def parse_signed_message(message: bytes) -> list[str]:
    """Split kg-auth-v1 bytes into their framed fields. Only the vulnerable verifier ever needs this."""
    if not message.startswith(DOMAIN_TAG):
        raise ProtocolError("MESSAGE_MALFORMED", "missing domain tag")
    out, pos = [], len(DOMAIN_TAG)
    for _ in range(_FIELD_COUNT):
        if pos + 4 > len(message):
            raise ProtocolError("MESSAGE_MALFORMED", "truncated")
        (n,) = struct.unpack(">I", message[pos : pos + 4])
        pos += 4
        if pos + n > len(message):
            raise ProtocolError("MESSAGE_MALFORMED", "truncated")
        out.append(message[pos : pos + n].decode("utf-8", errors="replace"))
        pos += n
    if pos != len(message):
        raise ProtocolError("MESSAGE_MALFORMED", "trailing bytes")
    return out


class ClientBytesVerifier:
    """In-memory, per-scenario state only. One instance per scenario run."""

    def __init__(self) -> None:
        self._challenges: dict[str, _Issued] = {}
        self._used: set[str] = set()
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

    def verify(self, *, challenge_id: str, signed_message: str, signature: str) -> tuple[str, str | None]:
        issued = self._challenges.get(challenge_id)
        if issued is None:
            return "deny", "CHALLENGE_NOT_FOUND"
        if challenge_id in self._used:
            return "deny", "CHALLENGE_CONSUMED"
        self._used.add(challenge_id)  # single use: consumed before the signature check, like the real engine
        try:
            message = b64url_decode(signed_message)
            key, _ = load_public_key(issued.spki)
            # BUG (intentional): verifies over the client's bytes, not encode_signed_message(issued.fields).
            ok = verify_signature(key, message, signature)
            fields = parse_signed_message(message)
        except EncodingError:
            return "deny", "MESSAGE_MALFORMED"
        except ProtocolError as exc:
            return "deny", exc.code
        if not ok:
            return "deny", "SIGNATURE_INVALID"
        # BUG (intentional): the action comes from the client's message, which may belong to another challenge.
        action = fields[5]
        if action not in ("unlock", "lock"):
            return "deny", "ACTION_INVALID"
        self.lock_state = "unlocked" if action == "unlock" else "locked"
        return "allow", None
