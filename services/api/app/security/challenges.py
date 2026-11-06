"""Challenge issuance and atomic single-use consumption (D-003)."""

from __future__ import annotations

import enum
import secrets
from dataclasses import dataclass

from sqlalchemy import Connection, and_, insert, select, update

from app.models.tables import challenges
from app.security.encoding import b64url_encode, new_id
from app.security.protocol import ACTIONS, NONCE_BYTES, ProtocolError, SignedFields

CHALLENGE_TTL_SECONDS = 30


@dataclass(frozen=True)
class Challenge:
    id: str
    lab_id: str
    vehicle_id: str
    key_id: str
    nonce: str
    action: str
    expires_at: int
    consumed_at: int | None

    def signed_fields(self) -> SignedFields:
        return SignedFields(
            vehicle_id=self.vehicle_id,
            key_id=self.key_id,
            challenge_id=self.id,
            nonce=self.nonce,
            action=self.action,
            expires_at=self.expires_at,
        )


class ConsumeResult(enum.Enum):
    CONSUMED = "CONSUMED"
    NOT_FOUND = "CHALLENGE_NOT_FOUND"
    ALREADY_CONSUMED = "CHALLENGE_CONSUMED"
    EXPIRED = "CHALLENGE_EXPIRED"


def issue_challenge(
    conn: Connection, *, lab_id: str, vehicle_id: str, key_id: str, action: str, now: int
) -> Challenge:
    """Store a fresh, unused challenge. The caller has already checked the vehicle/key belong to the lab."""
    if action not in ACTIONS:
        raise ProtocolError("ACTION_INVALID")
    row = Challenge(
        id=new_id("chl"),
        lab_id=lab_id,
        vehicle_id=vehicle_id,
        key_id=key_id,
        nonce=b64url_encode(secrets.token_bytes(NONCE_BYTES)),
        action=action,
        expires_at=now + CHALLENGE_TTL_SECONDS,
        consumed_at=None,
    )
    conn.execute(insert(challenges).values(**row.__dict__, created_at=now))
    return row


def get_challenge(conn: Connection, *, lab_id: str, challenge_id: str) -> Challenge | None:
    row = conn.execute(
        select(challenges).where(and_(challenges.c.id == challenge_id, challenges.c.lab_id == lab_id))
    ).mappings().first()
    if row is None:
        return None
    return Challenge(**{k: row[k] for k in Challenge.__dataclass_fields__})


def consume_challenge(conn: Connection, *, lab_id: str, challenge_id: str, now: int) -> ConsumeResult:
    """Mark a challenge used, at most once, even under concurrent callers.

    A single conditional UPDATE does the check and the write together, so there is no gap
    between them (no TOCTOU). Must run inside the caller's transaction so the
    consumption commits or rolls back with the vehicle state change.
    """
    result = conn.execute(
        update(challenges)
        .where(
            and_(
                challenges.c.id == challenge_id,
                challenges.c.lab_id == lab_id,
                challenges.c.consumed_at.is_(None),
                challenges.c.expires_at > now,
            )
        )
        .values(consumed_at=now)
    )
    if result.rowcount == 1:
        return ConsumeResult.CONSUMED

    existing = get_challenge(conn, lab_id=lab_id, challenge_id=challenge_id)
    if existing is None:
        return ConsumeResult.NOT_FOUND
    if existing.consumed_at is not None:
        return ConsumeResult.ALREADY_CONSUMED
    return ConsumeResult.EXPIRED
