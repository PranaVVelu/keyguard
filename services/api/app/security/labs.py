"""Lab creation and bearer-token authorization (D-002)."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from sqlalchemy import Connection, insert, select

from app.models.tables import labs, vehicles
from app.security.encoding import b64url_encode, is_valid_id, new_id

LAB_TTL_SECONDS = 24 * 60 * 60
DEFAULT_VEHICLE_NAME = "KG Coupe (fictional)"


@dataclass(frozen=True)
class NewLab:
    lab_id: str
    lab_token: str  # returned to the client once; only its hash is stored
    vehicle_id: str
    expires_at: int


def _hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii")).digest()


def create_lab(conn: Connection, *, now: int) -> NewLab:
    lab_id = new_id("lab")
    token = b64url_encode(secrets.token_bytes(32))
    expires_at = now + LAB_TTL_SECONDS
    conn.execute(insert(labs).values(id=lab_id, token_hash=_hash_token(token), created_at=now, expires_at=expires_at))
    vehicle_id = new_id("veh")
    conn.execute(
        insert(vehicles).values(
            id=vehicle_id, lab_id=lab_id, name=DEFAULT_VEHICLE_NAME, lock_state="locked", created_at=now
        )
    )
    return NewLab(lab_id=lab_id, lab_token=token, vehicle_id=vehicle_id, expires_at=expires_at)


def authorize_lab(conn: Connection, *, lab_id: str, bearer_token: str | None, now: int) -> bool:
    """True only for an existing, unexpired lab whose token matches.

    Callers must turn every False into the same LAB_NOT_FOUND response, so nobody can tell
    an unknown lab from a wrong token or an expired lab.
    """
    if not is_valid_id(lab_id, "lab") or not bearer_token or len(bearer_token) > 128:
        return False
    try:
        presented = _hash_token(bearer_token)
    except UnicodeEncodeError:
        return False
    row = conn.execute(select(labs.c.token_hash, labs.c.expires_at).where(labs.c.id == lab_id)).first()
    if row is None:
        # Still do a comparison so an unknown lab costs about the same time as a wrong token.
        hmac.compare_digest(presented, b"\x00" * 32)
        return False
    return hmac.compare_digest(presented, row.token_hash) and row.expires_at > now


def lock_lab(conn: Connection, *, lab_id: str) -> None:
    """Serialize count-then-insert limit checks for one lab (keys, open challenges).

    PostgreSQL READ COMMITTED would otherwise let concurrent requests all see the old count and all insert.
    SQLite writes are already serialized by BEGIN IMMEDIATE, and SQLAlchemy omits FOR UPDATE there.
    """
    conn.execute(select(labs.c.id).where(labs.c.id == lab_id).with_for_update())
