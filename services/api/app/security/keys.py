"""Public-key registry. Only public keys are ever received or stored."""

from __future__ import annotations

from sqlalchemy import Connection, and_, insert, select

from app.models.tables import digital_keys
from app.security.encoding import b64url_encode, new_id
from app.security.protocol import fingerprint, load_public_key


def enroll_key(conn: Connection, *, lab_id: str, vehicle_id: str, spki_b64url: str, label: str, now: int) -> str:
    """Validate and store a P-256 public key bound to one vehicle. Raises ProtocolError on a bad key."""
    _, der = load_public_key(spki_b64url)
    key_id = new_id("key")
    conn.execute(
        insert(digital_keys).values(
            id=key_id,
            lab_id=lab_id,
            vehicle_id=vehicle_id,
            label=label,
            public_key=der,
            fingerprint=fingerprint(der),
            status="active",
            created_at=now,
        )
    )
    return key_id


def get_key_spki(conn: Connection, *, lab_id: str, key_id: str) -> str | None:
    der = conn.execute(
        select(digital_keys.c.public_key).where(and_(digital_keys.c.id == key_id, digital_keys.c.lab_id == lab_id))
    ).scalar()
    return None if der is None else b64url_encode(der)
