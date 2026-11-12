"""Public-key registry. Only public keys are ever received or stored."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Connection, and_, func, insert, select, update

from app.models.tables import digital_keys, vehicles
from app.security.encoding import b64url_encode, new_id
from app.security.labs import lock_lab
from app.security.protocol import fingerprint, load_public_key

MAX_KEYS_PER_LAB = 10
CREDENTIAL_TYPES = ("phone", "card", "fob")


class EnrollmentError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class KeyRecord:
    id: str
    vehicle_id: str
    label: str
    fingerprint: str
    status: str
    credential_type: str
    last_counter: int
    created_at: int
    revoked_at: int | None


def enroll_key(
    conn: Connection,
    *,
    lab_id: str,
    vehicle_id: str,
    spki_b64url: str,
    label: str,
    now: int,
    credential_type: str = "phone",
) -> str:
    """Validate and store a P-256 public key bound to one vehicle in this lab.

    Raises ProtocolError for a bad key, or EnrollmentError for VEHICLE_NOT_FOUND,
    KEY_ALREADY_ENROLLED or KEY_LIMIT_REACHED.
    """
    if credential_type not in CREDENTIAL_TYPES:
        raise EnrollmentError("CREDENTIAL_TYPE_INVALID")
    _, der = load_public_key(spki_b64url)
    fp = fingerprint(der)
    lock_lab(conn, lab_id=lab_id)  # the key-limit and duplicate checks below must not race

    vehicle_in_lab = conn.execute(
        select(vehicles.c.id).where(and_(vehicles.c.id == vehicle_id, vehicles.c.lab_id == lab_id))
    ).first()
    if vehicle_in_lab is None:
        raise EnrollmentError("VEHICLE_NOT_FOUND")

    in_lab = digital_keys.c.lab_id == lab_id
    if conn.execute(select(digital_keys.c.id).where(and_(in_lab, digital_keys.c.fingerprint == fp))).first():
        raise EnrollmentError("KEY_ALREADY_ENROLLED")
    if conn.execute(select(func.count()).select_from(digital_keys).where(in_lab)).scalar_one() >= MAX_KEYS_PER_LAB:
        raise EnrollmentError("KEY_LIMIT_REACHED")

    key_id = new_id("key")
    conn.execute(
        insert(digital_keys).values(
            id=key_id,
            lab_id=lab_id,
            vehicle_id=vehicle_id,
            label=label,
            public_key=der,
            fingerprint=fp,
            status="active",
            credential_type=credential_type,
            last_counter=0,
            created_at=now,
        )
    )
    return key_id


def list_keys(conn: Connection, *, lab_id: str) -> list[KeyRecord]:
    rows = conn.execute(
        select(
            digital_keys.c.id,
            digital_keys.c.vehicle_id,
            digital_keys.c.label,
            digital_keys.c.fingerprint,
            digital_keys.c.status,
            digital_keys.c.credential_type,
            digital_keys.c.last_counter,
            digital_keys.c.created_at,
            digital_keys.c.revoked_at,
        )
        .where(digital_keys.c.lab_id == lab_id)
        .order_by(digital_keys.c.created_at, digital_keys.c.id)
    ).mappings()
    return [KeyRecord(**r) for r in rows]


@dataclass(frozen=True)
class KeyAuthInfo:
    vehicle_id: str
    status: str
    spki_der: bytes
    credential_type: str
    last_counter: int


def get_key_auth_info(conn: Connection, *, lab_id: str, key_id: str) -> KeyAuthInfo | None:
    row = conn.execute(
        select(
            digital_keys.c.vehicle_id,
            digital_keys.c.status,
            digital_keys.c.public_key,
            digital_keys.c.credential_type,
            digital_keys.c.last_counter,
        ).where(and_(digital_keys.c.id == key_id, digital_keys.c.lab_id == lab_id))
    ).first()
    if row is None:
        return None
    return KeyAuthInfo(
        vehicle_id=row.vehicle_id,
        status=row.status,
        spki_der=row.public_key,
        credential_type=row.credential_type,
        last_counter=row.last_counter,
    )


def get_key_spki(conn: Connection, *, lab_id: str, key_id: str) -> str | None:
    der = conn.execute(
        select(digital_keys.c.public_key).where(and_(digital_keys.c.id == key_id, digital_keys.c.lab_id == lab_id))
    ).scalar()
    return None if der is None else b64url_encode(der)


def revoke_key(conn: Connection, *, lab_id: str, key_id: str, now: int) -> KeyRecord | None:
    """Mark a key revoked. Takes effect immediately: authenticate re-checks status inside its transaction.

    Idempotent: revoking an already-revoked key keeps its original revoked_at. Returns None for an unknown key.
    """
    conn.execute(
        update(digital_keys)
        .where(and_(digital_keys.c.id == key_id, digital_keys.c.lab_id == lab_id, digital_keys.c.status == "active"))
        .values(status="revoked", revoked_at=now)
    )
    return next((k for k in list_keys(conn, lab_id=lab_id) if k.id == key_id), None)
