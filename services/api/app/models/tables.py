"""Database schema (spec §6). Times are integer Unix seconds from the server clock."""

from __future__ import annotations

from sqlalchemy import (
    CheckConstraint,
    Column,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
)

metadata = MetaData()

labs = Table(
    "labs",
    metadata,
    Column("id", String, primary_key=True),
    Column("token_hash", LargeBinary(32), nullable=False),  # SHA-256(lab_token); the token itself is never stored
    Column("created_at", Integer, nullable=False),
    Column("expires_at", Integer, nullable=False),
)

vehicles = Table(
    "vehicles",
    metadata,
    Column("id", String, primary_key=True),
    Column("lab_id", String, ForeignKey("labs.id", ondelete="CASCADE"), nullable=False, index=True),
    Column("name", String, nullable=False),
    Column("lock_state", String, nullable=False),
    Column("created_at", Integer, nullable=False),
    CheckConstraint("lock_state IN ('locked', 'unlocked')", name="ck_vehicle_lock_state"),
)

digital_keys = Table(
    "digital_keys",
    metadata,
    Column("id", String, primary_key=True),
    Column("lab_id", String, ForeignKey("labs.id", ondelete="CASCADE"), nullable=False, index=True),
    Column("vehicle_id", String, ForeignKey("vehicles.id", ondelete="CASCADE"), nullable=False),
    Column("label", String, nullable=False),
    Column("public_key", LargeBinary, nullable=False),  # SPKI DER
    Column("fingerprint", String(64), nullable=False),
    Column("status", String, nullable=False),
    Column("created_at", Integer, nullable=False),
    Column("revoked_at", Integer),
    CheckConstraint("status IN ('active', 'revoked')", name="ck_key_status"),
    UniqueConstraint("lab_id", "fingerprint", name="uq_key_fingerprint_per_lab"),
)

challenges = Table(
    "challenges",
    metadata,
    Column("id", String, primary_key=True),
    Column("lab_id", String, ForeignKey("labs.id", ondelete="CASCADE"), nullable=False),
    Column("vehicle_id", String, ForeignKey("vehicles.id", ondelete="CASCADE"), nullable=False),
    Column("key_id", String, ForeignKey("digital_keys.id", ondelete="CASCADE"), nullable=False),
    Column("nonce", String, nullable=False),
    Column("action", String, nullable=False),
    Column("created_at", Integer, nullable=False),
    Column("expires_at", Integer, nullable=False),
    Column("consumed_at", Integer),
    CheckConstraint("action IN ('unlock', 'lock')", name="ck_challenge_action"),
    Index("ix_challenges_lab_id_id", "lab_id", "id"),
)

security_events = Table(
    "security_events",
    metadata,
    Column("id", String, primary_key=True),
    Column("lab_id", String, ForeignKey("labs.id", ondelete="CASCADE"), nullable=False, index=True),
    Column("vehicle_id", String),
    Column("key_id", String),
    Column("event_type", String, nullable=False),
    Column("outcome", String, nullable=False),
    Column("reason", Text),
    Column("duration_ms", Integer),
    Column("created_at", Integer, nullable=False),
)
