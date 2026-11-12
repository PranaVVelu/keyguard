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

accounts = Table(
    "accounts",
    metadata,
    Column("id", String, primary_key=True),
    Column("display_name", String, nullable=False),
    Column("user_handle", LargeBinary(32), nullable=False, unique=True),  # WebAuthn user.id: random, not personal data
    Column("created_at", Integer, nullable=False),
)

labs = Table(
    "labs",
    metadata,
    Column("id", String, primary_key=True),
    Column("token_hash", LargeBinary(32), nullable=False),  # SHA-256(lab_token); the token itself is never stored
    Column("created_at", Integer, nullable=False),
    Column("expires_at", Integer, nullable=False),
    # Saved labs (D-012): the owning account, if any. Ownership never transfers.
    Column("account_id", String, ForeignKey("accounts.id"), index=True),
    Column("saved_at", Integer),
)

passkeys = Table(
    "passkeys",
    metadata,
    Column("id", String, primary_key=True),  # WebAuthn credential ID, base64url
    Column("account_id", String, ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False, index=True),
    Column("public_key", LargeBinary, nullable=False),  # COSE public key from the attestation
    Column("sign_count", Integer, nullable=False),
    Column("created_at", Integer, nullable=False),
    Column("last_used_at", Integer),
)

webauthn_challenges = Table(
    "webauthn_challenges",
    metadata,
    Column("id", String, primary_key=True),
    Column("purpose", String, nullable=False),
    Column("challenge", LargeBinary(32), nullable=False),
    # Registration only: the pending account's details, bound to this challenge.
    Column("display_name", String),
    Column("user_handle", LargeBinary(32)),
    Column("created_at", Integer, nullable=False),
    Column("expires_at", Integer, nullable=False),
    Column("consumed_at", Integer),
    CheckConstraint("purpose IN ('register', 'login')", name="ck_webauthn_purpose"),
)

sessions = Table(
    "sessions",
    metadata,
    Column("id", String, primary_key=True),
    Column("token_hash", LargeBinary(32), nullable=False, unique=True),  # SHA-256 of the cookie value
    Column("account_id", String, ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False, index=True),
    Column("created_at", Integer, nullable=False),
    Column("expires_at", Integer, nullable=False),
    Column("revoked_at", Integer),
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
    Column("credential_type", String, nullable=False, server_default="phone"),
    # kg-fob-v1 only: highest counter accepted so far (D-010). Always 0 for phone and card keys.
    Column("last_counter", Integer, nullable=False, server_default="0"),
    Column("created_at", Integer, nullable=False),
    Column("revoked_at", Integer),
    CheckConstraint("status IN ('active', 'revoked')", name="ck_key_status"),
    CheckConstraint("credential_type IN ('phone', 'card', 'fob')", name="ck_key_credential_type"),
    CheckConstraint("last_counter >= 0", name="ck_key_last_counter"),
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
    # Integer surrogate key gives a stable insertion order for events written in the same second.
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column("id", String, nullable=False, unique=True),
    Column("lab_id", String, ForeignKey("labs.id", ondelete="CASCADE"), nullable=False, index=True),
    Column("vehicle_id", String),
    Column("key_id", String),
    Column("event_type", String, nullable=False),
    Column("outcome", String, nullable=False),
    Column("reason", Text),
    Column("duration_ms", Integer),
    Column("created_at", Integer, nullable=False),
)

lab_runs = Table(
    "lab_runs",
    metadata,
    Column("id", String, primary_key=True),
    Column("lab_id", String, ForeignKey("labs.id", ondelete="CASCADE"), nullable=False, index=True),
    Column("scenario", String, nullable=False),
    Column("mode", String, nullable=False),
    Column("expected_result", String, nullable=False),
    Column("actual_result", String, nullable=False),
    Column("actual_reason", String),
    Column("duration_ms", Integer),
    Column("created_at", Integer, nullable=False),
    CheckConstraint("mode IN ('vulnerable', 'hardened')", name="ck_lab_run_mode"),
)
