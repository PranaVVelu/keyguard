"""Accounts, passkeys (WebAuthn), sessions and saved labs (F12, D-012).

WebAuthn verification is delegated to the vetted `py_webauthn` library. This module owns everything around it:
single-use challenges, sign-count clone detection, hashed session tokens and saved-lab ownership.

Every verify function consumes its challenge FIRST, in the same transaction, and returns an error code instead
of raising, so the transaction commits and a failed attempt still burns the challenge (same rule as D-003).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, Engine, and_, delete, func, insert, select, update
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse, WebAuthnException
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.models.tables import accounts, labs, passkeys, security_events, sessions, vehicles, webauthn_challenges
from app.security.cleanup import delete_labs_where
from app.security.encoding import EncodingError, b64url_decode, b64url_encode, is_valid_id, new_id

RP_NAME = "KeyGuard (educational demo)"
WEBAUTHN_TTL_SECONDS = 5 * 60
SESSION_TTL_SECONDS = 12 * 60 * 60
SAVED_LAB_TTL_SECONDS = 30 * 24 * 60 * 60
UNSAVED_LAB_TTL_SECONDS = 24 * 60 * 60
SAVED_LAB_LIMIT = 10
ALGORITHMS = [COSEAlgorithmIdentifier.ECDSA_SHA_256, COSEAlgorithmIdentifier.EDDSA]


@dataclass(frozen=True)
class RelyingParty:
    rp_id: str
    origin: str


class AccountError(Exception):
    """A stable, machine-readable failure. Routes map `code` to an HTTP status."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _hash(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii")).digest()


# --- WebAuthn challenges ----------------------------------------------------------------------------


def _store_challenge(conn: Connection, *, purpose: str, now: int, **extra: Any) -> tuple[str, bytes]:
    challenge_id, challenge = new_id("wac"), secrets.token_bytes(32)
    conn.execute(
        insert(webauthn_challenges).values(
            id=challenge_id, purpose=purpose, challenge=challenge, created_at=now,
            expires_at=now + WEBAUTHN_TTL_SECONDS, **extra,
        )
    )
    return challenge_id, challenge


def _consume_challenge(conn: Connection, *, challenge_id: str, purpose: str, now: int):
    """Atomically mark a challenge used. Returns its row, or None if unknown, wrong purpose, used or expired."""
    if not is_valid_id(challenge_id, "wac"):
        return None
    t = webauthn_challenges.c
    claimed = conn.execute(
        update(webauthn_challenges)
        .where(and_(t.id == challenge_id, t.purpose == purpose, t.consumed_at.is_(None), t.expires_at > now))
        .values(consumed_at=now)
    ).rowcount
    if claimed != 1:
        return None
    return conn.execute(select(webauthn_challenges).where(t.id == challenge_id)).mappings().one()


# --- Registration -----------------------------------------------------------------------------------


def begin_registration(engine: Engine, rp: RelyingParty, *, display_name: str, now: int) -> dict:
    user_handle = secrets.token_bytes(32)
    with engine.begin() as conn:
        challenge_id, challenge = _store_challenge(
            conn, purpose="register", now=now, display_name=display_name, user_handle=user_handle
        )
    options = generate_registration_options(
        rp_id=rp.rp_id,
        rp_name=RP_NAME,
        user_name=display_name,
        user_id=user_handle,
        user_display_name=display_name,
        challenge=challenge,
        timeout=WEBAUTHN_TTL_SECONDS * 1000,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        supported_pub_key_algs=ALGORITHMS,
    )
    return {"challenge_id": challenge_id, "options": json.loads(options_to_json(options))}


def finish_registration(
    engine: Engine, rp: RelyingParty, *, challenge_id: str, credential: dict, now: int
) -> tuple[str | None, str | None, str | None]:
    """Returns (account_id, session_token, error_code). Exactly one of account/session or error is set."""
    with engine.begin() as conn:
        row = _consume_challenge(conn, challenge_id=challenge_id, purpose="register", now=now)
        if row is None:
            return None, None, "CHALLENGE_INVALID"
        try:
            verified = verify_registration_response(
                credential=credential,
                expected_challenge=row["challenge"],
                expected_rp_id=rp.rp_id,
                expected_origin=rp.origin,
                require_user_verification=True,
                supported_pub_key_algs=ALGORITHMS,
            )
        except (InvalidRegistrationResponse, WebAuthnException, ValueError, KeyError, TypeError):
            return None, None, "PASSKEY_INVALID"
        credential_id = b64url_encode(verified.credential_id)
        if conn.execute(select(passkeys.c.id).where(passkeys.c.id == credential_id)).first():
            return None, None, "PASSKEY_ALREADY_REGISTERED"

        account_id = new_id("acct")
        conn.execute(insert(accounts).values(
            id=account_id, display_name=row["display_name"], user_handle=row["user_handle"], created_at=now,
        ))
        conn.execute(insert(passkeys).values(
            id=credential_id, account_id=account_id, public_key=verified.credential_public_key,
            sign_count=verified.sign_count, created_at=now, last_used_at=now,
        ))
        token = _create_session(conn, account_id=account_id, now=now)
    return account_id, token, None


# --- Login ------------------------------------------------------------------------------------------


def begin_login(engine: Engine, rp: RelyingParty, *, now: int) -> dict:
    with engine.begin() as conn:
        challenge_id, challenge = _store_challenge(conn, purpose="login", now=now)
    options = generate_authentication_options(
        rp_id=rp.rp_id,
        challenge=challenge,
        timeout=WEBAUTHN_TTL_SECONDS * 1000,
        user_verification=UserVerificationRequirement.REQUIRED,
        # No allow_credentials: discoverable credentials, so the server never reveals which accounts exist.
    )
    return {"challenge_id": challenge_id, "options": json.loads(options_to_json(options))}


def finish_login(
    engine: Engine, rp: RelyingParty, *, challenge_id: str, credential: dict, now: int
) -> tuple[str | None, str | None, str | None]:
    """Returns (account_id, session_token, error_code)."""
    with engine.begin() as conn:
        row = _consume_challenge(conn, challenge_id=challenge_id, purpose="login", now=now)
        if row is None:
            return None, None, "CHALLENGE_INVALID"
        credential_id = credential.get("id") if isinstance(credential, dict) else None
        if not isinstance(credential_id, str):
            return None, None, "PASSKEY_INVALID"
        stored = conn.execute(
            select(passkeys.c.id, passkeys.c.account_id, passkeys.c.public_key, passkeys.c.sign_count, accounts.c.user_handle)
            .join(accounts, accounts.c.id == passkeys.c.account_id)
            .where(passkeys.c.id == credential_id)
        ).first()
        if stored is None:
            return None, None, "PASSKEY_UNKNOWN"

        # The authenticator's user handle, if sent, must belong to the account that owns this credential.
        handle = (credential.get("response") or {}).get("userHandle")
        if handle:
            try:
                if not hmac.compare_digest(b64url_decode(handle), stored.user_handle):
                    return None, None, "PASSKEY_INVALID"
            except EncodingError:
                return None, None, "PASSKEY_INVALID"

        try:
            verified = verify_authentication_response(
                credential=credential,
                expected_challenge=row["challenge"],
                expected_rp_id=rp.rp_id,
                expected_origin=rp.origin,
                credential_public_key=stored.public_key,
                credential_current_sign_count=stored.sign_count,
                require_user_verification=True,
            )
        except InvalidAuthenticationResponse as exc:
            # py_webauthn rejects a counter that didn't increase: a cloned authenticator (D-012, T24).
            return None, None, "PASSKEY_CLONED" if "sign count" in str(exc).lower() else "PASSKEY_INVALID"
        except (WebAuthnException, ValueError, KeyError, TypeError):
            return None, None, "PASSKEY_INVALID"

        conn.execute(
            update(passkeys).where(passkeys.c.id == stored.id).values(sign_count=verified.new_sign_count, last_used_at=now)
        )
        token = _create_session(conn, account_id=stored.account_id, now=now)
    return stored.account_id, token, None


# --- Sessions ---------------------------------------------------------------------------------------


def _create_session(conn: Connection, *, account_id: str, now: int) -> str:
    token = b64url_encode(secrets.token_bytes(32))
    conn.execute(insert(sessions).values(
        id=new_id("ses"), token_hash=_hash(token), account_id=account_id, created_at=now,
        expires_at=now + SESSION_TTL_SECONDS,
    ))
    return token


def account_for_session(conn: Connection, *, token: str | None, now: int) -> str | None:
    """The account a session cookie belongs to, or None if missing, unknown, revoked or expired."""
    if not token or len(token) > 128:
        return None
    try:
        digest = _hash(token)
    except UnicodeEncodeError:
        return None
    row = conn.execute(
        select(sessions.c.account_id, sessions.c.expires_at, sessions.c.revoked_at).where(sessions.c.token_hash == digest)
    ).first()
    if row is None or row.revoked_at is not None or row.expires_at <= now:
        return None
    return row.account_id


def revoke_session(engine: Engine, *, token: str | None, now: int) -> None:
    if not token or len(token) > 128:
        return
    with engine.begin() as conn:
        conn.execute(
            update(sessions)
            .where(and_(sessions.c.token_hash == _hash(token), sessions.c.revoked_at.is_(None)))
            .values(revoked_at=now)
        )


# --- Account summary and deletion -------------------------------------------------------------------


def account_summary(conn: Connection, *, account_id: str, now: int) -> dict:
    acct = conn.execute(
        select(accounts.c.id, accounts.c.display_name, accounts.c.created_at).where(accounts.c.id == account_id)
    ).mappings().one()
    keys = conn.execute(
        select(passkeys.c.id, passkeys.c.created_at, passkeys.c.last_used_at)
        .where(passkeys.c.account_id == account_id)
        .order_by(passkeys.c.created_at)
    ).mappings().all()
    event_counts = (
        select(security_events.c.lab_id, func.count().label("n")).group_by(security_events.c.lab_id).subquery()
    )
    saved = conn.execute(
        select(
            labs.c.id, labs.c.saved_at, labs.c.expires_at, vehicles.c.name, vehicles.c.lock_state,
            func.coalesce(event_counts.c.n, 0).label("events"),
        )
        .join(vehicles, vehicles.c.lab_id == labs.c.id)
        .outerjoin(event_counts, event_counts.c.lab_id == labs.c.id)
        .where(and_(labs.c.account_id == account_id, labs.c.expires_at > now))
        .order_by(labs.c.saved_at.desc())
    ).mappings().all()
    return {
        "account": dict(acct),
        "passkeys": [
            {"id_prefix": k["id"][:8], "created_at": k["created_at"], "last_used_at": k["last_used_at"]} for k in keys
        ],
        "saved_labs": [
            {
                "lab_id": r["id"], "saved_at": r["saved_at"], "expires_at": r["expires_at"],
                "vehicle_name": r["name"], "lock_state": r["lock_state"], "event_count": r["events"],
            }
            for r in saved
        ],
    }


def delete_account(engine: Engine, *, account_id: str) -> int:
    """Delete the account, its passkeys, its sessions and every saved lab with all of its data."""
    with engine.begin() as conn:
        labs_deleted = delete_labs_where(conn, labs.c.account_id == account_id)
        conn.execute(delete(sessions).where(sessions.c.account_id == account_id))
        conn.execute(delete(passkeys).where(passkeys.c.account_id == account_id))
        conn.execute(delete(accounts).where(accounts.c.id == account_id))
    return labs_deleted


# --- Saved labs -------------------------------------------------------------------------------------


def save_lab(engine: Engine, *, account_id: str, lab_id: str, now: int) -> None:
    """Attach a lab (already authorized by its bearer token) to this account and extend its retention."""
    with engine.begin() as conn:
        owner = conn.execute(select(labs.c.account_id).where(labs.c.id == lab_id)).scalar_one()
        if owner == account_id:
            conn.execute(update(labs).where(labs.c.id == lab_id).values(expires_at=now + SAVED_LAB_TTL_SECONDS))
            return
        if owner is not None:
            raise AccountError("LAB_ALREADY_SAVED")
        count = conn.execute(
            select(func.count()).select_from(labs).where(and_(labs.c.account_id == account_id, labs.c.expires_at > now))
        ).scalar_one()
        if count >= SAVED_LAB_LIMIT:
            raise AccountError("SAVED_LAB_LIMIT_REACHED")
        # The conditional WHERE makes the claim atomic: two accounts racing to save the same lab can't both win.
        claimed = conn.execute(
            update(labs)
            .where(and_(labs.c.id == lab_id, labs.c.account_id.is_(None)))
            .values(account_id=account_id, saved_at=now, expires_at=now + SAVED_LAB_TTL_SECONDS)
        ).rowcount
        if claimed != 1:
            raise AccountError("LAB_ALREADY_SAVED")


def open_saved_lab(engine: Engine, *, account_id: str, lab_id: str, now: int) -> tuple[str, int]:
    """Issue a fresh lab token for a saved lab this account owns; older tokens stop working (D-012)."""
    if not is_valid_id(lab_id, "lab"):
        raise AccountError("LAB_NOT_FOUND")
    token = b64url_encode(secrets.token_bytes(32))
    expires_at = now + SAVED_LAB_TTL_SECONDS
    with engine.begin() as conn:
        updated = conn.execute(
            update(labs)
            .where(and_(labs.c.id == lab_id, labs.c.account_id == account_id, labs.c.expires_at > now))
            .values(token_hash=_hash(token), expires_at=expires_at)
        ).rowcount
    if updated != 1:
        raise AccountError("LAB_NOT_FOUND")  # unknown, expired and someone else's lab look the same
    return token, expires_at


def unsave_lab(engine: Engine, *, account_id: str, lab_id: str, now: int) -> None:
    if not is_valid_id(lab_id, "lab"):
        raise AccountError("LAB_NOT_FOUND")
    with engine.begin() as conn:
        current = conn.execute(
            select(labs.c.expires_at).where(and_(labs.c.id == lab_id, labs.c.account_id == account_id))
        ).scalar()
        if current is None:
            raise AccountError("LAB_NOT_FOUND")
        conn.execute(
            update(labs)
            .where(labs.c.id == lab_id)
            .values(account_id=None, saved_at=None, expires_at=min(current, now + UNSAVED_LAB_TTL_SECONDS))
        )
