"""Hardened authentication engine (spec §5, D-003).

Order of operations, all inside one database transaction:

  1. Load the challenge, scoped to the lab.            → CHALLENGE_NOT_FOUND
  2. Consume it atomically (burn on any attempt, O-2).  → CHALLENGE_CONSUMED / CHALLENGE_EXPIRED
  3. The request's key must be the challenge's key.     → KEY_MISMATCH
  4. The key must exist, be active, and be bound to
     the challenge's vehicle.                           → KEY_UNKNOWN / KEY_REVOKED / VEHICLE_MISMATCH
  5. Verify the signature over bytes rebuilt from the
     stored challenge row (never client-supplied).      → SIGNATURE_MALFORMED / SIGNATURE_INVALID
  6. Apply the vehicle state change.

Consuming before checking means the challenge is spent even when a later check fails, and
the conditional UPDATE leaves no gap between checking and consuming. Deny decisions still
commit, so the burn and the event persist; only an allow changes vehicle state.

Cryptographic validity is necessary but not sufficient: steps 3–4 are authorization.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from sqlalchemy import Engine, and_, select, update

from app.models.tables import vehicles
from app.security.challenges import ConsumeResult, consume_challenge, get_challenge
from app.security.encoding import b64url_encode
from app.security.events import record_event
from app.security.keys import get_key_auth_info
from app.security.protocol import ProtocolError, encode_signed_message, load_public_key, verify_signature

STEPS = (
    "challenge_found",
    "challenge_consumed",
    "key_matches_challenge",
    "key_active_and_bound",
    "signature_valid",
    "state_committed",
)

NEW_STATE = {"unlock": "unlocked", "lock": "locked"}


@dataclass
class TraceStep:
    step: str
    status: str  # "pass" | "fail" | "skipped"
    detail: str | None = None


@dataclass
class Decision:
    decision: str  # "allow" | "deny"
    reason: str | None
    challenge_id: str
    vehicle_id: str | None
    action: str | None
    lock_state: str | None
    duration_ms: int
    trace: list[TraceStep] = field(default_factory=list)


class _Trace:
    def __init__(self) -> None:
        self.steps: list[TraceStep] = []

    def ok(self, step: str, detail: str | None = None) -> None:
        self.steps.append(TraceStep(step, "pass", detail))

    def fail(self, step: str, detail: str) -> None:
        self.steps.append(TraceStep(step, "fail", detail))
        done = {s.step for s in self.steps}
        self.steps.extend(TraceStep(s, "skipped") for s in STEPS if s not in done)


def authenticate(
    engine: Engine,
    *,
    lab_id: str,
    challenge_id: str,
    key_id: str,
    signature: str,
    clock: Callable[[], int],
) -> Decision:
    started = time.perf_counter()
    trace = _Trace()
    vehicle_id: str | None = None
    action: str | None = None

    with engine.begin() as conn:
        now = clock()

        def finish(decision: str, reason: str | None, lock_state: str | None) -> Decision:
            duration_ms = round((time.perf_counter() - started) * 1000)
            record_event(
                conn,
                lab_id=lab_id,
                event_type=f"authenticate_{action}" if action else "authenticate",
                outcome=decision,
                vehicle_id=vehicle_id,
                key_id=key_id if decision == "allow" else None,
                reason=reason,
                duration_ms=duration_ms,
                now=now,
            )
            return Decision(decision, reason, challenge_id, vehicle_id, action, lock_state, duration_ms, trace.steps)

        def deny(step: str, reason: str) -> Decision:
            trace.fail(step, reason)
            current = None
            if vehicle_id:
                current = conn.execute(select(vehicles.c.lock_state).where(vehicles.c.id == vehicle_id)).scalar()
            return finish("deny", reason, current)

        # 1. challenge exists in this lab
        chl = get_challenge(conn, lab_id=lab_id, challenge_id=challenge_id)
        if chl is None:
            return deny("challenge_found", "CHALLENGE_NOT_FOUND")
        vehicle_id, action = chl.vehicle_id, chl.action
        trace.ok("challenge_found", f"{chl.action} · {chl.vehicle_id}")

        # 2. atomic single-use consumption
        consumed = consume_challenge(conn, lab_id=lab_id, challenge_id=challenge_id, now=now)
        if consumed is not ConsumeResult.CONSUMED:
            return deny("challenge_consumed", consumed.value)
        trace.ok("challenge_consumed", f"expires_at {chl.expires_at}, now {now}")

        # 3. key named in the request is the key the challenge was issued to
        if key_id != chl.key_id:
            return deny("key_matches_challenge", "KEY_MISMATCH")
        trace.ok("key_matches_challenge")

        # 4. authorization: key exists, is active, is bound to this vehicle
        info = get_key_auth_info(conn, lab_id=lab_id, key_id=key_id)
        if info is None:
            return deny("key_active_and_bound", "KEY_UNKNOWN")
        if info.status != "active":
            return deny("key_active_and_bound", "KEY_REVOKED")
        if info.vehicle_id != chl.vehicle_id:
            return deny("key_active_and_bound", "VEHICLE_MISMATCH")
        trace.ok("key_active_and_bound")

        # 5. signature over server-rebuilt canonical bytes
        try:
            public_key, _ = load_public_key(b64url_encode(info.spki_der))
            valid = verify_signature(public_key, encode_signed_message(chl.signed_fields()), signature)
        except ProtocolError as exc:
            return deny("signature_valid", "SIGNATURE_MALFORMED" if exc.code == "SIGNATURE_MALFORMED" else exc.code)
        if not valid:
            return deny("signature_valid", "SIGNATURE_INVALID")
        trace.ok("signature_valid", "ECDSA P-256 / SHA-256")

        # 6. commit the authorized state transition in the same transaction as the consumption
        new_state = NEW_STATE[chl.action]
        conn.execute(
            update(vehicles)
            .where(and_(vehicles.c.id == chl.vehicle_id, vehicles.c.lab_id == lab_id))
            .values(lock_state=new_state)
        )
        trace.ok("state_committed", new_state)
        return finish("allow", None, new_state)
