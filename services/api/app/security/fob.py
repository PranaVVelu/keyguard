"""kg-fob-v1 rolling-counter decision engine (D-010, F10).

A fob press carries (vehicle, key, counter, action, signature); there is no server challenge. Everything runs
in ONE transaction, in this order:

  1. key_found              the key exists in this lab                         → KEY_UNKNOWN
  2. key_is_fob             it is a fob credential                             → KEY_TYPE_MISMATCH
  3. key_active_and_bound   active and bound to the requested vehicle          → KEY_REVOKED / VEHICLE_MISMATCH
  4. signature_valid        ECDSA over bytes rebuilt from the stored key ID     → SIGNATURE_MALFORMED / _INVALID
                            and vehicle ID plus the request's counter and action
  5. counter_fresh          conditional UPDATE advances last_counter only if    → COUNTER_REPLAYED /
                            last < counter <= last + FOB_WINDOW                   COUNTER_OUT_OF_WINDOW
  6. state_committed        vehicle lock state updated

The signature is checked BEFORE the counter moves, so only the fob's owner can advance it: unsigned requests
with huge counters can't lock a fob out. Two concurrent presses with the same counter can't both win, because
the counter only advances through one conditional UPDATE.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from sqlalchemy import Engine, and_, select, update

from app.models.tables import digital_keys, vehicles
from app.security.authenticate import NEW_STATE, TraceStep
from app.security.events import record_event
from app.security.keys import get_key_auth_info
from app.security.protocol import FobFields, ProtocolError, encode_fob_message, load_public_key, verify_signature
from app.security.encoding import b64url_encode

FOB_WINDOW = 32  # how far ahead of the last accepted counter a press may be (resync after missed presses)

STEPS = (
    "key_found",
    "key_is_fob",
    "key_active_and_bound",
    "signature_valid",
    "counter_fresh",
    "state_committed",
)


@dataclass
class FobDecision:
    decision: str
    reason: str | None
    key_id: str
    vehicle_id: str | None
    action: str
    counter: int
    last_counter: int | None
    lock_state: str | None
    duration_ms: int
    trace: list[TraceStep] = field(default_factory=list)


def press_fob(
    engine: Engine,
    *,
    lab_id: str,
    key_id: str,
    vehicle_id: str,
    action: str,
    counter: int,
    signature: str,
    clock: Callable[[], int],
) -> FobDecision:
    started = time.perf_counter()
    steps: list[TraceStep] = []

    with engine.begin() as conn:
        now = clock()
        known_vehicle: str | None = None
        last_counter: int | None = None

        def current_lock_state() -> str | None:
            if not known_vehicle:
                return None
            return conn.execute(
                select(vehicles.c.lock_state).where(and_(vehicles.c.id == known_vehicle, vehicles.c.lab_id == lab_id))
            ).scalar()

        def finish(decision: str, reason: str | None, lock_state: str | None) -> FobDecision:
            duration_ms = round((time.perf_counter() - started) * 1000)
            record_event(
                conn,
                lab_id=lab_id,
                event_type=f"fob_{action}",
                outcome=decision,
                vehicle_id=known_vehicle,
                key_id=key_id if decision == "allow" else None,  # same attribution rule as authenticate
                reason=reason,
                duration_ms=duration_ms,
                now=now,
            )
            return FobDecision(
                decision, reason, key_id, known_vehicle, action, counter, last_counter, lock_state, duration_ms, steps
            )

        def deny(step: str, reason: str) -> FobDecision:
            steps.append(TraceStep(step, "fail", reason))
            done = {s.step for s in steps}
            steps.extend(TraceStep(s, "skipped") for s in STEPS if s not in done)
            return finish("deny", reason, current_lock_state())

        # 1-3. key exists, is a fob, active and bound
        info = get_key_auth_info(conn, lab_id=lab_id, key_id=key_id)
        if info is None:
            return deny("key_found", "KEY_UNKNOWN")
        last_counter = info.last_counter
        steps.append(TraceStep("key_found", "pass", info.credential_type))
        if info.credential_type != "fob":
            return deny("key_is_fob", "KEY_TYPE_MISMATCH")
        steps.append(TraceStep("key_is_fob", "pass"))
        if info.status != "active":
            return deny("key_active_and_bound", "KEY_REVOKED")
        if info.vehicle_id != vehicle_id:
            return deny("key_active_and_bound", "VEHICLE_MISMATCH")
        known_vehicle = info.vehicle_id
        steps.append(TraceStep("key_active_and_bound", "pass"))

        # 4. signature over server-rebuilt bytes (stored IDs; the counter and action are what the fob claims)
        try:
            public_key, _ = load_public_key(b64url_encode(info.spki_der))
            message = encode_fob_message(FobFields(info.vehicle_id, key_id, counter, action))
            valid = verify_signature(public_key, message, signature)
        except ProtocolError as exc:
            return deny("signature_valid", "SIGNATURE_MALFORMED" if exc.code == "SIGNATURE_MALFORMED" else exc.code)
        if not valid:
            return deny("signature_valid", "SIGNATURE_INVALID")
        steps.append(TraceStep("signature_valid", "pass", "ECDSA P-256 / SHA-256 over kg-fob-v1"))

        # 5. atomic counter advance: the only way a press can succeed
        advanced = conn.execute(
            update(digital_keys)
            .where(
                and_(
                    digital_keys.c.id == key_id,
                    digital_keys.c.lab_id == lab_id,
                    digital_keys.c.status == "active",
                    digital_keys.c.last_counter < counter,
                    digital_keys.c.last_counter + FOB_WINDOW >= counter,
                )
            )
            .values(last_counter=counter)
        ).rowcount
        if advanced != 1:
            last_counter = conn.execute(
                select(digital_keys.c.last_counter).where(
                    and_(digital_keys.c.id == key_id, digital_keys.c.lab_id == lab_id)
                )
            ).scalar_one()
            reason = "COUNTER_REPLAYED" if counter <= last_counter else "COUNTER_OUT_OF_WINDOW"
            return deny("counter_fresh", reason)
        steps.append(TraceStep("counter_fresh", "pass", f"{last_counter} → {counter} (window {FOB_WINDOW})"))
        last_counter = counter

        # 6. commit the state change in the same transaction
        new_state = NEW_STATE[action]
        conn.execute(
            update(vehicles)
            .where(and_(vehicles.c.id == info.vehicle_id, vehicles.c.lab_id == lab_id))
            .values(lock_state=new_state)
        )
        steps.append(TraceStep("state_committed", "pass", new_state))
        return finish("allow", None, new_state)
