"""Security event log. Records IDs and reason codes only, never tokens, keys or signatures (T11)."""

from __future__ import annotations

from sqlalchemy import Connection, insert

from app.models.tables import security_events
from app.security.encoding import new_id


def record_event(
    conn: Connection,
    *,
    lab_id: str,
    event_type: str,
    outcome: str,
    now: int,
    vehicle_id: str | None = None,
    key_id: str | None = None,
    reason: str | None = None,
    duration_ms: int | None = None,
) -> str:
    event_id = new_id("evt")
    conn.execute(
        insert(security_events).values(
            id=event_id,
            lab_id=lab_id,
            vehicle_id=vehicle_id,
            key_id=key_id,
            event_type=event_type,
            outcome=outcome,
            reason=reason,
            duration_ms=duration_ms,
            created_at=now,
        )
    )
    return event_id
