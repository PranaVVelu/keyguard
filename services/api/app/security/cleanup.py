"""TTL cleanup and event retention (D-002, D-009, T12).

Deletes expired labs and everything in them, prunes dead challenges, and caps each lab's event history.
Safe to run at any time and from several processes: every statement is an idempotent DELETE.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Engine, delete, func, select

from app.models.tables import challenges, digital_keys, lab_runs, labs, security_events, vehicles

# A challenge that expired this long ago can never matter again: authenticate rejects it anyway, and the
# per-lab open-challenge count only looks at unexpired ones.
CHALLENGE_GRACE_SECONDS = 5 * 60
MAX_EVENTS_PER_LAB = 2000
MAX_ACTIVE_LABS = 5000


@dataclass(frozen=True)
class CleanupReport:
    labs_deleted: int
    challenges_deleted: int
    events_trimmed: int


def run_cleanup(engine: Engine, *, now: int) -> CleanupReport:
    with engine.begin() as conn:
        expired = select(labs.c.id).where(labs.c.expires_at <= now)
        # Children are deleted explicitly (not only via ON DELETE CASCADE) so cleanup doesn't depend on the
        # database enforcing foreign keys.
        for table in (challenges, security_events, lab_runs, digital_keys, vehicles):
            conn.execute(delete(table).where(table.c.lab_id.in_(expired)))
        labs_deleted = conn.execute(delete(labs).where(labs.c.expires_at <= now)).rowcount

        challenges_deleted = conn.execute(
            delete(challenges).where(challenges.c.expires_at <= now - CHALLENGE_GRACE_SECONDS)
        ).rowcount

        events_trimmed = 0
        over = conn.execute(
            select(security_events.c.lab_id)
            .group_by(security_events.c.lab_id)
            .having(func.count() > MAX_EVENTS_PER_LAB)
        ).scalars().all()
        for lab_id in over:
            keep = (
                select(security_events.c.seq)
                .where(security_events.c.lab_id == lab_id)
                .order_by(security_events.c.seq.desc())
                .limit(MAX_EVENTS_PER_LAB)
            )
            events_trimmed += conn.execute(
                delete(security_events).where(
                    security_events.c.lab_id == lab_id, security_events.c.seq.not_in(keep)
                )
            ).rowcount
    return CleanupReport(labs_deleted, challenges_deleted, events_trimmed)


def count_active_labs(engine: Engine, *, now: int) -> int:
    with engine.connect() as conn:
        return conn.execute(select(func.count()).select_from(labs).where(labs.c.expires_at > now)).scalar_one()


if __name__ == "__main__":  # pragma: no cover - operational entry point
    import os
    import time

    from app.db import make_engine

    eng = make_engine(os.environ.get("KEYGUARD_DATABASE_URL", "sqlite:///./keyguard.db"))
    print(run_cleanup(eng, now=int(time.time())))
