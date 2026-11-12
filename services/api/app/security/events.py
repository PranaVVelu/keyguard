"""Security event log. Records IDs and reason codes only, never tokens, keys or signatures (T11).

The write side is `record_event`; the read side (list/summarize) backs the events API and Security Analytics.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Connection, and_, func, insert, or_, select

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


# --- Read side (F08 Security Analytics) -------------------------------------------------------------

CATEGORIES: dict[str, tuple[str, ...]] = {
    "authentication": ("authenticate", "fob_"),  # challenge-response and key-fob presses (D-010)
    "challenge": ("challenge_",),
    "key": ("key_",),
    "scenario": ("scenario_",),
}
PASS_OUTCOMES = ("allow", "issued", "success", "as_expected")
MAX_EVENTS_PAGE = 200


def category_of(event_type: str) -> str:
    for name, prefixes in CATEGORIES.items():
        if event_type.startswith(prefixes):
            return name
    return "other"


def result_of(outcome: str) -> str:
    return "pass" if outcome in PASS_OUTCOMES else "fail"


@dataclass(frozen=True)
class EventFilter:
    category: str | None = None
    result: str | None = None  # "pass" | "fail"
    reason: str | None = None
    q: str | None = None


def _like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _where(lab_id: str, f: EventFilter):
    ev = security_events.c
    clauses = [ev.lab_id == lab_id]  # always scoped in SQL (D-002)
    if f.category:
        clauses.append(or_(*(ev.event_type.startswith(p, autoescape=True) for p in CATEGORIES[f.category])))
    if f.result == "pass":
        clauses.append(ev.outcome.in_(PASS_OUTCOMES))
    elif f.result == "fail":
        clauses.append(ev.outcome.not_in(PASS_OUTCOMES))
    if f.reason:
        clauses.append(ev.reason == f.reason)
    if f.q:
        pattern = f"%{_like_escape(f.q.lower())}%"
        clauses.append(
            or_(*(func.lower(func.coalesce(c, "")).like(pattern, escape="\\")
                  for c in (ev.id, ev.event_type, ev.outcome, ev.reason, ev.vehicle_id, ev.key_id)))
        )
    return and_(*clauses)


def list_events(conn: Connection, *, lab_id: str, f: EventFilter, limit: int, offset: int) -> tuple[int, list[dict]]:
    where = _where(lab_id, f)
    total = conn.execute(select(func.count()).select_from(security_events).where(where)).scalar_one()
    rows = conn.execute(
        select(
            security_events.c.id, security_events.c.event_type, security_events.c.outcome, security_events.c.reason,
            security_events.c.vehicle_id, security_events.c.key_id, security_events.c.duration_ms,
            security_events.c.created_at,
        )
        .where(where)
        .order_by(security_events.c.seq.desc())
        .limit(limit)
        .offset(offset)
    ).mappings().all()
    return total, [
        {**r, "category": category_of(r["event_type"]), "result": result_of(r["outcome"])} for r in rows
    ]


def summarize_events(conn: Connection, *, lab_id: str) -> dict:
    ev = security_events.c
    rows = conn.execute(
        select(ev.event_type, ev.outcome, ev.reason, func.count().label("n"))
        .where(ev.lab_id == lab_id)
        .group_by(ev.event_type, ev.outcome, ev.reason)
    ).all()
    by_category = {name: {"pass": 0, "fail": 0} for name in CATEGORIES}
    reasons: dict[str, int] = {}
    total = passed = 0
    for event_type, outcome, reason, n in rows:
        cat = category_of(event_type)
        res = result_of(outcome)
        by_category.setdefault(cat, {"pass": 0, "fail": 0})[res] += n
        total += n
        if res == "pass":
            passed += n
        elif reason:
            reasons[reason] = reasons.get(reason, 0) + n

    durations = conn.execute(
        select(ev.duration_ms)
        .where(
            ev.lab_id == lab_id,
            or_(*(ev.event_type.startswith(p, autoescape=True) for p in CATEGORIES["authentication"])),
            ev.duration_ms.is_not(None),
        )
        .order_by(ev.duration_ms)
    ).scalars().all()

    def pct(p: float) -> int | None:
        if not durations:
            return None
        return durations[min(len(durations) - 1, int(round(p * (len(durations) - 1))))]

    return {
        "total": total,
        "pass": passed,
        "fail": total - passed,
        "by_category": by_category,
        "failure_reasons": [
            {"reason": r, "count": n} for r, n in sorted(reasons.items(), key=lambda kv: (-kv[1], kv[0]))
        ],
        "authentication": {
            "allowed": by_category["authentication"]["pass"],
            "denied": by_category["authentication"]["fail"],
            "median_ms": pct(0.5),
            "p95_ms": pct(0.95),
        },
    }
