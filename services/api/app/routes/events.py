"""Read-only, lab-scoped security event history (spec §6 `GET /api/labs/{id}/events`, F08)."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request

from app.models.schemas import ErrorResponse, EventPage, EventSummary, SecurityEvent
from app.routes.labs import require_lab
from app.security.cleanup import MAX_EVENTS_PER_LAB
from app.security.events import MAX_EVENTS_PAGE, EventFilter, list_events, summarize_events

router = APIRouter(prefix="/api/labs")

_ERRORS = {s: {"model": ErrorResponse} for s in (404, 422, 429)}


@router.get("/{lab_id}/events", response_model=EventPage, responses=_ERRORS)
def get_events(
    request: Request,
    lab_id: str = Depends(require_lab),
    category: Literal["authentication", "challenge", "key", "scenario"] | None = None,
    result: Literal["pass", "fail"] | None = None,
    reason: Annotated[str | None, Query(pattern=r"^[A-Z_]{1,40}$")] = None,
    q: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_EVENTS_PAGE)] = 50,
    offset: Annotated[int, Query(ge=0, le=MAX_EVENTS_PER_LAB)] = 0,
) -> EventPage:
    """Newest first. Every filter is applied in SQL inside this lab only; `q` is a case-insensitive substring
    search over IDs, type, outcome and reason code."""
    f = EventFilter(category=category, result=result, reason=reason, q=q)
    with request.app.state.engine.connect() as conn:
        total, rows = list_events(conn, lab_id=lab_id, f=f, limit=limit, offset=offset)
    return EventPage(total=total, limit=limit, offset=offset, events=[SecurityEvent(**r) for r in rows])


@router.get("/{lab_id}/events/summary", response_model=EventSummary, responses=_ERRORS)
def get_event_summary(request: Request, lab_id: str = Depends(require_lab)) -> EventSummary:
    """Pass/fail counts per category, failure reasons ranked by frequency, and authentication timing."""
    with request.app.state.engine.connect() as conn:
        return EventSummary.model_validate(summarize_events(conn, lab_id=lab_id))
