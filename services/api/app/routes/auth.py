from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends, Request

from app.errors import ApiError
from app.models.schemas import (
    AuthenticateRequest,
    ChallengeIssued,
    ChallengeRequest,
    DecisionOut,
    ErrorResponse,
    FobDecisionOut,
    FobPressRequest,
)
from app.routes.labs import require_lab
from app.security.authenticate import authenticate
from app.security.challenges import MAX_OPEN_CHALLENGES_PER_LAB, count_open_challenges, issue_challenge
from app.security.events import record_event
from app.security.fob import press_fob
from app.security.keys import get_key_auth_info
from app.security.labs import lock_lab
from app.security.protocol import PROTOCOL_VERSION

router = APIRouter(prefix="/api/labs")

_ISSUE_ERRORS = {
    "KEY_UNKNOWN": (404, "Key not found in this lab"),
    "KEY_REVOKED": (403, "Key has been revoked"),
    "VEHICLE_MISMATCH": (422, "Key is not enrolled for this vehicle"),
    "CHALLENGE_LIMIT_REACHED": (429, "Too many open challenges in this lab"),
    "KEY_TYPE_MISMATCH": (422, "Key fobs use the rolling-counter endpoint, not challenges"),
}


@router.post(
    "/{lab_id}/challenges",
    status_code=201,
    response_model=ChallengeIssued,
    responses={s: {"model": ErrorResponse} for s in (403, 404, 422, 429)},
)
def post_challenge(body: ChallengeRequest, request: Request, lab_id: str = Depends(require_lab)) -> ChallengeIssued:
    """Issue a single-use, 30-second challenge bound to (vehicle, key, action).

    Issuance refuses keys that obviously can't succeed. Authenticate re-checks everything
    anyway, because state can change between issue and use (e.g. revocation).
    """
    state = request.app.state
    now = state.clock()
    with state.engine.begin() as conn:
        lock_lab(conn, lab_id=lab_id)  # serialize the open-challenge limit check (PostgreSQL)
        info = get_key_auth_info(conn, lab_id=lab_id, key_id=body.key_id)
        if info is None:
            code = "KEY_UNKNOWN"
        elif info.status != "active":
            code = "KEY_REVOKED"
        elif info.vehicle_id != body.vehicle_id:
            code = "VEHICLE_MISMATCH"
        elif info.credential_type == "fob":
            code = "KEY_TYPE_MISMATCH"
        elif count_open_challenges(conn, lab_id=lab_id, now=now) >= MAX_OPEN_CHALLENGES_PER_LAB:
            code = "CHALLENGE_LIMIT_REACHED"
        else:
            code = None
            chl = issue_challenge(
                conn, lab_id=lab_id, vehicle_id=body.vehicle_id, key_id=body.key_id, action=body.action, now=now
            )
        record_event(
            conn,
            lab_id=lab_id,
            event_type=f"challenge_{body.action}",
            outcome="denied" if code else "issued",
            vehicle_id=body.vehicle_id if info else None,
            key_id=body.key_id if info else None,
            reason=code,
            now=now,
        )
    if code:
        status, message = _ISSUE_ERRORS[code]
        raise ApiError(status, code, message)
    return ChallengeIssued(
        protocol_version=PROTOCOL_VERSION,
        challenge_id=chl.id,
        vehicle_id=chl.vehicle_id,
        key_id=chl.key_id,
        nonce=chl.nonce,
        action=chl.action,
        expires_at=chl.expires_at,
    )


@router.post("/{lab_id}/authenticate", response_model=DecisionOut, responses={404: {"model": ErrorResponse}})
def post_authenticate(body: AuthenticateRequest, request: Request, lab_id: str = Depends(require_lab)) -> DecisionOut:
    """Verify a signed challenge and, only if every check passes, apply the vehicle state change.

    Allow and deny are both returned as 200: a deny is a valid decision, not a transport error.
    Requests that fail schema validation never reach the engine (422 REQUEST_INVALID).
    """
    state = request.app.state
    decision = authenticate(
        state.engine,
        lab_id=lab_id,
        challenge_id=body.challenge_id,
        key_id=body.key_id,
        signature=body.signature,
        clock=state.clock,
    )
    return DecisionOut(**asdict(decision))


@router.post("/{lab_id}/fob", response_model=FobDecisionOut, responses={404: {"model": ErrorResponse}})
def post_fob_press(body: FobPressRequest, request: Request, lab_id: str = Depends(require_lab)) -> FobDecisionOut:
    """A key-fob button press (kg-fob-v1 rolling counter, D-010). Allow and deny are both 200, as for authenticate."""
    state = request.app.state
    decision = press_fob(
        state.engine,
        lab_id=lab_id,
        key_id=body.key_id,
        vehicle_id=body.vehicle_id,
        action=body.action,
        counter=body.counter,
        signature=body.signature,
        clock=state.clock,
    )
    return FobDecisionOut(**asdict(decision))
