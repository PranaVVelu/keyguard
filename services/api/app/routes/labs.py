from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select

from app.errors import ApiError
from app.models.schemas import ErrorResponse, LabCreated, Vehicle, VehicleList
from app.models.tables import vehicles
from app.security.cleanup import MAX_ACTIVE_LABS, count_active_labs, run_cleanup
from app.security.ratelimit import Limit, client_address
from app.security.labs import authorize_lab, create_lab

router = APIRouter(prefix="/api/labs")

_NOT_FOUND = {404: {"model": ErrorResponse, "description": "Unknown lab, wrong token or expired lab (indistinguishable)"}}


def require_lab(lab_id: str, request: Request) -> str:
    """Dependency: authorize the bearer token for this lab, or fail with a uniform 404."""
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    state = request.app.state
    with state.engine.connect() as conn:
        ok = scheme.lower() == "bearer" and authorize_lab(conn, lab_id=lab_id, bearer_token=token, now=state.clock())
    if not ok:
        raise ApiError(404, "LAB_NOT_FOUND", "Lab not found")
    # Counted only after authorization, so nobody without the token can spend a lab's budget.
    _limit(request, "lab", lab_id, state.rate_limits.lab)
    return lab_id


def _limit(request: Request, bucket: str, key: str, limit: Limit | None) -> None:
    retry = request.app.state.limiter.hit(bucket, key, limit)
    if retry is not None:
        raise ApiError(429, "RATE_LIMITED", "Too many requests", {"Retry-After": str(retry)})


@router.post("", status_code=201, response_model=LabCreated, responses={s: {"model": ErrorResponse} for s in (429, 503)})
def post_lab(request: Request) -> LabCreated:
    state = request.app.state
    _limit(request, "lab_create", client_address(request), state.rate_limits.lab_create)
    now = state.clock()
    if count_active_labs(state.engine, now=now) >= MAX_ACTIVE_LABS:
        run_cleanup(state.engine, now=now)
        if count_active_labs(state.engine, now=now) >= MAX_ACTIVE_LABS:
            raise ApiError(503, "LAB_CAPACITY", "The demo is at capacity; try again later", {"Retry-After": "300"})
    with state.engine.begin() as conn:
        new = create_lab(conn, now=now)
    return LabCreated(lab_id=new.lab_id, lab_token=new.lab_token, expires_at=new.expires_at)


@router.get("/{lab_id}/vehicles", response_model=VehicleList, responses=_NOT_FOUND)
def get_vehicles(request: Request, lab_id: str = Depends(require_lab)) -> VehicleList:
    with request.app.state.engine.connect() as conn:
        rows = conn.execute(
            select(vehicles.c.id, vehicles.c.name, vehicles.c.lock_state)
            .where(vehicles.c.lab_id == lab_id)
            .order_by(vehicles.c.created_at, vehicles.c.id)
        ).mappings()
        return VehicleList(vehicles=[Vehicle(**r) for r in rows])
