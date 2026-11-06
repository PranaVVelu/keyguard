from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select

from app.errors import ApiError
from app.models.schemas import ErrorResponse, LabCreated, Vehicle, VehicleList
from app.models.tables import vehicles
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
    return lab_id


@router.post("", status_code=201, response_model=LabCreated)
def post_lab(request: Request) -> LabCreated:
    state = request.app.state
    with state.engine.begin() as conn:
        new = create_lab(conn, now=state.clock())
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
