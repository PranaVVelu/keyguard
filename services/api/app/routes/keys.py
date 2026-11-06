from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.errors import ApiError
from app.models.schemas import DigitalKey, EnrollKeyRequest, ErrorResponse, KeyList
from app.routes.labs import require_lab
from app.security.events import record_event
from app.security.keys import EnrollmentError, enroll_key, list_keys, revoke_key
from app.security.encoding import is_valid_id
from app.security.protocol import ProtocolError

router = APIRouter(prefix="/api/labs")

_ENROLL_ERRORS = {
    "VEHICLE_NOT_FOUND": (404, "Vehicle not found in this lab"),
    "KEY_ALREADY_ENROLLED": (409, "This public key is already enrolled in this lab"),
    "KEY_LIMIT_REACHED": (409, "This lab has reached its key limit"),
    "PUBLIC_KEY_INVALID": (422, "Public key is not a valid SPKI encoding"),
    "PUBLIC_KEY_UNSUPPORTED": (422, "Only ECDSA P-256 public keys are supported"),
}


@router.post(
    "/{lab_id}/keys",
    status_code=201,
    response_model=DigitalKey,
    responses={s: {"model": ErrorResponse} for s in (404, 409, 422)},
)
def post_key(body: EnrollKeyRequest, request: Request, lab_id: str = Depends(require_lab)) -> DigitalKey:
    state = request.app.state
    now = state.clock()
    try:
        with state.engine.begin() as conn:
            key_id = enroll_key(
                conn, lab_id=lab_id, vehicle_id=body.vehicle_id, spki_b64url=body.public_key, label=body.label, now=now
            )
            record_event(
                conn, lab_id=lab_id, event_type="key_enrolled", outcome="success",
                vehicle_id=body.vehicle_id, key_id=key_id, now=now,
            )
            record = next(k for k in list_keys(conn, lab_id=lab_id) if k.id == key_id)
    except (ProtocolError, EnrollmentError) as exc:
        status, message = _ENROLL_ERRORS[exc.code]
        with state.engine.begin() as conn:
            record_event(
                conn, lab_id=lab_id, event_type="key_enrolled", outcome="denied",
                vehicle_id=body.vehicle_id, reason=exc.code, now=now,
            )
        raise ApiError(status, exc.code, message) from exc
    return DigitalKey(**record.__dict__)


@router.get("/{lab_id}/keys", response_model=KeyList, responses={404: {"model": ErrorResponse}})
def get_keys(request: Request, lab_id: str = Depends(require_lab)) -> KeyList:
    with request.app.state.engine.connect() as conn:
        return KeyList(keys=[DigitalKey(**k.__dict__) for k in list_keys(conn, lab_id=lab_id)])


@router.post(
    "/{lab_id}/keys/{key_id}/revoke",
    response_model=DigitalKey,
    responses={404: {"model": ErrorResponse}},
)
def post_revoke(key_id: str, request: Request, lab_id: str = Depends(require_lab)) -> DigitalKey:
    """Revoke a credential. Any challenge already issued to it is denied at authenticate time (KEY_REVOKED)."""
    state = request.app.state
    now = state.clock()
    with state.engine.begin() as conn:
        record = revoke_key(conn, lab_id=lab_id, key_id=key_id, now=now) if is_valid_id(key_id, "key") else None
        if record is None:
            raise ApiError(404, "KEY_UNKNOWN", "Key not found in this lab")
        record_event(
            conn, lab_id=lab_id, event_type="key_revoked", outcome="success",
            vehicle_id=record.vehicle_id, key_id=key_id, now=now,
        )
    return DigitalKey(**record.__dict__)
