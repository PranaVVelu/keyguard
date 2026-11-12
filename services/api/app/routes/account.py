"""Passkey sign-in, account and saved-lab endpoints (F12, D-012).

Account requests authenticate with the `kg_session` cookie (HttpOnly, SameSite=Strict). Every state-changing
request must also carry `X-KeyGuard-CSRF: 1`, which a cross-origin page can't send without passing CORS.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from pydantic import Field, field_validator

from app.errors import ApiError
from app.models.schemas import _Strict, ErrorResponse
from app.routes.labs import require_lab
from app.security import accounts as acct
from app.security.ratelimit import client_address

router = APIRouter(prefix="/api")

COOKIE = "kg_session"
CSRF_HEADER = "x-keyguard-csrf"

_STATUS = {
    "CHALLENGE_INVALID": (400, "Sign-in challenge is unknown, already used or expired; start again"),
    "PASSKEY_INVALID": (400, "Passkey response could not be verified"),
    "PASSKEY_UNKNOWN": (400, "Passkey response could not be verified"),
    "PASSKEY_CLONED": (400, "Passkey response could not be verified"),
    "PASSKEY_ALREADY_REGISTERED": (409, "This passkey is already registered"),
    "LAB_ALREADY_SAVED": (409, "This lab is saved to another account"),
    "SAVED_LAB_LIMIT_REACHED": (409, "This account has reached its saved-lab limit"),
    "LAB_NOT_FOUND": (404, "Lab not found"),
}


def _raise(code: str) -> None:
    status, message = _STATUS[code]
    raise ApiError(status, code, message)


def relying_party(request: Request) -> acct.RelyingParty:
    origins = os.environ.get("KEYGUARD_WEB_ORIGIN", "http://localhost:3000").split(",")
    return acct.RelyingParty(rp_id=os.environ.get("KEYGUARD_RP_ID", "localhost"), origin=origins[0].strip())


def require_csrf(request: Request) -> None:
    if request.headers.get(CSRF_HEADER) != "1":
        raise ApiError(403, "CSRF_REQUIRED", "Missing X-KeyGuard-CSRF header")


def _auth_limit(request: Request) -> None:
    retry = request.app.state.limiter.hit("auth", client_address(request), request.app.state.rate_limits.auth)
    if retry is not None:
        raise ApiError(429, "RATE_LIMITED", "Too many requests", {"Retry-After": str(retry)})


def require_account(request: Request) -> str:
    state = request.app.state
    with state.engine.connect() as conn:
        account_id = acct.account_for_session(conn, token=request.cookies.get(COOKIE), now=state.clock())
    if account_id is None:
        raise ApiError(401, "NOT_SIGNED_IN", "Sign in with a passkey first")
    return account_id


def _set_session(response: Response, token: str) -> None:
    response.set_cookie(
        COOKIE,
        token,
        max_age=acct.SESSION_TTL_SECONDS,
        httponly=True,
        samesite="strict",
        secure=os.environ.get("KEYGUARD_COOKIE_SECURE") == "1",
        path="/api",
    )


# --- Schemas ---------------------------------------------------------------------------------------


class RegisterOptionsRequest(_Strict):
    display_name: str = Field(min_length=1, max_length=40)

    @field_validator("display_name")
    @classmethod
    def _printable(cls, v: str) -> str:
        if v != v.strip() or any(not ch.isprintable() for ch in v):
            raise ValueError("display name must be printable with no surrounding whitespace")
        return v


class WebAuthnOptions(_Strict):
    challenge_id: str
    options: dict[str, Any]


class VerifyRequest(_Strict):
    challenge_id: str = Field(pattern=r"^wac_[A-Za-z0-9_-]{22}$")
    # The browser's PublicKeyCredential as JSON. py_webauthn parses and validates its structure.
    credential: dict[str, Any]


class AccountInfo(_Strict):
    id: str
    display_name: str
    created_at: int


class PasskeyInfo(_Strict):
    id_prefix: str
    created_at: int
    last_used_at: int | None


class SavedLab(_Strict):
    lab_id: str
    saved_at: int | None
    expires_at: int
    vehicle_name: str
    lock_state: str
    event_count: int


class AccountSummary(_Strict):
    account: AccountInfo
    passkeys: list[PasskeyInfo]
    saved_labs: list[SavedLab]


class OpenedLab(_Strict):
    lab_id: str
    lab_token: str
    expires_at: int


class DeleteRequest(_Strict):
    confirm: str = Field(pattern=r"^DELETE$")


_ERRS = {s: {"model": ErrorResponse} for s in (400, 401, 403, 404, 409, 422, 429)}


def _summary(request: Request, account_id: str) -> AccountSummary:
    with request.app.state.engine.connect() as conn:
        return AccountSummary.model_validate(acct.account_summary(conn, account_id=account_id, now=request.app.state.clock()))


# --- Passkey registration and sign-in ---------------------------------------------------------------


@router.post("/auth/register/options", response_model=WebAuthnOptions, responses=_ERRS,
             dependencies=[Depends(require_csrf), Depends(_auth_limit)])
def register_options(body: RegisterOptionsRequest, request: Request) -> WebAuthnOptions:
    state = request.app.state
    return WebAuthnOptions(**acct.begin_registration(
        state.engine, relying_party(request), display_name=body.display_name, now=state.clock()
    ))


@router.post("/auth/register/verify", response_model=AccountSummary, responses=_ERRS,
             dependencies=[Depends(require_csrf), Depends(_auth_limit)])
def register_verify(body: VerifyRequest, request: Request, response: Response) -> AccountSummary:
    state = request.app.state
    account_id, token, error = acct.finish_registration(
        state.engine, relying_party(request), challenge_id=body.challenge_id, credential=body.credential, now=state.clock()
    )
    if error:
        _raise(error)
    _set_session(response, token)
    return _summary(request, account_id)


@router.post("/auth/login/options", response_model=WebAuthnOptions, responses=_ERRS,
             dependencies=[Depends(require_csrf), Depends(_auth_limit)])
def login_options(request: Request) -> WebAuthnOptions:
    state = request.app.state
    return WebAuthnOptions(**acct.begin_login(state.engine, relying_party(request), now=state.clock()))


@router.post("/auth/login/verify", response_model=AccountSummary, responses=_ERRS,
             dependencies=[Depends(require_csrf), Depends(_auth_limit)])
def login_verify(body: VerifyRequest, request: Request, response: Response) -> AccountSummary:
    state = request.app.state
    account_id, token, error = acct.finish_login(
        state.engine, relying_party(request), challenge_id=body.challenge_id, credential=body.credential, now=state.clock()
    )
    if error:
        _raise(error)
    _set_session(response, token)
    return _summary(request, account_id)


@router.post("/auth/logout", status_code=204, dependencies=[Depends(require_csrf)])
def logout(request: Request, response: Response) -> Response:
    acct.revoke_session(request.app.state.engine, token=request.cookies.get(COOKIE), now=request.app.state.clock())
    response = Response(status_code=204)
    response.delete_cookie(COOKIE, path="/api")
    return response


# --- Account ----------------------------------------------------------------------------------------


@router.get("/account", response_model=AccountSummary, responses=_ERRS)
def get_account(request: Request, account_id: str = Depends(require_account)) -> AccountSummary:
    return _summary(request, account_id)


@router.post("/account/delete", status_code=204, responses=_ERRS, dependencies=[Depends(require_csrf)])
def delete_account(body: DeleteRequest, request: Request, account_id: str = Depends(require_account)) -> Response:
    acct.delete_account(request.app.state.engine, account_id=account_id)
    response = Response(status_code=204)
    response.delete_cookie(COOKIE, path="/api")
    return response


# --- Saved labs -------------------------------------------------------------------------------------


@router.post("/labs/{lab_id}/save", response_model=AccountSummary, responses=_ERRS, dependencies=[Depends(require_csrf)])
def save_lab(request: Request, lab_id: str = Depends(require_lab), account_id: str = Depends(require_account)) -> AccountSummary:
    """Needs BOTH the lab's bearer token (require_lab) and a signed-in account."""
    try:
        acct.save_lab(request.app.state.engine, account_id=account_id, lab_id=lab_id, now=request.app.state.clock())
    except acct.AccountError as exc:
        _raise(exc.code)
    return _summary(request, account_id)


@router.post("/account/labs/{lab_id}/open", response_model=OpenedLab, responses=_ERRS, dependencies=[Depends(require_csrf)])
def open_lab(lab_id: str, request: Request, account_id: str = Depends(require_account)) -> OpenedLab:
    try:
        token, expires_at = acct.open_saved_lab(
            request.app.state.engine, account_id=account_id, lab_id=lab_id, now=request.app.state.clock()
        )
    except acct.AccountError as exc:
        _raise(exc.code)
    return OpenedLab(lab_id=lab_id, lab_token=token, expires_at=expires_at)


@router.post("/account/labs/{lab_id}/unsave", response_model=AccountSummary, responses=_ERRS,
             dependencies=[Depends(require_csrf)])
def unsave_lab(lab_id: str, request: Request, account_id: str = Depends(require_account)) -> AccountSummary:
    try:
        acct.unsave_lab(request.app.state.engine, account_id=account_id, lab_id=lab_id, now=request.app.state.clock())
    except acct.AccountError as exc:
        _raise(exc.code)
    return _summary(request, account_id)
