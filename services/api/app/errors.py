"""Stable machine-readable error responses. Never echo request input back."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, headers: dict[str, str] | None = None) -> None:
        self.status, self.code, self.message, self.headers = status, code, message, headers


def _body(code: str, message: str) -> dict:
    return {"error": {"code": code, "message": message}}


def error_response(status: int, code: str, message: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(_body(code, message), status_code=status, headers=headers)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError):
        return JSONResponse(_body(exc.code, exc.message), status_code=exc.status, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError):
        return JSONResponse(_body("REQUEST_INVALID", "Request failed validation"), status_code=422)

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException):
        code = {404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED"}.get(exc.status_code, "HTTP_ERROR")
        return JSONResponse(_body(code, "Request could not be served"), status_code=exc.status_code)

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception):
        return JSONResponse(_body("INTERNAL_ERROR", "Internal error"), status_code=500)
