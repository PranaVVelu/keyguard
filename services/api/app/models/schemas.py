"""API request/response schemas."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class LabCreated(_Strict):
    lab_id: str
    lab_token: str
    expires_at: int


class Vehicle(_Strict):
    id: str
    name: str
    lock_state: Literal["locked", "unlocked"]


class VehicleList(_Strict):
    vehicles: list[Vehicle]


class ErrorBody(_Strict):
    code: str
    message: str


class ErrorResponse(_Strict):
    error: ErrorBody
