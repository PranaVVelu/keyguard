"""API request/response schemas."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


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


class EnrollKeyRequest(_Strict):
    vehicle_id: str = Field(pattern=r"^veh_[A-Za-z0-9_-]{22}$")
    # P-256 SPKI DER is 91 bytes, i.e. 122 base64url chars. Allow a little slack and let the parser decide.
    public_key: str = Field(min_length=1, max_length=256)
    label: str = Field(min_length=1, max_length=40)

    @field_validator("label")
    @classmethod
    def _printable_label(cls, v: str) -> str:
        if v != v.strip() or any(not ch.isprintable() for ch in v):
            raise ValueError("label must be printable with no surrounding whitespace")
        return v


class DigitalKey(_Strict):
    id: str
    vehicle_id: str
    label: str
    fingerprint: str
    status: Literal["active", "revoked"]
    created_at: int
    revoked_at: int | None


class KeyList(_Strict):
    keys: list[DigitalKey]


class ErrorBody(_Strict):
    code: str
    message: str


class ErrorResponse(_Strict):
    error: ErrorBody
