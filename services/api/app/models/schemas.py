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


_ID = r"^{p}_[A-Za-z0-9_-]{{22}}$"


class ChallengeRequest(_Strict):
    vehicle_id: str = Field(pattern=_ID.format(p="veh"))
    key_id: str = Field(pattern=_ID.format(p="key"))
    action: Literal["unlock", "lock"]


class ChallengeIssued(_Strict):
    protocol_version: Literal["kg-auth-v1"]
    challenge_id: str
    vehicle_id: str
    key_id: str
    nonce: str
    action: Literal["unlock", "lock"]
    expires_at: int


class AuthenticateRequest(_Strict):
    challenge_id: str = Field(pattern=_ID.format(p="chl"))
    key_id: str = Field(pattern=_ID.format(p="key"))
    # 64-byte P1363 signature = 86 base64url chars; allow slack so malformed ones reach the engine and burn the challenge.
    signature: str = Field(min_length=1, max_length=256)


class TraceStepOut(_Strict):
    step: str
    status: Literal["pass", "fail", "skipped"]
    detail: str | None


class DecisionOut(_Strict):
    decision: Literal["allow", "deny"]
    reason: str | None
    challenge_id: str
    vehicle_id: str | None
    action: Literal["unlock", "lock"] | None
    lock_state: Literal["locked", "unlocked"] | None
    duration_ms: int
    trace: list[TraceStepOut]


class ScenarioStep(_Strict):
    n: int
    actor: Literal["owner", "attacker"]
    label: str
    decision: Literal["allow", "deny"]
    reason: str | None
    lock_state: Literal["locked", "unlocked"] | None


class ScenarioModeRun(_Strict):
    mode: Literal["vulnerable", "hardened"]
    steps: list[ScenarioStep]
    final_lock_state: Literal["locked", "unlocked"] | None
    attack_decision: Literal["allow", "deny"]
    attack_reason: str | None


class ScenarioResult(_Strict):
    run_id: str
    scenario: str
    title: str
    description: str
    expected: dict[str, str]
    attack_label: str
    mode_notes: dict[str, str]
    takeaway: str
    actual: dict[str, str]
    matches_expected: bool
    runs: list[ScenarioModeRun]
    duration_ms: int
    created_at: int


class ScenarioSummary(_Strict):
    id: str
    title: str
    description: str
    expected: dict[str, str]
    attack_label: str
    mode_notes: dict[str, str]
    takeaway: str


class ScenarioCatalog(_Strict):
    scenarios: list[ScenarioSummary]


class LabRun(_Strict):
    run_id: str
    scenario: str
    mode: Literal["vulnerable", "hardened"]
    expected_result: str
    actual_result: str
    actual_reason: str | None
    duration_ms: int | None
    created_at: int


class LabRunList(_Strict):
    runs: list[LabRun]


EventCategory = Literal["authentication", "challenge", "key", "scenario", "other"]


class SecurityEvent(_Strict):
    """Sanitized event: IDs, type, outcome and reason code only (no tokens, keys, nonces or signatures)."""

    id: str
    event_type: str
    category: EventCategory
    outcome: str
    result: Literal["pass", "fail"]
    reason: str | None
    vehicle_id: str | None
    key_id: str | None
    duration_ms: int | None
    created_at: int


class EventPage(_Strict):
    total: int
    limit: int
    offset: int
    events: list[SecurityEvent]


class PassFail(_Strict):
    pass_: int = Field(alias="pass", serialization_alias="pass")
    fail: int

    model_config = ConfigDict(extra="forbid", strict=True, populate_by_name=True)


class ReasonCount(_Strict):
    reason: str
    count: int


class AuthStats(_Strict):
    allowed: int
    denied: int
    median_ms: int | None
    p95_ms: int | None


class EventSummary(_Strict):
    total: int
    pass_: int = Field(alias="pass", serialization_alias="pass")
    fail: int
    by_category: dict[str, PassFail]
    failure_reasons: list[ReasonCount]
    authentication: AuthStats

    model_config = ConfigDict(extra="forbid", strict=True, populate_by_name=True)
