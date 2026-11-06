"""Lab creation and lab-scoped authorization over HTTP (D-002, threat T7)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.main import create_app
from app.models.tables import labs
from app.security.labs import LAB_TTL_SECONDS

NOW = 1_793_923_200


class Clock:
    def __init__(self, t: int) -> None:
        self.t = t

    def __call__(self) -> int:
        return self.t


@pytest.fixture
def clock():
    return Clock(NOW)


@pytest.fixture
def client(tmp_path, clock):
    app = create_app(f"sqlite:///{tmp_path / 'kg.db'}", clock=clock)
    with TestClient(app) as c:
        yield c
    app.state.engine.dispose()


def _new_lab(client) -> dict:
    resp = client.post("/api/labs")
    assert resp.status_code == 201
    return resp.json()


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_create_lab_returns_token_once_and_seeds_vehicle(client):
    lab = _new_lab(client)
    assert lab["lab_id"].startswith("lab_")
    assert len(lab["lab_token"]) == 43  # 32 bytes, unpadded base64url
    assert lab["expires_at"] == NOW + LAB_TTL_SECONDS

    resp = client.get(f"/api/labs/{lab['lab_id']}/vehicles", headers=_auth(lab["lab_token"]))
    assert resp.status_code == 200
    (vehicle,) = resp.json()["vehicles"]
    assert vehicle["lock_state"] == "locked"
    assert vehicle["id"].startswith("veh_")
    assert lab["lab_token"] not in resp.text


def test_token_is_stored_only_as_hash(client):
    lab = _new_lab(client)
    with client.app.state.engine.connect() as conn:
        stored = conn.execute(select(labs.c.token_hash).where(labs.c.id == lab["lab_id"])).scalar_one()
    assert len(stored) == 32
    assert lab["lab_token"].encode() not in stored


def _assert_lab_not_found(resp):
    assert resp.status_code == 404
    assert resp.json() == {"error": {"code": "LAB_NOT_FOUND", "message": "Lab not found"}}


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": ""},
        {"Authorization": "Bearer"},
        {"Authorization": "Basic abc"},
        {"Authorization": "Bearer " + "A" * 43},
        {"Authorization": "Bearer " + "A" * 5000},
    ],
    ids=["missing", "empty", "no-token", "wrong-scheme", "wrong-token", "oversized"],
)
def test_bad_credentials_get_uniform_404(client, headers):
    lab = _new_lab(client)
    _assert_lab_not_found(client.get(f"/api/labs/{lab['lab_id']}/vehicles", headers=headers))


def test_cross_lab_request_is_denied_identically(client):
    a, b = _new_lab(client), _new_lab(client)
    cross = client.get(f"/api/labs/{b['lab_id']}/vehicles", headers=_auth(a["lab_token"]))
    unknown = client.get("/api/labs/lab_" + "Q" * 22 + "/vehicles", headers=_auth(a["lab_token"]))
    malformed = client.get("/api/labs/../vehicles", headers=_auth(a["lab_token"]))
    _assert_lab_not_found(cross)
    _assert_lab_not_found(unknown)
    assert malformed.status_code == 404
    assert cross.content == unknown.content


def test_expired_lab_is_indistinguishable_from_unknown(client, clock):
    lab = _new_lab(client)
    clock.t = lab["expires_at"]
    _assert_lab_not_found(client.get(f"/api/labs/{lab['lab_id']}/vehicles", headers=_auth(lab["lab_token"])))


def test_errors_never_echo_input(client):
    probe = "<script>alert(1)</script>"
    resp = client.get(f"/api/labs/{probe}/vehicles", headers=_auth(probe))
    assert resp.status_code == 404
    assert probe not in resp.text
