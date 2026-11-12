"""Accounts, passkeys, sessions and saved labs (F12, D-012), end to end with a software authenticator."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.models.tables import accounts, labs, passkeys, sessions, webauthn_challenges
from app.security.accounts import (
    SAVED_LAB_LIMIT,
    SAVED_LAB_TTL_SECONDS,
    SESSION_TTL_SECONDS,
    UNSAVED_LAB_TTL_SECONDS,
    WEBAUTHN_TTL_SECONDS,
)
from app.security.cleanup import run_cleanup
from app.security.ratelimit import Limit, RateLimits
from conftest import NOW
from webauthn_sim import SoftPasskey

CSRF = {"X-KeyGuard-CSRF": "1"}


def register(client, passkey: SoftPasskey, name: str = "Pranav", **create_kw):
    opts = client.post("/api/auth/register/options", json={"display_name": name}, headers=CSRF)
    assert opts.status_code == 200, opts.text
    body = opts.json()
    return client.post(
        "/api/auth/register/verify",
        json={"challenge_id": body["challenge_id"], "credential": passkey.create(body["options"], **create_kw)},
        headers=CSRF,
    )


def login(client, passkey: SoftPasskey, **get_kw):
    body = client.post("/api/auth/login/options", headers=CSRF).json()
    return client.post(
        "/api/auth/login/verify",
        json={"challenge_id": body["challenge_id"], "credential": passkey.get(body["options"], **get_kw)},
        headers=CSRF,
    )


def new_lab(client) -> dict:
    lab = client.post("/api/labs").json()
    return {**lab, "headers": {"Authorization": f"Bearer {lab['lab_token']}"}}


@pytest.fixture
def other_client(client):
    """A second browser: same app, separate cookie jar."""
    c = TestClient(client.app)
    yield c
    c.close()


@pytest.fixture
def signed_in(client):
    passkey = SoftPasskey()
    resp = register(client, passkey)
    assert resp.status_code == 200, resp.text
    return passkey, resp.json()


def _code(resp) -> str:
    return resp.json()["error"]["code"]


# --- Options ---------------------------------------------------------------------------------------


def test_registration_options_require_resident_key_and_user_verification(client):
    o = client.post("/api/auth/register/options", json={"display_name": "Ana"}, headers=CSRF).json()["options"]
    assert o["rp"]["id"] == "localhost"
    assert o["authenticatorSelection"]["residentKey"] == "required"
    assert o["authenticatorSelection"]["userVerification"] == "required"
    assert o.get("attestation", "none") == "none"
    assert [p["alg"] for p in o["pubKeyCredParams"]] == [-7, -8]
    assert len(o["challenge"]) == 43  # 32 random bytes, base64url


def test_login_options_reveal_no_accounts(client, signed_in):
    o = client.post("/api/auth/login/options", headers=CSRF).json()["options"]
    assert o.get("allowCredentials", []) == []
    assert o["userVerification"] == "required"


@pytest.mark.parametrize("name", ["", " padded", "x" * 41, "tab\tname"])
def test_display_name_is_validated(client, name):
    resp = client.post("/api/auth/register/options", json={"display_name": name}, headers=CSRF)
    assert resp.status_code == 422


# --- Registration and login ------------------------------------------------------------------------


def test_register_creates_account_passkey_and_session_cookie(client):
    passkey = SoftPasskey()
    resp = register(client, passkey, name="Pranav")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["account"]["display_name"] == "Pranav"
    assert body["account"]["id"].startswith("acct_")
    assert [p["id_prefix"] for p in body["passkeys"]] == [passkey.id[:8]]
    cookie = resp.headers["set-cookie"]
    for attr in ("kg_session=", "HttpOnly", "SameSite=strict", "Path=/api", f"Max-Age={SESSION_TTL_SECONDS}"):
        assert attr.lower() in cookie.lower(), cookie
    assert client.get("/api/account").json()["account"]["id"] == body["account"]["id"]


def test_login_from_another_browser(client, other_client, signed_in):
    passkey, reg = signed_in
    resp = login(other_client, passkey)
    assert resp.status_code == 200, resp.text
    assert resp.json()["account"]["id"] == reg["account"]["id"]
    with client.app.state.engine.connect() as conn:
        assert conn.execute(select(passkeys.c.sign_count)).scalar() == passkey.sign_count


def test_session_token_is_stored_only_as_a_hash(client, signed_in):
    token = client.cookies.get("kg_session")
    with client.app.state.engine.connect() as conn:
        rows = conn.execute(select(sessions)).mappings().all()
    assert len(rows) == 1
    assert token.encode() not in rows[0]["token_hash"] and len(rows[0]["token_hash"]) == 32
    assert all(token not in str(v) for v in rows[0].values())


# --- Challenge rules (T20) -------------------------------------------------------------------------


def test_registration_response_cannot_be_replayed(client):
    passkey = SoftPasskey()
    body = client.post("/api/auth/register/options", json={"display_name": "A"}, headers=CSRF).json()
    payload = {"challenge_id": body["challenge_id"], "credential": passkey.create(body["options"])}
    assert client.post("/api/auth/register/verify", json=payload, headers=CSRF).status_code == 200
    again = client.post("/api/auth/register/verify", json=payload, headers=CSRF)
    assert again.status_code == 400 and _code(again) == "CHALLENGE_INVALID"


def test_failed_verification_burns_the_challenge(client):
    passkey = SoftPasskey()
    body = client.post("/api/auth/register/options", json={"display_name": "A"}, headers=CSRF).json()
    bad = client.post("/api/auth/register/verify", headers=CSRF, json={
        "challenge_id": body["challenge_id"], "credential": passkey.create(body["options"], origin="https://evil.example")})
    assert _code(bad) == "PASSKEY_INVALID"
    good = client.post("/api/auth/register/verify", headers=CSRF, json={
        "challenge_id": body["challenge_id"], "credential": passkey.create(body["options"])})
    assert _code(good) == "CHALLENGE_INVALID"
    with client.app.state.engine.connect() as conn:
        assert conn.execute(select(func.count()).select_from(accounts)).scalar_one() == 0


def test_login_challenge_cannot_be_used_for_registration(client):
    passkey = SoftPasskey()
    reg_opts = client.post("/api/auth/register/options", json={"display_name": "A"}, headers=CSRF).json()
    login_opts = client.post("/api/auth/login/options", headers=CSRF).json()
    resp = client.post("/api/auth/register/verify", headers=CSRF, json={
        "challenge_id": login_opts["challenge_id"], "credential": passkey.create(reg_opts["options"])})
    assert _code(resp) == "CHALLENGE_INVALID"


def test_expired_challenge_is_rejected(client, clock):
    passkey = SoftPasskey()
    body = client.post("/api/auth/register/options", json={"display_name": "A"}, headers=CSRF).json()
    clock.t += WEBAUTHN_TTL_SECONDS
    resp = client.post("/api/auth/register/verify", headers=CSRF, json={
        "challenge_id": body["challenge_id"], "credential": passkey.create(body["options"])})
    assert _code(resp) == "CHALLENGE_INVALID"


# --- Origin, RP ID, user verification (T19) --------------------------------------------------------


@pytest.mark.parametrize("bad", [{"origin": "https://keyguard-login.example"}, {"rp_id": "evil.example"}, {"uv": False}])
def test_registration_rejects_wrong_origin_rp_or_missing_uv(client, bad):
    resp = register(client, SoftPasskey(), **bad)
    assert resp.status_code == 400 and _code(resp) == "PASSKEY_INVALID"
    assert "set-cookie" not in resp.headers


@pytest.mark.parametrize("bad", [{"origin": "https://keyguard-login.example"}, {"rp_id": "evil.example"}, {"uv": False}])
def test_login_rejects_wrong_origin_rp_or_missing_uv(other_client, signed_in, bad):
    passkey, _ = signed_in
    resp = login(other_client, passkey, **bad)
    assert resp.status_code == 400 and _code(resp) == "PASSKEY_INVALID"
    assert other_client.get("/api/account").status_code == 401


def test_login_signature_from_another_key_is_rejected(other_client, signed_in):
    passkey, _ = signed_in
    impostor = SoftPasskey()
    impostor.credential_id, impostor.user_handle = passkey.credential_id, passkey.user_handle
    resp = login(other_client, impostor)
    assert _code(resp) == "PASSKEY_INVALID"


def test_unknown_passkey_is_rejected(other_client):
    stranger = SoftPasskey()
    stranger.user_handle = b"\x00" * 32
    assert _code(login(other_client, stranger)) == "PASSKEY_UNKNOWN"


def test_user_handle_must_match_the_credentials_account(other_client, signed_in):
    passkey, _ = signed_in
    assert _code(login(other_client, passkey, user_handle=b"\x01" * 32)) == "PASSKEY_INVALID"
    assert login(other_client, passkey, user_handle=None).status_code == 200  # omitting it is allowed


def test_same_passkey_cannot_register_twice(client, other_client, signed_in):
    passkey, _ = signed_in
    resp = register(other_client, passkey)
    assert resp.status_code == 409 and _code(resp) == "PASSKEY_ALREADY_REGISTERED"


# --- Clone detection (T24) -------------------------------------------------------------------------


def test_sign_count_regression_is_rejected(client, other_client):
    passkey = SoftPasskey(sign_count=5)
    assert register(client, passkey).status_code == 200
    assert login(other_client, passkey).status_code == 200  # 6 > 5
    resp = login(other_client, passkey, bump=0)  # 6 again: a cloned authenticator
    assert resp.status_code == 400 and _code(resp) == "PASSKEY_CLONED"
    assert login(other_client, passkey, bump=-3).json()["error"]["code"] == "PASSKEY_CLONED"


def test_always_zero_counters_are_allowed(client, other_client):
    passkey = SoftPasskey(sign_count=0)
    assert register(client, passkey).status_code == 200
    for _ in range(2):
        assert login(other_client, passkey, bump=0).status_code == 200


# --- CSRF and session rules (T21, T22) -------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/api/auth/register/options", "/api/auth/register/verify", "/api/auth/login/options",
        "/api/auth/login/verify", "/api/auth/logout", "/api/account/delete",
        "/api/labs/lab_AAAAAAAAAAAAAAAAAAAAAA/save", "/api/account/labs/lab_AAAAAAAAAAAAAAAAAAAAAA/open",
        "/api/account/labs/lab_AAAAAAAAAAAAAAAAAAAAAA/unsave",
    ],
)
def test_state_changes_require_the_csrf_header(client, signed_in, path):
    resp = client.post(path, json={})
    assert resp.status_code == 403 and _code(resp) == "CSRF_REQUIRED"


@pytest.mark.parametrize(
    ("method", "path"),
    [("get", "/api/account"), ("post", "/api/account/delete"),
     ("post", "/api/account/labs/lab_AAAAAAAAAAAAAAAAAAAAAA/open"),
     ("post", "/api/account/labs/lab_AAAAAAAAAAAAAAAAAAAAAA/unsave")],
)
def test_account_endpoints_need_a_session(client, method, path):
    resp = getattr(client, method)(path, headers=CSRF, **({"json": {"confirm": "DELETE"}} if method == "post" else {}))
    assert resp.status_code == 401 and _code(resp) == "NOT_SIGNED_IN"


def test_logout_revokes_the_session_server_side(client, other_client, signed_in):
    token = client.cookies.get("kg_session")
    assert client.post("/api/auth/logout", headers=CSRF).status_code == 204
    assert client.get("/api/account").status_code == 401
    # Even a copy of the old cookie no longer works.
    other_client.cookies.set("kg_session", token, path="/api")
    assert other_client.get("/api/account").status_code == 401


def test_session_expires(client, clock, signed_in):
    clock.t += SESSION_TTL_SECONDS
    assert client.get("/api/account").status_code == 401


def test_forged_session_cookie_is_rejected(other_client):
    other_client.cookies.set("kg_session", "x" * 43, path="/api")
    assert other_client.get("/api/account").status_code == 401
    other_client.cookies.set("kg_session", "A" * 200, path="/api")  # over-long values are refused before hashing
    assert other_client.get("/api/account").status_code == 401


def test_auth_endpoints_are_rate_limited(tmp_path):
    from app.main import create_app

    app = create_app(f"sqlite:///{tmp_path / 'rl.db'}", clock=lambda: NOW, cleanup_interval=0,
                     rate_limits=RateLimits(client=None, lab_create=None, lab=None, auth=Limit(3, 60)))
    with TestClient(app) as c:
        codes = [c.post("/api/auth/login/options", headers=CSRF).status_code for _ in range(4)]
    app.state.engine.dispose()
    assert codes == [200, 200, 200, 429]


# --- Saved labs (T23) ------------------------------------------------------------------------------


def test_save_open_and_rotate_the_lab_token(client, clock, signed_in):
    lab = new_lab(client)
    saved = client.post(f"/api/labs/{lab['lab_id']}/save", headers={**lab["headers"], **CSRF})
    assert saved.status_code == 200, saved.text
    [entry] = saved.json()["saved_labs"]
    assert entry["lab_id"] == lab["lab_id"] and entry["expires_at"] == NOW + SAVED_LAB_TTL_SECONDS
    assert entry["vehicle_name"] == "KG Coupe (fictional)"

    clock.t += 3600
    opened = client.post(f"/api/account/labs/{lab['lab_id']}/open", headers=CSRF)
    assert opened.status_code == 200
    new_token = opened.json()["lab_token"]
    assert new_token != lab["lab_token"]
    assert opened.json()["expires_at"] == clock.t + SAVED_LAB_TTL_SECONDS
    vehicles_path = f"/api/labs/{lab['lab_id']}/vehicles"
    assert client.get(vehicles_path, headers={"Authorization": f"Bearer {new_token}"}).status_code == 200
    old = client.get(vehicles_path, headers=lab["headers"])
    assert old.status_code == 404 and _code(old) == "LAB_NOT_FOUND"


def test_saving_needs_the_lab_token_too(client, signed_in):
    lab = new_lab(client)
    resp = client.post(f"/api/labs/{lab['lab_id']}/save", headers=CSRF)
    assert resp.status_code == 404 and _code(resp) == "LAB_NOT_FOUND"


def test_saving_needs_an_account(client):
    lab = new_lab(client)
    resp = client.post(f"/api/labs/{lab['lab_id']}/save", headers={**lab["headers"], **CSRF})
    assert resp.status_code == 401


def test_saved_labs_are_private_to_their_account(client, other_client, signed_in):
    lab = new_lab(client)
    client.post(f"/api/labs/{lab['lab_id']}/save", headers={**lab["headers"], **CSRF})
    assert register(other_client, SoftPasskey(), name="Mallory").status_code == 200

    # Even holding the lab token, another account can't take ownership.
    steal = other_client.post(f"/api/labs/{lab['lab_id']}/save", headers={**lab["headers"], **CSRF})
    assert steal.status_code == 409 and _code(steal) == "LAB_ALREADY_SAVED"
    # Open/unsave look exactly like an unknown lab.
    for action in ("open", "unsave"):
        resp = other_client.post(f"/api/account/labs/{lab['lab_id']}/{action}", headers=CSRF)
        assert resp.status_code == 404 and _code(resp) == "LAB_NOT_FOUND"
    assert other_client.get("/api/account").json()["saved_labs"] == []
    # And the owner still has it.
    assert [s["lab_id"] for s in client.get("/api/account").json()["saved_labs"]] == [lab["lab_id"]]


def test_unknown_or_malformed_lab_ids_are_not_found(client, signed_in):
    for lab_id in ("lab_AAAAAAAAAAAAAAAAAAAAAA", "nope"):
        assert client.post(f"/api/account/labs/{lab_id}/open", headers=CSRF).status_code == 404


def test_unsave_caps_retention_and_releases_ownership(client, other_client, clock, signed_in):
    lab = new_lab(client)
    client.post(f"/api/labs/{lab['lab_id']}/save", headers={**lab["headers"], **CSRF})
    clock.t += 10
    resp = client.post(f"/api/account/labs/{lab['lab_id']}/unsave", headers=CSRF)
    assert resp.status_code == 200 and resp.json()["saved_labs"] == []
    with client.app.state.engine.connect() as conn:
        row = conn.execute(select(labs.c.account_id, labs.c.expires_at).where(labs.c.id == lab["lab_id"])).one()
    assert row.account_id is None and row.expires_at == clock.t + UNSAVED_LAB_TTL_SECONDS


def test_saving_twice_is_idempotent_and_the_limit_is_enforced(client, signed_in):
    first = new_lab(client)
    for _ in range(2):
        assert client.post(f"/api/labs/{first['lab_id']}/save", headers={**first["headers"], **CSRF}).status_code == 200
    for _ in range(SAVED_LAB_LIMIT - 1):
        lab = new_lab(client)
        assert client.post(f"/api/labs/{lab['lab_id']}/save", headers={**lab["headers"], **CSRF}).status_code == 200
    extra = new_lab(client)
    resp = client.post(f"/api/labs/{extra['lab_id']}/save", headers={**extra["headers"], **CSRF})
    assert resp.status_code == 409 and _code(resp) == "SAVED_LAB_LIMIT_REACHED"


def test_saved_labs_outlive_the_normal_lab_ttl(client, clock, signed_in):
    saved, plain = new_lab(client), new_lab(client)
    client.post(f"/api/labs/{saved['lab_id']}/save", headers={**saved["headers"], **CSRF})
    run_cleanup(client.app.state.engine, now=NOW + 2 * 24 * 3600)
    with client.app.state.engine.connect() as conn:
        ids = set(conn.execute(select(labs.c.id)).scalars())
    assert saved["lab_id"] in ids and plain["lab_id"] not in ids
    run_cleanup(client.app.state.engine, now=NOW + SAVED_LAB_TTL_SECONDS)
    with client.app.state.engine.connect() as conn:
        assert saved["lab_id"] not in set(conn.execute(select(labs.c.id)).scalars())


# --- Account deletion and cleanup ------------------------------------------------------------------


def test_delete_account_removes_everything_it_owns(client, other_client, signed_in):
    passkey, _ = signed_in
    saved, unsaved = new_lab(client), new_lab(client)
    client.post(f"/api/labs/{saved['lab_id']}/save", headers={**saved["headers"], **CSRF})

    assert client.post("/api/account/delete", json={"confirm": "nope"}, headers=CSRF).status_code == 422
    resp = client.post("/api/account/delete", json={"confirm": "DELETE"}, headers=CSRF)
    assert resp.status_code == 204
    assert "kg_session=" in resp.headers.get("set-cookie", "")

    engine = client.app.state.engine
    with engine.connect() as conn:
        for table in (accounts, passkeys, sessions):
            assert conn.execute(select(func.count()).select_from(table)).scalar_one() == 0
        ids = set(conn.execute(select(labs.c.id)).scalars())
    assert saved["lab_id"] not in ids and unsaved["lab_id"] in ids
    assert client.get(f"/api/labs/{saved['lab_id']}/vehicles", headers=saved["headers"]).status_code == 404
    assert _code(login(other_client, passkey)) == "PASSKEY_UNKNOWN"


def test_cleanup_removes_expired_challenges_and_ended_sessions(client, clock, signed_in):
    client.post("/api/auth/login/options", headers=CSRF)  # an unused challenge
    client.post("/api/auth/logout", headers=CSRF)  # a revoked session
    report = run_cleanup(client.app.state.engine, now=NOW + WEBAUTHN_TTL_SECONDS)
    assert report.auth_rows_deleted == 3  # register challenge (used), login challenge, revoked session
    with client.app.state.engine.connect() as conn:
        assert conn.execute(select(func.count()).select_from(webauthn_challenges)).scalar_one() == 0
        assert conn.execute(select(func.count()).select_from(sessions)).scalar_one() == 0
