"""Resource controls (T12, D-009): rate limits, lab capacity, TTL cleanup and event retention."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, insert, select

from app.main import create_app
from app.models.tables import challenges, digital_keys, lab_runs, labs, security_events, vehicles
from app.security import cleanup as cleanup_mod
from app.security.challenges import CHALLENGE_TTL_SECONDS
from app.security.cleanup import CHALLENGE_GRACE_SECONDS, MAX_EVENTS_PER_LAB, run_cleanup
from app.security.encoding import new_id
from app.security.labs import LAB_TTL_SECONDS
from app.security.ratelimit import Limit, RateLimiter, RateLimits
from conftest import NOW, Clock
from test_authenticate_api import Lab, sign


@pytest.fixture
def make_client(tmp_path):
    made = []

    def _make(limits: RateLimits, clock: Clock | None = None):
        clock = clock or Clock(NOW)
        app = create_app(f"sqlite:///{tmp_path / f'kg{len(made)}.db'}", clock=clock, rate_limits=limits, cleanup_interval=0)
        c = TestClient(app)
        c.__enter__()
        made.append((c, app))
        return c, clock

    yield _make
    for c, app in made:
        c.__exit__(None, None, None)
        app.state.engine.dispose()


def _headers(lab: dict) -> dict:
    return {"Authorization": f"Bearer {lab['lab_token']}"}


# --- Rate limiter unit behaviour ------------------------------------------------------------------


def test_fixed_window_counts_and_resets():
    clock = Clock(NOW - NOW % 60)  # start of a window
    rl = RateLimiter(clock)
    limit = Limit(3, 60)
    assert [rl.hit("b", "k", limit) for _ in range(3)] == [None, None, None]
    clock.t += 15
    assert rl.hit("b", "k", limit) == 45  # Retry-After = seconds left in the window
    assert rl.hit("b", "other", limit) is None  # keys are independent
    assert rl.hit("other-bucket", "k", limit) is None  # buckets are independent
    clock.t += 45
    assert rl.hit("b", "k", limit) is None  # new window


def test_disabled_limit_never_blocks():
    rl = RateLimiter(Clock(NOW))
    assert all(rl.hit("b", "k", None) is None for _ in range(1000))


def test_memory_is_bounded(monkeypatch):
    clock = Clock(NOW)
    rl = RateLimiter(clock)
    monkeypatch.setattr(RateLimiter, "MAX_TRACKED_KEYS", 100)
    for i in range(1000):
        rl.hit("b", f"addr{i}", Limit(5, 60))
    assert len(rl._counts) <= 100


def test_limits_from_env(monkeypatch):
    monkeypatch.setenv("KEYGUARD_RATE_LAB", "5/10")
    monkeypatch.setenv("KEYGUARD_RATE_CLIENT", "off")
    monkeypatch.delenv("KEYGUARD_RATE_LAB_CREATE", raising=False)
    limits = RateLimits.from_env()
    assert limits.lab == Limit(5, 10)
    assert limits.client is None
    assert limits.lab_create == RateLimits().lab_create


def test_default_limits_are_enabled():
    d = RateLimits()
    assert d.client and d.lab_create and d.lab


# --- Rate limits over HTTP ------------------------------------------------------------------------


def test_lab_creation_is_limited_per_client(make_client):
    c, clock = make_client(RateLimits(client=None, lab_create=Limit(2, 60), lab=None))
    assert [c.post("/api/labs").status_code for _ in range(2)] == [201, 201]
    resp = c.post("/api/labs")
    assert resp.status_code == 429
    assert resp.json()["error"]["code"] == "RATE_LIMITED"
    assert 1 <= int(resp.headers["Retry-After"]) <= 60
    clock.t += 60
    assert c.post("/api/labs").status_code == 201


def test_per_lab_limit_applies_after_authorization_only(make_client):
    c, _ = make_client(RateLimits(client=None, lab_create=None, lab=Limit(3, 60)))
    lab = c.post("/api/labs").json()
    path = f"/api/labs/{lab['lab_id']}/vehicles"
    # Requests without the token are rejected as LAB_NOT_FOUND and do not spend the lab's budget.
    for _ in range(10):
        assert c.get(path).status_code == 404
    assert [c.get(path, headers=_headers(lab)).status_code for _ in range(3)] == [200, 200, 200]
    blocked = c.get(path, headers=_headers(lab))
    assert blocked.status_code == 429 and blocked.json()["error"]["code"] == "RATE_LIMITED"
    # One lab's budget doesn't affect another lab.
    other = c.post("/api/labs").json()
    assert c.get(f"/api/labs/{other['lab_id']}/vehicles", headers=_headers(other)).status_code == 200


def test_per_client_limit_covers_unauthenticated_probing(make_client):
    c, _ = make_client(RateLimits(client=Limit(5, 60), lab_create=None, lab=None))
    probe = f"/api/labs/{new_id('lab')}/vehicles"
    codes = [c.get(probe).status_code for _ in range(7)]
    assert codes == [404] * 5 + [429] * 2
    blocked = c.get("/api/health")
    assert blocked.status_code == 429 and "Retry-After" in blocked.headers


def test_rate_limited_authenticate_never_reaches_the_engine(make_client):
    """A 429 must not consume the challenge or change state: the owner can retry the same response later."""
    assert NOW % 20 == 0  # the test starts at the beginning of a 20 s window
    c, clock = make_client(RateLimits(client=None, lab_create=None, lab=Limit(5, 20)))
    lab_json = c.post("/api/labs").json()
    vehicle_id = c.get(f"/api/labs/{lab_json['lab_id']}/vehicles", headers=_headers(lab_json)).json()["vehicles"][0]["id"]
    lab = Lab(c, {**lab_json, "headers": _headers(lab_json), "vehicle_id": vehicle_id})  # request 1
    key_id, key = lab.enroll()  # 2
    chl = lab.challenge(key_id).json()  # 3
    sig = sign(key, chl)
    lab.lock_state()  # 4
    lab.lock_state()  # 5: budget spent
    blocked = lab.authenticate(chl["challenge_id"], key_id, sig)
    assert blocked.status_code == 429
    with c.app.state.engine.connect() as conn:
        consumed = conn.execute(select(challenges.c.consumed_at).where(challenges.c.id == chl["challenge_id"])).scalar()
        assert consumed is None
        assert _count(conn, security_events, lab_id=lab.id, event_type="authenticate_unlock") == 0
    clock.t += 20  # next window, still inside the 30 s challenge TTL
    assert clock.t < chl["expires_at"]
    assert lab.authenticate(chl["challenge_id"], key_id, sig).json()["decision"] == "allow"


# --- Capacity -------------------------------------------------------------------------------------


def test_lab_capacity_returns_503_and_cleanup_frees_space(make_client, monkeypatch):
    monkeypatch.setattr("app.routes.labs.MAX_ACTIVE_LABS", 2)
    c, clock = make_client(RateLimits(client=None, lab_create=None, lab=None))
    assert [c.post("/api/labs").status_code for _ in range(2)] == [201, 201]
    full = c.post("/api/labs")
    assert full.status_code == 503 and full.json()["error"]["code"] == "LAB_CAPACITY"
    clock.t += LAB_TTL_SECONDS  # both labs expire; creation triggers cleanup and succeeds
    assert c.post("/api/labs").status_code == 201


# --- TTL cleanup ----------------------------------------------------------------------------------


def _count(conn, table, **where) -> int:
    q = select(func.count()).select_from(table)
    for col, val in where.items():
        q = q.where(table.c[col] == val)
    return conn.execute(q).scalar_one()


def test_cleanup_deletes_expired_labs_and_everything_in_them(client, new_lab, clock):
    lab = Lab(client, new_lab)
    key_id, key = lab.enroll()
    chl = lab.challenge(key_id).json()
    lab.authenticate(chl["challenge_id"], key_id, sign(key, chl))
    client.post(f"/api/labs/{lab.id}/scenarios/replay", headers=lab.headers)
    clock.t += 60
    survivor = client.post("/api/labs").json()  # created later, expires later
    engine = client.app.state.engine

    with engine.connect() as conn:
        for table in (vehicles, digital_keys, challenges, security_events, lab_runs):
            assert _count(conn, table, lab_id=lab.id) > 0

    assert run_cleanup(engine, now=NOW + LAB_TTL_SECONDS - 1).labs_deleted == 0
    report = run_cleanup(engine, now=NOW + LAB_TTL_SECONDS)
    assert report.labs_deleted == 1

    with engine.connect() as conn:
        assert _count(conn, labs, id=lab.id) == 0
        for table in (vehicles, digital_keys, challenges, security_events, lab_runs):
            assert _count(conn, table, lab_id=lab.id) == 0
        assert _count(conn, labs, id=survivor["lab_id"]) == 1
        assert _count(conn, vehicles, lab_id=survivor["lab_id"]) == 1

    # The deleted lab's token is now indistinguishable from an unknown lab.
    clock.t = NOW + LAB_TTL_SECONDS
    resp = client.get(f"/api/labs/{lab.id}/vehicles", headers=lab.headers)
    assert resp.status_code == 404 and resp.json()["error"]["code"] == "LAB_NOT_FOUND"


def test_cleanup_prunes_dead_challenges_but_keeps_live_ones(client, new_lab, clock):
    lab = Lab(client, new_lab)
    key_id, key = lab.enroll()
    old = lab.challenge(key_id).json()
    clock.t += CHALLENGE_TTL_SECONDS + CHALLENGE_GRACE_SECONDS
    fresh = lab.challenge(key_id).json()
    report = run_cleanup(client.app.state.engine, now=clock.t)
    assert report.challenges_deleted == 1
    with client.app.state.engine.connect() as conn:
        assert _count(conn, challenges, id=old["challenge_id"]) == 0
        assert _count(conn, challenges, id=fresh["challenge_id"]) == 1
    # Within the grace period an expired challenge is kept, so its denial still reads CHALLENGE_EXPIRED.
    recent = lab.challenge(key_id).json()
    assert run_cleanup(client.app.state.engine, now=recent["expires_at"] + CHALLENGE_GRACE_SECONDS - 1).challenges_deleted == 0
    # A pruned challenge still fails closed (now as not found) and the live one still works.
    assert lab.authenticate(old["challenge_id"], key_id, sign(key, old)).json()["reason"] == "CHALLENGE_NOT_FOUND"
    assert lab.authenticate(fresh["challenge_id"], key_id, sign(key, fresh)).json()["decision"] == "allow"


def test_cleanup_keeps_only_the_newest_events_per_lab(client, new_lab, monkeypatch):
    monkeypatch.setattr(cleanup_mod, "MAX_EVENTS_PER_LAB", 5)
    engine = client.app.state.engine
    other = client.post("/api/labs").json()
    with engine.begin() as conn:
        for i in range(12):
            for lab_id in (new_lab["lab_id"], other["lab_id"]):
                conn.execute(insert(security_events).values(
                    id=new_id("evt"), lab_id=lab_id, event_type="key_enrolled", outcome="success",
                    reason=f"N{i:02d}", created_at=NOW,
                ))
    report = run_cleanup(engine, now=NOW)
    assert report.events_trimmed == 14
    page = client.get(f"/api/labs/{new_lab['lab_id']}/events", headers=new_lab["headers"]).json()
    assert [e["reason"] for e in page["events"]] == ["N11", "N10", "N09", "N08", "N07"]


def test_cleanup_is_idempotent(client, new_lab):
    engine = client.app.state.engine
    run_cleanup(engine, now=NOW + LAB_TTL_SECONDS)
    again = run_cleanup(engine, now=NOW + LAB_TTL_SECONDS)
    assert (again.labs_deleted, again.challenges_deleted, again.events_trimmed) == (0, 0, 0)


def test_retention_constant_matches_api_offset_cap():
    from app.routes.events import MAX_EVENTS_PER_LAB as api_cap

    assert api_cap == MAX_EVENTS_PER_LAB


def test_stale_schema_is_refused_with_a_clear_message(tmp_path):
    import sqlite3

    from app.db import make_engine

    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE security_events (id TEXT PRIMARY KEY, lab_id TEXT)")
    con.close()
    with pytest.raises(RuntimeError, match="schema is out of date"):
        make_engine(f"sqlite:///{db}")
