"""Hosting hardening (D-013): trusted proxies, shared rate limiting, security headers, production config check."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.config import check_production, production_problems
from app.main import create_app
from app.models.tables import rate_limit_counters
from app.security.cleanup import run_cleanup
from app.security.ratelimit import DatabaseRateLimiter, Limit, RateLimits, parse_trusted_proxies, resolve_client
from app.testing_db import fresh_database_url
from conftest import NOW, Clock

PROXIES = parse_trusted_proxies("10.0.0.0/8, 127.0.0.1, fd00::/8")


# --- Trusted proxies --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("peer", "xff", "expected"),
    [
        ("203.0.113.9", None, "203.0.113.9"),  # direct client, no header
        ("203.0.113.9", "198.51.100.1", "203.0.113.9"),  # untrusted peer: its header is ignored (spoof)
        ("10.0.0.5", "198.51.100.1", "198.51.100.1"),  # one trusted proxy
        ("10.0.0.5", "6.6.6.6, 198.51.100.1", "198.51.100.1"),  # client-supplied junk left of the real hop
        ("10.0.0.5", "198.51.100.1, 10.0.0.9", "198.51.100.1"),  # two proxy hops
        ("10.0.0.5", "10.0.0.7, 10.0.0.9", "10.0.0.7"),  # all hops trusted: leftmost
        ("10.0.0.5", "not-an-ip, 198.51.100.1", "198.51.100.1"),  # junk left of the real hop is never read
        ("10.0.0.5", "198.51.100.1, garbage", "10.0.0.5"),  # malformed nearest hop: fall back to the proxy
        ("fd00::1", "2001:db8::7", "2001:db8::7"),  # IPv6
        (None, None, "unknown"),
    ],
)
def test_resolve_client(peer, xff, expected):
    assert resolve_client(peer, xff, PROXIES) == expected


def test_no_trusted_proxies_means_the_header_is_never_read():
    assert resolve_client("10.0.0.5", "198.51.100.1", ()) == "10.0.0.5"


def test_invalid_proxy_config_is_rejected():
    with pytest.raises(ValueError):
        parse_trusted_proxies("10.0.0.0/8, nonsense")


def test_rate_limit_key_comes_from_the_trusted_chain(tmp_path, monkeypatch):
    """Through HTTP: two clients behind the same proxy get separate budgets; spoofing the header doesn't help."""
    monkeypatch.setenv("KEYGUARD_TRUSTED_PROXIES", "127.0.0.1")
    app = create_app(f"sqlite:///{tmp_path / 'p.db'}", clock=lambda: NOW, cleanup_interval=0,
                     rate_limits=RateLimits(client=None, lab_create=Limit(1, 60), lab=None, auth=None))
    with TestClient(app, client=("127.0.0.1", 1234)) as c:
        a = {"X-Forwarded-For": "198.51.100.1"}
        b = {"X-Forwarded-For": "198.51.100.2"}
        assert c.post("/api/labs", headers=a).status_code == 201
        assert c.post("/api/labs", headers=a).status_code == 429
        assert c.post("/api/labs", headers=b).status_code == 201  # a different client behind the same proxy
        # Client A prepends a fake address: the proxy appended the real one, which is what counts.
        assert c.post("/api/labs", headers={"X-Forwarded-For": "1.2.3.4, 198.51.100.1"}).status_code == 429
    with TestClient(app, client=("203.0.113.50", 1)) as direct:
        # Not a trusted proxy: its X-Forwarded-For is ignored, so it can't borrow another client's budget.
        assert direct.post("/api/labs", headers=b).status_code == 201
        assert direct.post("/api/labs", headers={"X-Forwarded-For": "198.51.100.99"}).status_code == 429
    app.state.engine.dispose()


# --- Shared (database) rate limiting ----------------------------------------------------------------


@pytest.fixture
def db_engine(tmp_path):
    from app.db import make_engine

    engine = make_engine(fresh_database_url(tmp_path))
    yield engine
    engine.dispose()


def test_database_limiter_is_shared_between_workers(db_engine):
    clock = Clock(NOW - NOW % 60)
    worker_a, worker_b = DatabaseRateLimiter(db_engine, clock), DatabaseRateLimiter(db_engine, clock)
    limit = Limit(3, 60)
    assert worker_a.hit("b", "k", limit) is None
    assert worker_b.hit("b", "k", limit) is None
    assert worker_a.hit("b", "k", limit) is None
    assert worker_b.hit("b", "k", limit) == 60  # the 4th hit, counted across both "processes"
    assert worker_a.hit("b", "other", limit) is None
    clock.t += 60
    assert worker_b.hit("b", "k", limit) is None  # new window


def test_database_limiter_stores_only_hashed_keys(db_engine):
    DatabaseRateLimiter(db_engine, Clock(NOW)).hit("client", "198.51.100.1", Limit(5, 60))
    with db_engine.connect() as conn:
        rows = conn.execute(select(rate_limit_counters)).mappings().all()
    assert len(rows) == 1 and "198.51.100.1" not in str(dict(rows[0]))
    assert len(rows[0]["key_hash"]) == 64


def test_database_limiter_counts_are_exact_under_concurrency(db_engine):
    import threading

    limiter, limit = DatabaseRateLimiter(db_engine, Clock(NOW)), Limit(25, 60)
    barrier, results, guard = threading.Barrier(40), [], threading.Lock()

    def hit():
        barrier.wait()
        r = limiter.hit("b", "k", limit)
        with guard:
            results.append(r)

    threads = [threading.Thread(target=hit) for _ in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert results.count(None) == 25 and len(results) == 40


def test_old_rate_limit_windows_are_cleaned_up(db_engine):
    DatabaseRateLimiter(db_engine, Clock(NOW)).hit("b", "k", Limit(5, 60))
    run_cleanup(db_engine, now=NOW + 3600 + 60)
    with db_engine.connect() as conn:
        assert conn.execute(select(rate_limit_counters)).first() is None


def test_app_with_database_rate_store_enforces_limits(tmp_path):
    app = create_app(fresh_database_url(tmp_path), clock=lambda: NOW, cleanup_interval=0, rate_store="database",
                     rate_limits=RateLimits(client=None, lab_create=Limit(2, 60), lab=None, auth=None))
    with TestClient(app) as c:
        assert [c.post("/api/labs").status_code for _ in range(3)] == [201, 201, 429]
    app.state.engine.dispose()


def test_unknown_rate_store_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="KEYGUARD_RATE_STORE"):
        create_app(f"sqlite:///{tmp_path / 'x.db'}", cleanup_interval=0, rate_store="redis")


# --- Security headers -------------------------------------------------------------------------------


def test_api_responses_carry_security_headers(client):
    resp = client.get("/api/health")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["Referrer-Policy"] == "no-referrer"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Content-Security-Policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert resp.headers["Cache-Control"] == "no-store"
    assert "Strict-Transport-Security" not in resp.headers  # only when KEYGUARD_HSTS=1
    # Also on errors and rate-limited responses.
    assert client.get("/api/labs/nope/vehicles").headers["X-Content-Type-Options"] == "nosniff"


def test_hsts_when_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYGUARD_HSTS", "1")
    app = create_app(f"sqlite:///{tmp_path / 'h.db'}", cleanup_interval=0)
    with TestClient(app) as c:
        assert c.get("/api/health").headers["Strict-Transport-Security"].startswith("max-age=31536000")
    app.state.engine.dispose()


# --- Production config check ------------------------------------------------------------------------

GOOD = {
    "KEYGUARD_ENV": "production",
    "KEYGUARD_DATABASE_URL": "postgresql+psycopg://u:p@db/keyguard",
    "KEYGUARD_WEB_ORIGIN": "https://app.keyguard.example",
    "KEYGUARD_RP_ID": "keyguard.example",
    "KEYGUARD_COOKIE_SECURE": "1",
    "KEYGUARD_HSTS": "1",
    "KEYGUARD_RATE_STORE": "database",
    "KEYGUARD_TRUSTED_PROXIES": "10.0.0.0/8",
}


def test_good_production_config_passes():
    assert production_problems(GOOD) == []
    check_production(GOOD)


def test_development_defaults_are_refused_in_production():
    problems = production_problems({"KEYGUARD_ENV": "production"})
    text = "\n".join(problems)
    for needle in ("PostgreSQL", "KEYGUARD_WEB_ORIGIN", "KEYGUARD_RP_ID", "KEYGUARD_COOKIE_SECURE", "KEYGUARD_HSTS",
                   "KEYGUARD_RATE_STORE"):
        assert needle in text
    with pytest.raises(RuntimeError, match="Refusing to start"):
        check_production({"KEYGUARD_ENV": "production"})


@pytest.mark.parametrize(
    ("override", "needle"),
    [
        ({"KEYGUARD_DATABASE_URL": "sqlite:///./keyguard.db"}, "PostgreSQL"),
        ({"KEYGUARD_WEB_ORIGIN": "http://app.keyguard.example"}, "https://"),
        ({"KEYGUARD_RP_ID": "other.example"}, "parent domain"),
        ({"KEYGUARD_COOKIE_SECURE": "0"}, "COOKIE_SECURE"),
        ({"KEYGUARD_RATE_STORE": "memory"}, "RATE_STORE"),
        ({"KEYGUARD_RATE_LAB": "off"}, "turned off"),
        ({"KEYGUARD_TRUSTED_PROXIES": "nonsense"}, "TRUSTED_PROXIES"),
    ],
)
def test_each_unsafe_setting_is_reported(override, needle):
    problems = production_problems({**GOOD, **override})
    assert len(problems) == 1 and needle in problems[0], problems


def test_development_mode_is_never_blocked():
    check_production({"KEYGUARD_DATABASE_URL": "sqlite:///./keyguard.db"})


def test_app_refuses_to_start_with_unsafe_production_config(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYGUARD_ENV", "production")
    with pytest.raises(RuntimeError, match="Refusing to start"):
        create_app(f"sqlite:///{tmp_path / 'x.db'}", cleanup_interval=0)


def test_production_disables_interactive_docs(tmp_path, monkeypatch):
    for k, v in {**GOOD, "KEYGUARD_DATABASE_URL": "postgresql+psycopg://u:p@db/k"}.items():
        monkeypatch.setenv(k, v)
    import app.main as main_mod

    monkeypatch.setattr(main_mod, "make_engine", lambda url: __import__("app.db", fromlist=["make_engine"]).make_engine(
        f"sqlite:///{tmp_path / 'd.db'}"))
    app = main_mod.create_app(cleanup_interval=0)
    with TestClient(app) as c:
        assert c.get("/docs").status_code == 404
        assert c.get("/openapi.json").status_code == 404
        assert c.get("/api/health").status_code == 200
    app.state.engine.dispose()


def test_health_checks_the_database(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok" and body["database"] in ("sqlite", "postgresql")


def test_health_reports_a_broken_database_as_503(client, monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("db down: secret-host:5432")

    monkeypatch.setattr(client.app.state.engine, "connect", boom)
    resp = client.get("/api/health")
    assert resp.status_code == 503 and resp.json()["error"]["code"] == "DATABASE_UNAVAILABLE"
    assert "secret-host" not in resp.text


# --- Free-subdomain mode: the web app's authenticated proxy (D-013) -------------------------------------

SECRET = "s" * 40


@pytest.fixture
def proxied(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYGUARD_PROXY_SECRET", SECRET)
    app = create_app(f"sqlite:///{tmp_path / 'px.db'}", clock=lambda: NOW, cleanup_interval=0,
                     rate_limits=RateLimits(client=None, lab_create=Limit(1, 60), lab=None, auth=None))
    with TestClient(app) as c:
        yield c
    app.state.engine.dispose()


def _via_proxy(ip: str, secret: str = SECRET) -> dict:
    return {"X-KeyGuard-Proxy-Secret": secret, "X-KeyGuard-Client-IP": ip}


def test_requests_that_skip_the_proxy_are_refused(proxied):
    resp = proxied.post("/api/labs")
    assert resp.status_code == 403 and resp.json()["error"]["code"] == "PROXY_REQUIRED"
    wrong = proxied.post("/api/labs", headers=_via_proxy("198.51.100.1", secret="t" * 40))
    assert wrong.status_code == 403
    # The host's health check still works without the secret.
    assert proxied.get("/api/health").status_code == 200


def test_proxy_vouched_ip_is_the_rate_limit_key(proxied):
    a, b = _via_proxy("198.51.100.1"), _via_proxy("198.51.100.2")
    assert proxied.post("/api/labs", headers=a).status_code == 201
    assert proxied.post("/api/labs", headers=a).status_code == 429
    assert proxied.post("/api/labs", headers=b).status_code == 201
    # X-Forwarded-For is not consulted in this mode, so it can't be used to dodge the limit.
    assert proxied.post("/api/labs", headers={**a, "X-Forwarded-For": "203.0.113.77"}).status_code == 429


def test_a_non_ip_client_header_falls_back_to_the_peer(proxied):
    headers = _via_proxy("not-an-ip")
    assert proxied.post("/api/labs", headers=headers).status_code == 201
    # Same fallback key (the TestClient peer) → limited.
    assert proxied.post("/api/labs", headers=_via_proxy("also bad")).status_code == 429


def test_production_needs_a_proxy_secret_or_trusted_proxies():
    env = {**GOOD}
    env.pop("KEYGUARD_TRUSTED_PROXIES")
    assert any("per visitor" in p for p in production_problems(env))
    assert production_problems({**env, "KEYGUARD_PROXY_SECRET": SECRET}) == []
    assert any("32 characters" in p for p in production_problems({**env, "KEYGUARD_PROXY_SECRET": "short"}))


def test_hosted_postgres_urls_are_normalised():
    from app.db import normalize_url

    assert normalize_url("postgres://u:p@h/db?sslmode=require") == "postgresql+psycopg://u:p@h/db?sslmode=require"
    assert normalize_url("postgresql://u:p@h/db") == "postgresql+psycopg://u:p@h/db"
    assert normalize_url("postgresql+psycopg://u@h/db") == "postgresql+psycopg://u@h/db"
    assert normalize_url("sqlite:///x.db") == "sqlite:///x.db"
    assert production_problems({**GOOD, "KEYGUARD_DATABASE_URL": "postgres://u:p@h/db"}) == []
