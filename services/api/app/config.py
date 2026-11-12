"""Deployment settings and the production safety check (D-013).

`KEYGUARD_ENV=production` turns on a startup check that refuses to run with settings that are only safe on a
developer machine. Every problem is reported at once, so a misconfigured deploy fails fast and clearly.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

from app.security.ratelimit import RateLimits, parse_trusted_proxies


def is_production(env: Mapping[str, str] = os.environ) -> bool:
    return env.get("KEYGUARD_ENV", "development").strip().lower() == "production"


def database_url(env: Mapping[str, str] = os.environ) -> str:
    """KEYGUARD_DATABASE_URL, else DATABASE_URL (what Neon injects through the Vercel integration), else local SQLite."""
    return env.get("KEYGUARD_DATABASE_URL") or env.get("DATABASE_URL") or "sqlite:///./keyguard.db"


def production_problems(env: Mapping[str, str] = os.environ) -> list[str]:
    """Everything that makes this configuration unsafe for public hosting. Empty means OK."""
    problems: list[str] = []
    db = database_url(env)
    if not db.startswith(("postgresql", "postgres://")):
        problems.append("KEYGUARD_DATABASE_URL (or DATABASE_URL) must be a PostgreSQL URL (SQLite is for local use only)")
    origins = [o.strip() for o in env.get("KEYGUARD_WEB_ORIGIN", "").split(",") if o.strip()]
    if not origins:
        problems.append("KEYGUARD_WEB_ORIGIN must list the deployed web origin(s)")
    elif any(not o.startswith("https://") for o in origins):
        problems.append("every KEYGUARD_WEB_ORIGIN must be https://")
    rp = env.get("KEYGUARD_RP_ID", "localhost")
    if rp == "localhost":
        problems.append("KEYGUARD_RP_ID must be the site's registrable domain, not localhost")
    elif origins and not all(o.split("://", 1)[1].split(":")[0].split("/")[0].endswith(rp) for o in origins):
        problems.append("KEYGUARD_RP_ID must be the web origin's host or a parent domain of it")
    if env.get("KEYGUARD_COOKIE_SECURE") != "1":
        problems.append("KEYGUARD_COOKIE_SECURE=1 is required (session cookie over HTTPS only)")
    if env.get("KEYGUARD_HSTS") != "1":
        problems.append("KEYGUARD_HSTS=1 is required")
    if env.get("KEYGUARD_RATE_STORE", "memory") != "database":
        problems.append("KEYGUARD_RATE_STORE=database is required (memory counters are per process)")
    try:
        proxies = parse_trusted_proxies(env.get("KEYGUARD_TRUSTED_PROXIES"))
    except ValueError as exc:
        problems.append(f"KEYGUARD_TRUSTED_PROXIES is invalid: {exc}")
        proxies = None  # already reported; don't also report it as missing
    secret = env.get("KEYGUARD_PROXY_SECRET", "")
    if secret and len(secret) < 32:
        problems.append("KEYGUARD_PROXY_SECRET must be at least 32 characters")
    ip_header = env.get("KEYGUARD_CLIENT_IP_HEADER", "")
    if proxies == () and not secret and not ip_header:
        # Behind any host's load balancer the direct peer is the balancer, so every visitor would share one budget.
        problems.append(
            "set KEYGUARD_CLIENT_IP_HEADER (platform edge), KEYGUARD_PROXY_SECRET (web proxy) or "
            "KEYGUARD_TRUSTED_PROXIES so rate limits are per visitor"
        )
    if env.get("VERCEL") and not env.get("CRON_SECRET"):
        problems.append("CRON_SECRET is required on Vercel so only Vercel Cron can trigger cleanup")
    try:
        limits = RateLimits.from_env(env)
        if None in (limits.client, limits.lab_create, limits.lab, limits.auth):
            problems.append("rate limits can't be turned off in production")
    except ValueError as exc:
        problems.append(f"a KEYGUARD_RATE_* value is invalid: {exc}")
    return problems


def check_production(env: Mapping[str, str] = os.environ) -> None:
    if not is_production(env):
        return
    problems = production_problems(env)
    if problems:
        raise RuntimeError("Refusing to start with KEYGUARD_ENV=production:\n  - " + "\n  - ".join(problems))
