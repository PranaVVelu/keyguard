"""FastAPI application factory.

    uv run uvicorn app.main:create_app --factory --reload --port 8000
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from collections.abc import Callable

from fastapi import FastAPI, Request
from sqlalchemy import text
from fastapi.middleware.cors import CORSMiddleware

from app.db import make_engine
from app.errors import error_response, install_error_handlers
from app.routes import account, auth, events, keys, lab, labs
from app.security.cleanup import run_cleanup
from app.config import check_production, is_production
from app.security.ratelimit import DatabaseRateLimiter, RateLimiter, RateLimits, client_address, parse_trusted_proxies
from starlette.concurrency import run_in_threadpool

log = logging.getLogger("keyguard")


def create_app(
    database_url: str | None = None,
    clock: Callable[[], int] | None = None,
    *,
    rate_limits: RateLimits | None = None,
    cleanup_interval: int | None = None,
    rate_store: str | None = None,
) -> FastAPI:
    """`cleanup_interval` seconds between TTL cleanup passes; 0 disables the background task (tests).

    `rate_store` is "memory" (default) or "database" (shared across workers, D-013).
    """
    check_production()
    engine = make_engine(database_url or os.environ.get("KEYGUARD_DATABASE_URL", "sqlite:///./keyguard.db"))
    now_fn = clock or (lambda: int(time.time()))
    interval = cleanup_interval if cleanup_interval is not None else int(os.environ.get("KEYGUARD_CLEANUP_INTERVAL", "300"))

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI):
        task = asyncio.create_task(_cleanup_loop(engine, now_fn, interval)) if interval > 0 else None
        try:
            yield
        finally:
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

    production = is_production()
    # Interactive docs load scripts from a CDN; they're for local development only.
    app = FastAPI(
        title="KeyGuard API", version="0.1.0", lifespan=lifespan,
        docs_url=None if production else "/docs", redoc_url=None, openapi_url=None if production else "/openapi.json",
    )
    app.state.engine = engine
    app.state.clock = now_fn
    app.state.rate_limits = rate_limits or RateLimits.from_env()
    store = rate_store or os.environ.get("KEYGUARD_RATE_STORE", "memory")
    if store not in ("memory", "database"):
        raise ValueError(f"KEYGUARD_RATE_STORE must be 'memory' or 'database', not {store!r}")
    app.state.limiter = DatabaseRateLimiter(engine, now_fn) if store == "database" else RateLimiter(now_fn)
    app.state.trusted_proxies = parse_trusted_proxies(os.environ.get("KEYGUARD_TRUSTED_PROXIES"))
    hsts = os.environ.get("KEYGUARD_HSTS") == "1"

    @app.middleware("http")
    async def per_client_limit(request: Request, call_next):
        if request.url.path.startswith("/api/") and request.method != "OPTIONS":
            # Run in a worker thread: the database store does I/O and must not block the event loop.
            retry = await run_in_threadpool(
                app.state.limiter.hit, "client", client_address(request), app.state.rate_limits.client
            )
            if retry is not None:
                return error_response(429, "RATE_LIMITED", "Too many requests", {"Retry-After": str(retry)})
        return await call_next(request)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        h = response.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("X-Frame-Options", "DENY")
        if request.url.path.startswith("/api/"):
            # JSON only: nothing here should ever be rendered, framed or cached.
            h.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
            h.setdefault("Cache-Control", "no-store")
        if hsts:
            h.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    # Added last so it is outermost: CORS headers are present even on 429 responses.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.environ.get("KEYGUARD_WEB_ORIGIN", "http://localhost:3000").split(","),
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type", "X-KeyGuard-CSRF"],
        allow_credentials=True,  # the account session cookie (D-012); origins are an explicit list, never "*"
        expose_headers=["Retry-After"],
    )
    install_error_handlers(app)
    app.include_router(labs.router)
    app.include_router(keys.router)
    app.include_router(auth.router)
    app.include_router(lab.router)
    app.include_router(events.router)
    app.include_router(account.router)

    @app.get("/api/health")
    def health():
        """Liveness plus a database round trip, so a host's health check catches a broken database (D-013)."""
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception:  # noqa: BLE001 - report unhealthy, never leak the error
            return error_response(503, "DATABASE_UNAVAILABLE", "Database unavailable")
        return {"status": "ok", "database": engine.dialect.name}

    return app


async def _cleanup_loop(engine, now_fn: Callable[[], int], interval: int) -> None:
    while True:
        try:
            report = await asyncio.to_thread(run_cleanup, engine, now=now_fn())
            if report.labs_deleted or report.challenges_deleted or report.events_trimmed or report.auth_rows_deleted:
                log.info("cleanup: %s", report)
        except Exception:  # keep the loop alive; the next pass retries
            log.exception("cleanup pass failed")
        await asyncio.sleep(interval)
