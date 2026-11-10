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
from fastapi.middleware.cors import CORSMiddleware

from app.db import make_engine
from app.errors import error_response, install_error_handlers
from app.routes import auth, events, keys, lab, labs
from app.security.cleanup import run_cleanup
from app.security.ratelimit import RateLimiter, RateLimits, client_address

log = logging.getLogger("keyguard")


def create_app(
    database_url: str | None = None,
    clock: Callable[[], int] | None = None,
    *,
    rate_limits: RateLimits | None = None,
    cleanup_interval: int | None = None,
) -> FastAPI:
    """`cleanup_interval` seconds between TTL cleanup passes; 0 disables the background task (tests)."""
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

    app = FastAPI(title="KeyGuard API", version="0.1.0", lifespan=lifespan)
    app.state.engine = engine
    app.state.clock = now_fn
    app.state.rate_limits = rate_limits or RateLimits.from_env()
    app.state.limiter = RateLimiter(now_fn)

    @app.middleware("http")
    async def per_client_limit(request: Request, call_next):
        if request.url.path.startswith("/api/") and request.method != "OPTIONS":
            retry = app.state.limiter.hit("client", client_address(request), app.state.rate_limits.client)
            if retry is not None:
                return error_response(429, "RATE_LIMITED", "Too many requests", {"Retry-After": str(retry)})
        return await call_next(request)

    # Added last so it is outermost: CORS headers are present even on 429 responses.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.environ.get("KEYGUARD_WEB_ORIGIN", "http://localhost:3000").split(","),
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
        expose_headers=["Retry-After"],
    )
    install_error_handlers(app)
    app.include_router(labs.router)
    app.include_router(keys.router)
    app.include_router(auth.router)
    app.include_router(lab.router)
    app.include_router(events.router)

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok"}

    return app


async def _cleanup_loop(engine, now_fn: Callable[[], int], interval: int) -> None:
    while True:
        try:
            report = await asyncio.to_thread(run_cleanup, engine, now=now_fn())
            if report.labs_deleted or report.challenges_deleted or report.events_trimmed:
                log.info("cleanup: %s", report)
        except Exception:  # keep the loop alive; the next pass retries
            log.exception("cleanup pass failed")
        await asyncio.sleep(interval)
