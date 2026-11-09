"""FastAPI application factory.

    uv run uvicorn app.main:create_app --factory --reload --port 8000
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.db import make_engine
from app.errors import install_error_handlers
from app.routes import auth, keys, lab, labs


def create_app(database_url: str | None = None, clock: Callable[[], int] | None = None) -> FastAPI:
    app = FastAPI(title="KeyGuard API", version="0.1.0")
    app.state.engine = make_engine(database_url or os.environ.get("KEYGUARD_DATABASE_URL", "sqlite:///./keyguard.db"))
    app.state.clock = clock or (lambda: int(time.time()))

    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.environ.get("KEYGUARD_WEB_ORIGIN", "http://localhost:3000").split(","),
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )
    install_error_handlers(app)
    app.include_router(labs.router)
    app.include_router(keys.router)
    app.include_router(auth.router)
    app.include_router(lab.router)

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok"}

    return app
