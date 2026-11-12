"""Choose the database for test runs and evidence runs.

By default every test (and every matrix scenario) gets its own SQLite file. Setting KEYGUARD_TEST_DATABASE_URL
to a PostgreSQL URL runs the same tests against PostgreSQL instead: the schema is dropped and recreated before
each test, so tests stay independent. CI runs the suite both ways.
"""

from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import create_engine

from app.models.tables import metadata

ENV = "KEYGUARD_TEST_DATABASE_URL"


def fresh_database_url(tmpdir: Path, name: str = "kg.db") -> str:
    shared = os.environ.get(ENV)
    if not shared:
        return f"sqlite:///{Path(tmpdir) / name}"
    engine = create_engine(shared)
    try:
        metadata.drop_all(engine)
    finally:
        engine.dispose()
    return shared


def target_dialect() -> str:
    url = os.environ.get(ENV, "")
    return url.split(":", 1)[0].split("+", 1)[0] if url else "sqlite"
