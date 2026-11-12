"""Engine setup. SQLite writes use BEGIN IMMEDIATE so conditional updates serialize cleanly."""

from __future__ import annotations

from sqlalchemy import Engine, create_engine, event, inspect

from app.models.tables import metadata


def _create_schema(engine: Engine) -> None:
    metadata.create_all(engine)
    # No migrations in the MVP: lab data is disposable (24 h TTL). Refuse to run on a stale schema rather than
    # failing later with confusing SQL errors.
    insp = inspect(engine)
    for table in metadata.sorted_tables:
        missing = {c.name for c in table.columns} - {c["name"] for c in insp.get_columns(table.name)}
        if missing:
            raise RuntimeError(
                f"Database schema is out of date ({table.name} lacks {sorted(missing)}). "
                "Lab data is disposable: delete the database file (default ./keyguard.db) and restart."
            )


def normalize_url(url: str) -> str:
    """Hosted Postgres providers hand out `postgres://` or `postgresql://` URLs; use the psycopg 3 driver for both."""
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix):]
    return url


def make_engine(url: str) -> Engine:
    url = normalize_url(url)
    if not url.startswith("sqlite"):
        # pre_ping: serverless Postgres (e.g. Neon) closes idle connections; check before reuse.
        engine = create_engine(url, pool_pre_ping=True)
        _create_schema(engine)
        return engine

    engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30})

    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_conn, _record):
        # Let SQLAlchemy own transaction boundaries instead of pysqlite's implicit BEGIN.
        dbapi_conn.isolation_level = None
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys = ON")
        cur.execute("PRAGMA journal_mode = WAL")
        cur.close()

    @event.listens_for(engine, "begin")
    def _on_begin(conn):
        conn.exec_driver_sql("BEGIN IMMEDIATE")

    _create_schema(engine)
    return engine
