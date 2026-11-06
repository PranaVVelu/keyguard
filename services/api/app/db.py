"""Engine setup. SQLite writes use BEGIN IMMEDIATE so conditional updates serialize cleanly."""

from __future__ import annotations

from sqlalchemy import Engine, create_engine, event

from app.models.tables import metadata


def make_engine(url: str) -> Engine:
    if not url.startswith("sqlite"):
        engine = create_engine(url)
        metadata.create_all(engine)
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

    metadata.create_all(engine)
    return engine
