from collections.abc import Generator
from contextlib import contextmanager

import pymysql
from pymysql.cursors import DictCursor

from shared.db.config import DatabaseSettings, connection_kwargs


def get_connection(
    settings: DatabaseSettings | None = None,
    *,
    read_only: bool = False,
) -> pymysql.Connection:
    """
    Open a MySQL connection.

    read_only=True  → autocommit on (FastAPI GET handlers)
    read_only=False → autocommit off (collector / live pipeline transactions)
    """
    kwargs = connection_kwargs(settings)
    kwargs["cursorclass"] = DictCursor
    conn = pymysql.connect(**kwargs)
    conn.autocommit(read_only)
    return conn


@contextmanager
def db_session(
    settings: DatabaseSettings | None = None,
) -> Generator[pymysql.Connection, None, None]:
    """Transactional session for write pipelines (commit on success, rollback on error)."""
    conn = get_connection(settings, read_only=False)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_db() -> Generator[pymysql.Connection, None, None]:
    """FastAPI dependency: one read-only connection per request."""
    conn = get_connection(read_only=True)
    try:
        yield conn
    finally:
        conn.close()
