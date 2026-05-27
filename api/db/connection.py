from collections.abc import Generator

import pymysql
from pymysql.cursors import DictCursor

from shared.db.config import DatabaseSettings, connection_kwargs


def get_connection(settings: DatabaseSettings | None = None) -> pymysql.Connection:
    kwargs = connection_kwargs(settings)
    kwargs["cursorclass"] = DictCursor
    conn = pymysql.connect(**kwargs)
    conn.autocommit(True)
    return conn


def get_db() -> Generator[pymysql.Connection, None, None]:
    """FastAPI dependency: one read-only connection per request."""
    conn = get_connection()
    try:
        yield conn
    finally:
        conn.close()
