from contextlib import contextmanager
from typing import Generator

import pymysql
from pymysql.cursors import DictCursor

from shared.db.config import DatabaseSettings, connection_kwargs


def get_connection(settings: DatabaseSettings | None = None) -> pymysql.Connection:
    kwargs = connection_kwargs(settings)
    kwargs["cursorclass"] = DictCursor
    return pymysql.connect(**kwargs)


@contextmanager
def db_session(
    settings: DatabaseSettings | None = None,
) -> Generator[pymysql.Connection, None, None]:
    conn = get_connection(settings)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
