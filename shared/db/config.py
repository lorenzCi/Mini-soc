import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class DatabaseSettings:
    host: str
    port: int
    user: str
    password: str
    database: str

    @classmethod
    def from_env(cls) -> "DatabaseSettings":
        return cls(
            host=os.getenv("MYSQL_HOST", "127.0.0.1"),
            port=int(os.getenv("MYSQL_PORT", "3306")),
            user=os.getenv("MYSQL_USER", "root"),
            password=os.getenv("MYSQL_PASSWORD", ""),
            database=os.getenv("MYSQL_DATABASE", "mini_soc"),
        )


def connection_kwargs(settings: DatabaseSettings | None = None) -> dict:
    s = settings or DatabaseSettings.from_env()
    return {
        "host": s.host,
        "port": s.port,
        "user": s.user,
        "password": s.password,
        "database": s.database,
        "charset": "utf8mb4",
        "cursorclass": None,  # set by caller if needed
    }
