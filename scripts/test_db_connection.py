#!/usr/bin/env python3
"""Verify MySQL connectivity and that mini_soc tables exist."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from shared.db.config import DatabaseSettings
from shared.db.connection import get_connection

EXPECTED_TABLES = (
    "detection_rules",
    "packets",
    "users",
    "alerts",
    "alert_packets",
    "alert_actions",
    "detection_stats_hourly",
)


def main() -> int:
    settings = DatabaseSettings.from_env()
    print(f"Connecting to {settings.user}@{settings.host}:{settings.port}/{settings.database} ...")

    try:
        conn = get_connection(settings)
    except Exception as exc:

        
        print(f"FAILED: {exc}")
        print("\nCheck .env (copy from .env.example) and that MySQL is running in phpMyAdmin/XAMPP/MAMP.")
        return 1

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT DATABASE() AS db")
            row = cur.fetchone()
            print(f"OK — connected, database: {row['db']}")

            cur.execute("SHOW TABLES")
            tables = {r[f"Tables_in_{settings.database}"] for r in cur.fetchall()}
            missing = [t for t in EXPECTED_TABLES if t not in tables]
            if missing:
                print(f"WARNING — missing tables: {', '.join(missing)}")
                print("Import schemaMySql.sql in phpMyAdmin (Import tab) or run the SQL file.")
                return 2
            print(f"OK — all {len(EXPECTED_TABLES)} tables present.")
    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
