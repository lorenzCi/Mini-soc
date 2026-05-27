import json
from typing import Any

import pymysql

from detector.models import DetectionRule


def load_enabled_rules(conn: pymysql.Connection) -> list[DetectionRule]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
              id, name, description, enabled, severity, rule_type, conditions
            FROM detection_rules
            WHERE enabled = TRUE
            ORDER BY id ASC
            """
        )
        rows = cur.fetchall()

    rules: list[DetectionRule] = []
    for r in rows:
        conditions_raw = r["conditions"]
        conditions: dict[str, Any]
        if isinstance(conditions_raw, (bytes, bytearray)):
            conditions = json.loads(conditions_raw.decode("utf-8"))
        elif isinstance(conditions_raw, str):
            conditions = json.loads(conditions_raw)
        else:
            # PyMySQL can already return a dict depending on server/client settings.
            conditions = conditions_raw

        rules.append(
            DetectionRule(
                id=int(r["id"]),
                name=str(r["name"]),
                description=r.get("description"),
                enabled=bool(r["enabled"]),
                severity=str(r["severity"]),
                rule_type=str(r["rule_type"]),
                conditions=conditions,
            )
        )
    return rules

