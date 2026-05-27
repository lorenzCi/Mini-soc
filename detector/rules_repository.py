import json
import logging
from typing import Any

import pymysql

from detector.models import DetectionRule

logger = logging.getLogger(__name__)


def _parse_conditions(raw: Any) -> dict[str, Any] | None:
    if raw is None:
        return None
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else None
    return None


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
        try:
            conditions = _parse_conditions(r["conditions"])
            if not conditions:
                logger.warning("Skipping rule id=%s: invalid conditions JSON", r.get("id"))
                continue

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
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            logger.warning("Skipping rule id=%s: %s", r.get("id"), exc)
    return rules

