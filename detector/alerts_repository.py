from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import pymysql

from detector.models import DetectionRule, PacketRow
from shared.net.ip import ip_to_varbinary

_OPEN_STATUSES = ("new", "acknowledged", "investigating")


def _to_mysql_datetime(value: datetime) -> datetime:
    """MySQL DATETIME has no timezone; store UTC as naive."""
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _find_open_correlated_alert(
    conn: pymysql.Connection,
    *,
    rule_id: int,
    packet: PacketRow,
    window_start: datetime,
) -> int | None:
    """
    Find an existing open alert for the same rule + 5-tuple (best-effort).
    Used to avoid alert storms on repetitive traffic.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id
            FROM alerts
            WHERE rule_id = %s
              AND status IN ('new', 'acknowledged', 'investigating')
              AND src_ip <=> %s
              AND dst_ip <=> %s
              AND src_port <=> %s
              AND dst_port <=> %s
              AND protocol <=> %s
              AND last_seen_at >= %s
            ORDER BY last_seen_at DESC
            LIMIT 1
            """,
            (
                rule_id,
                ip_to_varbinary(packet.src_ip),
                ip_to_varbinary(packet.dst_ip),
                packet.src_port,
                packet.dst_port,
                packet.protocol,
                _to_mysql_datetime(window_start),
            ),
        )
        row = cur.fetchone()
    if not row:
        return None
    return int(row["id"])


def _create_alert(
    conn: pymysql.Connection,
    *,
    rule: DetectionRule,
    packet: PacketRow,
    evidence: dict[str, Any],
) -> int:
    title = f"{rule.name} ({packet.protocol.upper()})"
    description = rule.description or f"Rule {rule.name} matched packet {packet.id}"

    first_last = _to_mysql_datetime(packet.captured_at)
    evidence_json = json.dumps(evidence, separators=(",", ":"))

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO alerts (
              rule_id,
              title,
              description,
              severity,
              src_ip,
              dst_ip,
              src_port,
              dst_port,
              protocol,
              event_count,
              first_seen_at,
              last_seen_at,
              evidence
            ) VALUES (
              %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
            )
            """,
            (
                rule.id,
                title,
                description,
                rule.severity,
                ip_to_varbinary(packet.src_ip),
                ip_to_varbinary(packet.dst_ip),
                packet.src_port,
                packet.dst_port,
                packet.protocol,
                1,
                first_last,
                first_last,
                evidence_json,
            ),
        )
        alert_id = int(cur.lastrowid)

        cur.execute(
            """
            INSERT INTO alert_packets (alert_id, packet_id, role)
            VALUES (%s, %s, 'trigger')
            """,
            (alert_id, packet.id),
        )

        cur.execute(
            """
            INSERT INTO alert_actions (alert_id, user_id, action, comment, metadata)
            VALUES (%s, NULL, 'created', NULL, %s)
            """,
            (alert_id, json.dumps({"source": "live_engine"}, separators=(",", ":"))),
        )

    return alert_id


def _correlate_alert(
    conn: pymysql.Connection,
    *,
    alert_id: int,
    packet: PacketRow,
    evidence: dict[str, Any],
) -> int:
    """Bump an existing alert and attach the new packet as related."""
    last_seen = _to_mysql_datetime(packet.captured_at)
    evidence_json = json.dumps(evidence, separators=(",", ":"))

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE alerts
            SET
              event_count = event_count + 1,
              last_seen_at = %s,
              evidence = %s
            WHERE id = %s
            """,
            (last_seen, evidence_json, alert_id),
        )

        cur.execute(
            """
            INSERT IGNORE INTO alert_packets (alert_id, packet_id, role)
            VALUES (%s, %s, 'related')
            """,
            (alert_id, packet.id),
        )

        cur.execute("SELECT event_count FROM alerts WHERE id = %s", (alert_id,))
        row = cur.fetchone()

    return int(row["event_count"]) if row else 0


def process_rule_match(
    conn: pymysql.Connection,
    *,
    rule: DetectionRule,
    packet: PacketRow,
    evidence: dict[str, Any],
    correlate_window_secs: int = 300,
) -> tuple[int, Literal["created", "correlated"]]:
    """
    Create a new alert or correlate into an existing open one.

    Correlation key: rule_id + src/dst IP + ports + protocol, within time window.
    """
    if correlate_window_secs > 0:
        window_start = packet.captured_at
        if window_start.tzinfo is None:
            window_start = window_start.replace(tzinfo=timezone.utc)
        window_start = window_start - timedelta(seconds=correlate_window_secs)

        existing_id = _find_open_correlated_alert(
            conn,
            rule_id=rule.id,
            packet=packet,
            window_start=window_start,
        )
        if existing_id is not None:
            _correlate_alert(
                conn,
                alert_id=existing_id,
                packet=packet,
                evidence=evidence,
            )
            return existing_id, "correlated"

    alert_id = _create_alert(conn, rule=rule, packet=packet, evidence=evidence)
    return alert_id, "created"


def create_alert_for_match(
    conn: pymysql.Connection,
    *,
    rule: DetectionRule,
    packet: PacketRow,
    evidence: dict[str, Any],
) -> int:
    """Backward-compatible: always creates a new alert (no correlation)."""
    alert_id, _ = process_rule_match(
        conn,
        rule=rule,
        packet=packet,
        evidence=evidence,
        correlate_window_secs=0,
    )
    return alert_id
