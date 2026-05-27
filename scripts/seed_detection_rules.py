#!/usr/bin/env python3
"""
Seed a baseline set of detection_rules into MySQL.

Idempotent: uses the unique `name` column (INSERT ... ON DUPLICATE KEY UPDATE).

Run:
  source .venv/bin/activate
  python scripts/seed_detection_rules.py
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from shared.db.connection import db_session


def _upsert_rule(
    *,
    name: str,
    description: str,
    severity: str,
    rule_type: str,
    enabled: bool,
    conditions: dict,
) -> None:
    with db_session() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO detection_rules (
              name, description, enabled, severity, rule_type, conditions
            ) VALUES (
              %s, %s, %s, %s, %s, %s
            )
            ON DUPLICATE KEY UPDATE
              description = VALUES(description),
              enabled = VALUES(enabled),
              severity = VALUES(severity),
              rule_type = VALUES(rule_type),
              conditions = VALUES(conditions)
            """,
            (
                name,
                description,
                1 if enabled else 0,
                severity,
                rule_type,
                json.dumps(conditions, separators=(",", ":")),
            ),
        )


def main() -> int:
    rules = [
        {
            "name": "TCP to SSH (22)",
            "description": "Detect TCP packets destined to SSH (port 22).",
            "severity": "low",
            "rule_type": "signature",
            "enabled": True,
            "conditions": {
                "all": [
                    {"field": "protocol", "op": "eq", "value": "tcp"},
                    {"field": "dst_port", "op": "eq", "value": 22},
                ]
            },
        },
        {
            "name": "TCP to RDP (3389)",
            "description": "Detect TCP packets destined to RDP (port 3389).",
            "severity": "medium",
            "rule_type": "signature",
            "enabled": True,
            "conditions": {
                "all": [
                    {"field": "protocol", "op": "eq", "value": "tcp"},
                    {"field": "dst_port", "op": "eq", "value": 3389},
                ]
            },
        },
        {
            "name": "TCP to SMB (445)",
            "description": "Detect TCP packets destined to SMB (port 445).",
            "severity": "medium",
            "rule_type": "signature",
            "enabled": True,
            "conditions": {
                "all": [
                    {"field": "protocol", "op": "eq", "value": "tcp"},
                    {"field": "dst_port", "op": "eq", "value": 445},
                ]
            },
        },
        {
            "name": "HTTP request in payload preview",
            "description": "Detect basic HTTP methods visible in payload_preview (best-effort).",
            "severity": "low",
            "rule_type": "signature",
            "enabled": True,
            "conditions": {
                "all": [
                    {"field": "protocol", "op": "eq", "value": "tcp"},
                    {"field": "payload_preview", "op": "regex", "value": r"^utf8:(GET|POST|HEAD|PUT|DELETE|OPTIONS)\b"},
                ]
            },
        },
        {
            "name": "Suspicious: bash -i reverse shell string",
            "description": "Detect common reverse shell substring in payload_preview.",
            "severity": "high",
            "rule_type": "signature",
            "enabled": True,
            "conditions": {
                "any": [
                    {"field": "payload_preview", "op": "contains", "value": "bash -i"},
                    {"field": "payload_preview", "op": "contains", "value": "/dev/tcp/"},
                    {"field": "payload_preview", "op": "contains", "value": "nc -e"},
                ]
            },
        },
        {
            "name": "Large packet size (>= 1400 bytes)",
            "description": "Heuristic: very large packets can be interesting for tunneling/exfil; tune later.",
            "severity": "low",
            "rule_type": "custom",
            "enabled": False,
            "conditions": {"clause": {"field": "packet_size", "op": "gte", "value": 1400}},
        },
        {
            "name": "TCP to MySQL (3306)",
            "description": "Detect TCP traffic to MySQL default port 3306.",
            "severity": "low",
            "rule_type": "signature",
            "enabled": True,
            "conditions": {
                "all": [
                    {"field": "protocol", "op": "eq", "value": "tcp"},
                    {"field": "dst_port", "op": "eq", "value": 3306},
                ]
            },
        },
        {
            "name": "TCP to Telnet (23)",
            "description": "Detect TCP traffic to Telnet (cleartext remote access).",
            "severity": "medium",
            "rule_type": "signature",
            "enabled": True,
            "conditions": {
                "all": [
                    {"field": "protocol", "op": "eq", "value": "tcp"},
                    {"field": "dst_port", "op": "eq", "value": 23},
                ]
            },
        },
        {
            "name": "UDP to DNS (53)",
            "description": "Detect UDP DNS queries/responses on port 53.",
            "severity": "low",
            "rule_type": "signature",
            "enabled": True,
            "conditions": {
                "all": [
                    {"field": "protocol", "op": "eq", "value": "udp"},
                    {"field": "dst_port", "op": "eq", "value": 53},
                ]
            },
        },
        {
            "name": "ICMP traffic",
            "description": "Detect ICMP packets (ping, traceroute, etc.).",
            "severity": "low",
            "rule_type": "signature",
            "enabled": True,
            "conditions": {"clause": {"field": "protocol", "op": "eq", "value": "icmp"}},
        },
        {
            "name": "TCP to FTP (21)",
            "description": "Detect TCP traffic to FTP control port 21.",
            "severity": "medium",
            "rule_type": "signature",
            "enabled": True,
            "conditions": {
                "all": [
                    {"field": "protocol", "op": "eq", "value": "tcp"},
                    {"field": "dst_port", "op": "eq", "value": 21},
                ]
            },
        },
        {
            "name": "TCP to Redis (6379)",
            "description": "Detect TCP traffic to Redis default port 6379.",
            "severity": "medium",
            "rule_type": "signature",
            "enabled": True,
            "conditions": {
                "all": [
                    {"field": "protocol", "op": "eq", "value": "tcp"},
                    {"field": "dst_port", "op": "eq", "value": 6379},
                ]
            },
        },
        {
            "name": "Suspicious: PowerShell in payload",
            "description": "Detect PowerShell-related strings in payload_preview.",
            "severity": "high",
            "rule_type": "signature",
            "enabled": True,
            "conditions": {
                "any": [
                    {"field": "payload_preview", "op": "contains", "value": "powershell"},
                    {"field": "payload_preview", "op": "contains", "value": "PowerShell"},
                    {"field": "payload_preview", "op": "contains", "value": "-EncodedCommand"},
                ]
            },
        },
        {
            "name": "Suspicious: SQL injection pattern in payload",
            "description": "Detect common SQLi substrings in payload_preview.",
            "severity": "high",
            "rule_type": "signature",
            "enabled": True,
            "conditions": {
                "any": [
                    {"field": "payload_preview", "op": "regex", "value": "(?i)union\\s+select"},
                    {"field": "payload_preview", "op": "contains", "value": "' OR '1'='1"},
                    {"field": "payload_preview", "op": "contains", "value": "1=1--"},
                ]
            },
        },
        {
            "name": "TCP SYN without ACK (possible scan)",
            "description": "Heuristic: TCP SYN flag set without ACK (single-packet signal).",
            "severity": "low",
            "rule_type": "port_scan",
            "enabled": True,
            "conditions": {
                "all": [
                    {"field": "protocol", "op": "eq", "value": "tcp"},
                    {"field": "tcp_flags", "op": "contains", "value": "S"},
                    {"field": "tcp_flags", "op": "not_contains", "value": "A"},
                ]
            },
        },
    ]

    for r in rules:
        _upsert_rule(**r)

    print(f"Seeded {len(rules)} rule(s) into `detection_rules` (upsert).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

