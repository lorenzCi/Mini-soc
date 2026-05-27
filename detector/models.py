from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal


Severity = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True)
class DetectionRule:
    id: int
    name: str
    description: str | None
    enabled: bool
    severity: Severity
    rule_type: str
    conditions: dict[str, Any]


@dataclass(frozen=True)
class PacketRow:
    id: int
    captured_at: datetime
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str
    packet_size: int | None
    tcp_flags: str | None
    payload_hash: str | None
    payload_preview: str | None


@dataclass(frozen=True)
class RuleMatch:
    rule_id: int
    rule_name: str
    severity: Severity
    packet_id: int
    matched_at: datetime
    evidence: dict[str, Any]

