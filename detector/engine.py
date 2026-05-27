from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from detector.models import DetectionRule, PacketRow, RuleMatch


def _get_field(packet: PacketRow, field: str) -> Any:
    if not hasattr(packet, field):
        raise KeyError(f"Unknown packet field: {field}")
    return getattr(packet, field)


def _op_eq(actual: Any, expected: Any) -> bool:
    return actual == expected


def _op_in(actual: Any, expected_list: Any) -> bool:
    if not isinstance(expected_list, list):
        return False
    return actual in expected_list


def _op_contains(actual: Any, expected: Any) -> bool:
    if actual is None or expected is None:
        return False
    return str(expected) in str(actual)


def _op_not_contains(actual: Any, expected: Any) -> bool:
    if actual is None:
        return True
    if expected is None:
        return False
    return str(expected) not in str(actual)


def _op_regex(actual: Any, pattern: Any) -> bool:
    if actual is None or pattern is None:
        return False
    try:
        return re.search(str(pattern), str(actual)) is not None
    except re.error:
        return False


def _op_gt(actual: Any, expected: Any) -> bool:
    try:
        return actual is not None and float(actual) > float(expected)
    except Exception:
        return False


def _op_gte(actual: Any, expected: Any) -> bool:
    try:
        return actual is not None and float(actual) >= float(expected)
    except Exception:
        return False


def _op_lt(actual: Any, expected: Any) -> bool:
    try:
        return actual is not None and float(actual) < float(expected)
    except Exception:
        return False


def _op_lte(actual: Any, expected: Any) -> bool:
    try:
        return actual is not None and float(actual) <= float(expected)
    except Exception:
        return False


_OPS = {
    "eq": _op_eq,
    "in": _op_in,
    "contains": _op_contains,
    "not_contains": _op_not_contains,
    "regex": _op_regex,
    "gt": _op_gt,
    "gte": _op_gte,
    "lt": _op_lt,
    "lte": _op_lte,
}


def _coerce_value(field: str, actual: Any, expected: Any) -> tuple[Any, Any]:
    """Normalize port/number comparisons (JSON ints vs DB ints vs strings)."""
    if field.endswith("_port") or field == "packet_size":
        try:
            if actual is not None:
                actual = int(actual)
            if expected is not None:
                expected = int(expected)
        except (TypeError, ValueError):
            pass
    return actual, expected


def _evaluate_clause(packet: PacketRow, clause: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    """
    Clause format (minimal and explicit):
      { "field": "dst_port", "op": "eq", "value": 22 }
    """
    field = clause.get("field")
    op = clause.get("op", "eq")
    value = clause.get("value")

    if not isinstance(field, str) or not isinstance(op, str):
        return False, {"error": "invalid_clause", "clause": clause}

    try:
        actual = _get_field(packet, field)
    except KeyError:
        return False, {"error": "unknown_field", "field": field}

    actual, value = _coerce_value(field, actual, value)

    fn = _OPS.get(op)
    if fn is None:
        return False, {"error": "unknown_op", "op": op}

    ok = fn(actual, value)
    return ok, {"field": field, "op": op, "expected": value, "actual": actual}


def rule_matches_packet(rule: DetectionRule, packet: PacketRow) -> tuple[bool, dict[str, Any]]:
    """
    Supported conditions JSON (kept small on purpose):

    - {"all": [clause, ...]}  -> AND
    - {"any": [clause, ...]}  -> OR
    - {"clause": {...}}       -> single clause

    If conditions are malformed, we treat as no-match (safe default).
    """
    c = rule.conditions or {}
    evidence: dict[str, Any] = {"rule_type": rule.rule_type, "conditions": c, "checks": []}

    if isinstance(c, dict) and "clause" in c and isinstance(c["clause"], dict):
        ok, check = _evaluate_clause(packet, c["clause"])
        evidence["checks"].append(check)
        return ok, evidence

    if isinstance(c, dict) and "all" in c and isinstance(c["all"], list):
        all_ok = True
        for clause in c["all"]:
            if not isinstance(clause, dict):
                all_ok = False
                evidence["checks"].append({"error": "invalid_clause", "clause": clause})
                continue
            ok, check = _evaluate_clause(packet, clause)
            evidence["checks"].append(check)
            if not ok:
                all_ok = False
        return all_ok, evidence

    if isinstance(c, dict) and "any" in c and isinstance(c["any"], list):
        any_ok = False
        for clause in c["any"]:
            if not isinstance(clause, dict):
                evidence["checks"].append({"error": "invalid_clause", "clause": clause})
                continue
            ok, check = _evaluate_clause(packet, clause)
            evidence["checks"].append(check)
            if ok:
                any_ok = True
        return any_ok, evidence

    # Back-compat ultra-minimal:
    # {"field":"protocol","op":"eq","value":"tcp"}
    if isinstance(c, dict) and {"field", "op", "value"}.issubset(c.keys()):
        ok, check = _evaluate_clause(packet, c)  # type: ignore[arg-type]
        evidence["checks"].append(check)
        return ok, evidence

    return False, {"error": "unsupported_conditions", "conditions": c}


def detect_matches(
    *,
    rules: list[DetectionRule],
    packets: list[PacketRow],
) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    now = datetime.now(timezone.utc)
    for p in packets:
        for r in rules:
            ok, evidence = rule_matches_packet(r, p)
            if not ok:
                continue
            matches.append(
                RuleMatch(
                    rule_id=r.id,
                    rule_name=r.name,
                    severity=r.severity,
                    packet_id=p.id,
                    matched_at=now,
                    evidence={
                        "packet": {
                            "id": p.id,
                            "captured_at": p.captured_at.isoformat(timespec="milliseconds"),
                            "src_ip": p.src_ip,
                            "dst_ip": p.dst_ip,
                            "src_port": p.src_port,
                            "dst_port": p.dst_port,
                            "protocol": p.protocol,
                            "tcp_flags": p.tcp_flags,
                            "packet_size": p.packet_size,
                            "payload_hash": p.payload_hash,
                            "payload_preview": p.payload_preview,
                        },
                        "rule_eval": evidence,
                    },
                )
            )
    return matches

