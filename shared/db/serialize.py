import json
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from shared.net.ip import varbinary_to_ip


def _json_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def row_to_json(row: dict[str, Any]) -> dict[str, Any]:
    """Convert a MySQL DictCursor row to JSON-safe primitives."""
    out: dict[str, Any] = {}
    for key, value in row.items():
        if key in ("src_ip", "dst_ip"):
            out[key] = varbinary_to_ip(value)
        elif key in ("evidence", "conditions", "metadata"):
            out[key] = _json_value(value)
        elif isinstance(value, datetime):
            out[key] = value.isoformat(timespec="milliseconds")
        elif isinstance(value, date):
            out[key] = value.isoformat()
        elif isinstance(value, Decimal):
            out[key] = float(value)
        elif isinstance(value, bytes):
            out[key] = value.hex()
        elif key == "enabled" and value is not None:
            out[key] = bool(value)
        else:
            out[key] = value
    return out
