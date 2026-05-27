import pymysql

from api.db.serialize import row_to_json

# Latest alerts by last activity (SOC triage order).
SQL_LIST_ALERTS = """
SELECT
  id,
  rule_id,
  title,
  description,
  severity,
  status,
  assigned_to,
  src_ip,
  dst_ip,
  src_port,
  dst_port,
  protocol,
  event_count,
  first_seen_at,
  last_seen_at,
  evidence,
  created_at,
  updated_at
FROM alerts
ORDER BY last_seen_at DESC
LIMIT %s
"""


def list_alerts(conn: pymysql.Connection, *, limit: int) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute(SQL_LIST_ALERTS, (limit,))
        rows = cur.fetchall()
    return [row_to_json(r) for r in rows]
