import pymysql

from shared.db.serialize import row_to_json

# Latest captured packets (telemetry tail).
SQL_LIST_PACKETS = """
SELECT
  id,
  captured_at,
  src_ip,
  dst_ip,
  src_port,
  dst_port,
  protocol,
  packet_size,
  tcp_flags,
  payload_hash,
  payload_preview,
  created_at
FROM packets
ORDER BY captured_at DESC
LIMIT %s
"""


def list_packets(conn: pymysql.Connection, *, limit: int) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute(SQL_LIST_PACKETS, (limit,))
        rows = cur.fetchall()
    return [row_to_json(r) for r in rows]
