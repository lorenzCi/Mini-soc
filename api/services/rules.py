import pymysql

from api.db.serialize import row_to_json

SQL_LIST_RULES = """
SELECT
  id,
  name,
  description,
  enabled,
  severity,
  rule_type,
  conditions,
  mitre_technique,
  created_at,
  updated_at
FROM detection_rules
ORDER BY id ASC
"""


def list_rules(conn: pymysql.Connection) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute(SQL_LIST_RULES)
        rows = cur.fetchall()
    return [row_to_json(r) for r in rows]
