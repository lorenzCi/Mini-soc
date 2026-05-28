import pymysql

from shared.net.ip import varbinary_to_ip

SQL_TOTAL_ALERTS = "SELECT COUNT(*) AS total FROM alerts"

SQL_TOTAL_PACKETS = "SELECT COUNT(*) AS total FROM packets"

SQL_RULE_COUNTS = """
SELECT
  COUNT(*) AS total_rules,
  SUM(enabled = TRUE) AS enabled_rules
FROM detection_rules
"""

SQL_ALERTS_BY_SEVERITY = """
SELECT severity, COUNT(*) AS count
FROM alerts
GROUP BY severity
ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low')
"""

SQL_TOP_SOURCE_IPS = """
SELECT src_ip, COUNT(*) AS alert_count
FROM alerts
WHERE src_ip IS NOT NULL
GROUP BY src_ip
ORDER BY alert_count DESC
LIMIT %s
"""


def get_stats(conn: pymysql.Connection, *, top_ips_limit: int = 10) -> dict:
    with conn.cursor() as cur:
        cur.execute(SQL_TOTAL_ALERTS)
        total_alerts = int((cur.fetchone() or {"total": 0})["total"])

        cur.execute(SQL_TOTAL_PACKETS)
        total_packets = int((cur.fetchone() or {"total": 0})["total"])

        cur.execute(SQL_RULE_COUNTS)
        rule_row = cur.fetchone() or {"total_rules": 0, "enabled_rules": 0}
        total_rules = int(rule_row["total_rules"] or 0)
        enabled_rules = int(rule_row["enabled_rules"] or 0)

        cur.execute(SQL_ALERTS_BY_SEVERITY)
        severity_rows = cur.fetchall()

        cur.execute(SQL_TOP_SOURCE_IPS, (top_ips_limit,))
        top_ip_rows = cur.fetchall()

    alerts_by_severity = {
        str(r["severity"]): int(r["count"]) for r in severity_rows
    }

    top_source_ips = []
    for r in top_ip_rows:
        ip = varbinary_to_ip(r.get("src_ip"))
        if ip:
            top_source_ips.append(
                {"src_ip": ip, "alert_count": int(r["alert_count"])}
            )

    return {
        "total_alerts": total_alerts,
        "total_packets": total_packets,
        "total_rules": total_rules,
        "enabled_rules": enabled_rules,
        "alerts_by_severity": alerts_by_severity,
        "top_source_ips": top_source_ips,
    }
