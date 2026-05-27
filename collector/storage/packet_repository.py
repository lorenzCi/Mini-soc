"""Insert normalized packets into the `packets` table."""

from datetime import datetime, timezone

import pymysql

from collector.sniffer.models import PacketRecord
from shared.net.ip import ip_to_varbinary

_INSERT_SQL = """
INSERT INTO packets (
    captured_at,
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    protocol,
    packet_size,
    tcp_flags,
    payload_hash,
    payload_preview
) VALUES (
    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
)
"""


def _to_mysql_datetime(value: datetime) -> datetime:
    """MySQL DATETIME has no timezone; store UTC as naive."""
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def insert_packet(conn: pymysql.Connection, record: PacketRecord) -> int:
    """
    Persist one PacketRecord. Returns the new `packets.id`.
    Caller should commit when appropriate (e.g. after each packet in live capture).
    """
    with conn.cursor() as cur:
        cur.execute(
            _INSERT_SQL,
            (
                _to_mysql_datetime(record.captured_at),
                ip_to_varbinary(record.src_ip),
                ip_to_varbinary(record.dst_ip),
                record.src_port,
                record.dst_port,
                record.protocol.value,
                record.packet_size,
                record.tcp_flags,
                record.payload_hash,
                record.payload_preview,
            ),
        )
        return int(cur.lastrowid)
