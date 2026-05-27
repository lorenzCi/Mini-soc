from __future__ import annotations

import pymysql

from detector.models import PacketRow
from shared.net.ip import varbinary_to_ip


def fetch_packets_after_id(
    conn: pymysql.Connection,
    *,
    after_id: int,
    limit: int = 500,
) -> list[PacketRow]:
    with conn.cursor() as cur:
        cur.execute(
            """
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
              payload_preview
            FROM packets
            WHERE id > %s
            ORDER BY id ASC
            LIMIT %s
            """,
            (after_id, limit),
        )
        rows = cur.fetchall()

    packets: list[PacketRow] = []
    for r in rows:
        packets.append(
            PacketRow(
                id=int(r["id"]),
                captured_at=r["captured_at"],
                src_ip=varbinary_to_ip(r.get("src_ip")),
                dst_ip=varbinary_to_ip(r.get("dst_ip")),
                src_port=r.get("src_port"),
                dst_port=r.get("dst_port"),
                protocol=str(r["protocol"]),
                packet_size=r.get("packet_size"),
                tcp_flags=r.get("tcp_flags"),
                payload_hash=r.get("payload_hash"),
                payload_preview=r.get("payload_preview"),
            )
        )
    return packets

