#!/usr/bin/env python3
"""
Step 2 — Capture packets and save them to MySQL (`packets` table).

Run from project root:
  .venv/bin/python scripts/test_db_connection.py
  sudo .venv/bin/python collector/step2_save_packets.py --count 10 --iface en0 --filter ip

Verify in phpMyAdmin:
  SELECT id, captured_at, protocol, packet_size FROM packets ORDER BY id DESC LIMIT 10;
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scapy.all import conf, get_if_list
from scapy.packet import Packet

from collector.sniffer.capture import capture_live
from collector.sniffer.parser import parse_packet
from collector.storage.packet_repository import insert_packet
from shared.db.connection import db_session


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Step 2: capture packets and insert into MySQL"
    )
    parser.add_argument("--count", type=int, default=10, help="Packets to capture")
    parser.add_argument("--iface", default=None, help="Interface, e.g. en0")
    parser.add_argument("--filter", default="ip", help='BPF filter (default: "ip")')
    parser.add_argument(
        "--list-ifaces",
        action="store_true",
        help="Show interfaces and exit",
    )
    args = parser.parse_args()

    if args.list_ifaces:
        print("Default interface:", conf.iface)
        for name in get_if_list():
            print(f"  - {name}")
        return 0

    saved = 0

    print(
        f"Capturing {args.count} packet(s) on {args.iface or conf.iface!r} "
        f"→ MySQL table `packets` …\n"
    )

    try:
        with db_session() as conn:
            def on_packet(raw: Packet) -> None:
                nonlocal saved
                record = parse_packet(raw)
                packet_id = insert_packet(conn, record)
                conn.commit()
                saved += 1
                print(f"{saved:>3}  id={packet_id}  {record.summary()}")

            capture_live(
                count=args.count,
                interface=args.iface,
                bpf_filter=args.filter,
                on_packet=on_packet,
            )
    except PermissionError:
        print(
            "\nPermission denied — on macOS run with sudo, e.g.:\n"
            "  sudo .venv/bin/python collector/step2_save_packets.py --count 10 --iface en0\n"
        )
        return 1
    except KeyboardInterrupt:
        print("\nStopped.")
        return 0

    print(f"\nDone. Saved {saved} row(s) to `packets`.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
