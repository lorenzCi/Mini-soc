#!/usr/bin/env python3
"""
One-command live Mini-SOC runner:
- sniff packets continuously
- insert into `packets`
- apply enabled `detection_rules`
- on match, create `alerts` + `alert_packets` + `alert_actions`

Stop with Ctrl+C.

Run (macOS usually needs sudo):
  sudo .venv/bin/python collector/run_live_soc.py --iface en0 --filter "ip"
"""

import argparse
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pymysql
from scapy.all import conf, get_if_list
from scapy.packet import Packet

from collector.sniffer.capture import capture_live
from collector.sniffer.parser import parse_packet
from collector.storage.packet_repository import insert_packet
from detector.alerts_repository import process_rule_match
from detector.engine import rule_matches_packet
from detector.models import PacketRow
from detector.rules_repository import load_enabled_rules
from shared.db.connection import db_session

logger = logging.getLogger(__name__)


def _record_to_packet_row(packet_id: int, record) -> PacketRow:
    return PacketRow(
        id=packet_id,
        captured_at=record.captured_at,
        src_ip=record.src_ip,
        dst_ip=record.dst_ip,
        src_port=record.src_port,
        dst_port=record.dst_port,
        protocol=record.protocol.value,
        packet_size=record.packet_size,
        tcp_flags=record.tcp_flags,
        payload_hash=record.payload_hash,
        payload_preview=record.payload_preview,
    )


def _build_match_evidence(packet_row: PacketRow, rule_eval: dict) -> dict:
    return {
        "packet": {
            "id": packet_row.id,
            "captured_at": packet_row.captured_at.isoformat(timespec="milliseconds"),
            "src_ip": packet_row.src_ip,
            "dst_ip": packet_row.dst_ip,
            "src_port": packet_row.src_port,
            "dst_port": packet_row.dst_port,
            "protocol": packet_row.protocol,
            "tcp_flags": packet_row.tcp_flags,
            "packet_size": packet_row.packet_size,
            "payload_hash": packet_row.payload_hash,
            "payload_preview": packet_row.payload_preview,
        },
        "rule_eval": rule_eval,
    }


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="Run live Mini-SOC pipeline (Ctrl+C to stop)")
    parser.add_argument("--iface", default=None, help="Interface, e.g. en0")
    parser.add_argument("--filter", default="ip", help='BPF filter (default: "ip")')
    parser.add_argument(
        "--reload-rules-every",
        type=int,
        default=200,
        help="Reload enabled rules every N packets (default: 200)",
    )
    parser.add_argument(
        "--correlate-window-secs",
        type=int,
        default=300,
        help="Merge repeats into same open alert within N seconds (default: 300, 0=off)",
    )
    parser.add_argument(
        "--ping-every",
        type=int,
        default=100,
        help="MySQL connection ping/reconnect every N packets (default: 100)",
    )
    parser.add_argument("--list-ifaces", action="store_true", help="Show interfaces and exit")
    args = parser.parse_args()

    if args.list_ifaces:
        print("Default interface:", conf.iface)
        for name in get_if_list():
            print(f"  - {name}")
        return 0

    seen = 0
    errors = 0
    alerts_created = 0
    alerts_correlated = 0

    print(
        f"Live SOC running on {args.iface or conf.iface!r} filter={args.filter!r}\n"
        f"- inserts into `packets`\n"
        f"- evaluates enabled `detection_rules`\n"
        f"- writes `alerts` on match (correlates repeats within {args.correlate_window_secs}s)\n"
        f"Stop with Ctrl+C.\n"
    )

    with db_session() as conn:
        conn.autocommit(False)
        rules = load_enabled_rules(conn)
        print(f"Loaded {len(rules)} enabled rule(s).")

        def on_packet(raw: Packet) -> None:
            nonlocal seen, errors, alerts_created, alerts_correlated, rules
            seen += 1

            if args.ping_every > 0 and (seen % args.ping_every) == 0:
                conn.ping(reconnect=True)

            if args.reload_rules_every > 0 and (seen % args.reload_rules_every) == 0:
                rules = load_enabled_rules(conn)

            try:
                record = parse_packet(raw)
                packet_id = insert_packet(conn, record)
                packet_row = _record_to_packet_row(packet_id, record)

                matched_any = False
                for rule in rules:
                    ok, evidence = rule_matches_packet(rule, packet_row)
                    if not ok:
                        continue
                    matched_any = True
                    alert_id, outcome = process_rule_match(
                        conn,
                        rule=rule,
                        packet=packet_row,
                        evidence=_build_match_evidence(packet_row, evidence),
                        correlate_window_secs=args.correlate_window_secs,
                    )
                    if outcome == "created":
                        alerts_created += 1
                        print(
                            f"ALERT NEW id={alert_id} rule={rule.name!r} sev={rule.severity} "
                            f"packet_id={packet_id} {record.summary()}"
                        )
                    else:
                        alerts_correlated += 1
                        print(
                            f"ALERT +1 id={alert_id} rule={rule.name!r} sev={rule.severity} "
                            f"packet_id={packet_id} (correlated) {record.summary()}"
                        )

                conn.commit()

                if not matched_any:
                    print(f"{seen:>6}  id={packet_id}  {record.summary()}")

            except pymysql.MySQLError as exc:
                conn.rollback()
                errors += 1
                logger.error("DB error on packet #%s (rolled back): %s", seen, exc)
            except Exception as exc:
                conn.rollback()
                errors += 1
                logger.error("Pipeline error on packet #%s (rolled back): %s", seen, exc)

        try:
            capture_live(
                count=None,
                interface=args.iface,
                bpf_filter=args.filter,
                on_packet=on_packet,
            )
        except PermissionError:
            print(
                "\nPermission denied — on macOS run with sudo, e.g.:\n"
                "  sudo .venv/bin/python collector/run_live_soc.py --iface en0 --filter ip\n"
            )
            return 1
        except KeyboardInterrupt:
            print(
                f"\nStopped. Packets={seen}, Errors={errors}, "
                f"Alerts created={alerts_created}, correlated={alerts_correlated}"
            )
            return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
