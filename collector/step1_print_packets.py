#!/usr/bin/env python3
"""
Step 1 — Packet sniffer (observe only, no database).

Run from project root:
  source .venv/bin/activate
  pip install -r requirements.txt
  python collector/step1_print_packets.py --count 5

On macOS live capture usually needs root:
  sudo .venv/bin/python collector/step1_print_packets.py --count 5

Generate traffic in another terminal (ping, browse a site) while it runs.
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Step 1: capture packets and print them")
    parser.add_argument(
        "--count",
        type=int,
        default=5,
        help="How many packets to capture then stop (default: 5)",
    )
    parser.add_argument(
        "--iface",
        default=None,
        help='Network interface, e.g. en0 (default: Scapy default)',
    )
    parser.add_argument(
        "--filter",
        default=None,
        help='BPF filter, e.g. "tcp" or "host 8.8.8.8"',
    )
    parser.add_argument(
        "--list-ifaces",
        action="store_true",
        help="Show available interfaces and exit",
    )
    args = parser.parse_args()

    if args.list_ifaces:
        print("Default interface:", conf.iface)
        print("Available interfaces:")
        for name in get_if_list():
            print(f"  - {name}")
        return 0

    seen = 0

    def on_packet(raw: Packet) -> None:
        nonlocal seen
        seen += 1
        record = parse_packet(raw)
        print(f"{seen:>3}  {record.summary()}")

    print(
        f"Capturing {args.count} packet(s) on interface "
        f"{args.iface or conf.iface!r} … (Ctrl+C to abort)\n"
    )
    try:
        capture_live(
            count=args.count,
            interface=args.iface,
            bpf_filter=args.filter,
            on_packet=on_packet,
        )
    except PermissionError:
        print(
            "\nPermission denied — on macOS run with sudo, e.g.:\n"
            "  sudo .venv/bin/python collector/step1_print_packets.py --count 5\n"
        )
        return 1
    except KeyboardInterrupt:
        print("\nStopped.")
        return 0

    print(f"\nDone. Parsed {seen} packet(s). (Not saved to MySQL yet — that's Step 2.)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
