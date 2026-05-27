#!/usr/bin/env python3
"""
Step 3 — Detection engine (read packets, apply enabled detection_rules).

This step does NOT write alerts yet; it only prints rule matches.
Step 4 will persist to `alerts` and `alert_packets`.

Run from project root:
  .venv/bin/python collector/step3_detect_packets.py --after-id 0 --limit 200
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from detector.engine import detect_matches
from detector.packets_repository import fetch_packets_after_id
from detector.rules_repository import load_enabled_rules
from shared.db.connection import db_session


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Step 3: read packets from MySQL, apply enabled detection rules"
    )
    parser.add_argument("--after-id", type=int, default=0, help="Process packets with id > this")
    parser.add_argument("--limit", type=int, default=200, help="Max packets to read in one run")
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print match evidence JSON",
    )
    args = parser.parse_args()

    with db_session() as conn:
        rules = load_enabled_rules(conn)
        packets = fetch_packets_after_id(conn, after_id=args.after_id, limit=args.limit)

    print(f"Loaded {len(rules)} enabled rule(s).")
    print(f"Fetched {len(packets)} packet(s) after id>{args.after_id}.")

    matches = detect_matches(rules=rules, packets=packets)
    print(f"\nMatches: {len(matches)}")

    for m in matches:
        print(f"- rule={m.rule_name} (id={m.rule_id}, sev={m.severity}) packet_id={m.packet_id}")
        if args.pretty:
            print(json.dumps(m.evidence, indent=2, sort_keys=True))
        else:
            print(json.dumps(m.evidence))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

