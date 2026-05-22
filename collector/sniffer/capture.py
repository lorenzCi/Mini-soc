"""
Live capture loop using Scapy.

Step 1: call a callback for each packet (e.g. print).
Later: callback will parse + save to MySQL.
"""

from typing import Callable

from scapy.all import sniff
from scapy.packet import Packet


def capture_live(
    *,
    count: int = 10,
    interface: str | None = None,
    bpf_filter: str | None = None,
    on_packet: Callable[[Packet], None],
) -> None:
    """
    Listen on a network interface until `count` packets are seen.

    interface: e.g. "en0" on Mac Wi‑Fi; None = Scapy default interface
    bpf_filter: optional Berkeley filter, e.g. "tcp port 80"
    """
    sniff(
        iface=interface,
        filter=bpf_filter,
        count=count,
        prn=on_packet,
        store=False,
    )
