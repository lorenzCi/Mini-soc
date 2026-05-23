"""
Turn a raw Scapy packet into our PacketRecord.

Scapy already decoded layers for us; we only extract the fields we care about
for IDS (IPs, ports, protocol, TCP flags, size).
"""

import hashlib
from datetime import datetime, timezone

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Packet, Raw

from collector.sniffer.models import PacketRecord, Protocol


def _protocol_from_packet(packet: Packet) -> Protocol:
    if packet.haslayer(TCP):
        return Protocol.TCP
    if packet.haslayer(UDP):
        return Protocol.UDP
    if packet.haslayer(ICMP):
        return Protocol.ICMP
    return Protocol.OTHER


def _payload_hash(packet: Packet) -> str | None:
    """SHA-256 hex of L4+ payload (matches packets.payload_hash CHAR(64))."""
    payload = b""
    if packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
    elif packet.haslayer(IP):
        payload = bytes(packet[IP].payload)
    if not payload:
        return None
    return hashlib.sha256(payload).hexdigest()


def _tcp_flags(packet: Packet) -> str | None:
    if not packet.haslayer(TCP):
        return None
    tcp = packet[TCP]
    letters = []
    if tcp.flags.F:
        letters.append("F")
    if tcp.flags.S:
        letters.append("S")
    if tcp.flags.R:
        letters.append("R")
    if tcp.flags.P:
        letters.append("P")
    if tcp.flags.A:
        letters.append("A")
    if tcp.flags.U:
        letters.append("U")
    return "".join(letters) or None


def parse_packet(packet: Packet, captured_at: datetime | None = None) -> PacketRecord:
    """Build a PacketRecord from one Scapy packet."""
    when = captured_at or datetime.now(timezone.utc)

    src_ip = dst_ip = None
    if packet.haslayer(IP):
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst

    src_port = dst_port = None
    if packet.haslayer(TCP):
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
    elif packet.haslayer(UDP):
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)

    return PacketRecord(
        captured_at=when,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=_protocol_from_packet(packet),
        packet_size=len(packet),
        tcp_flags=_tcp_flags(packet),
        payload_hash=_payload_hash(packet),
    )
