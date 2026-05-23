from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class Protocol(str, Enum):
    """Matches the MySQL ENUM on the packets table."""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    OTHER = "other"


@dataclass
class PacketRecord:
    """
    Normalized view of one captured frame.
    Step 1: we only print this. Later we will INSERT into `packets`.
    """

    captured_at: datetime
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: Protocol
    packet_size: int
    tcp_flags: str | None = None
    payload_hash: str | None = None

    def summary(self) -> str:
        """One-line text for the terminal (learning / debugging)."""
        flags = f" flags={self.tcp_flags}" if self.tcp_flags else ""
        ports = ""
        if self.src_port is not None or self.dst_port is not None:
            ports = f" {self.src_port or '-'} -> {self.dst_port or '-'}"
        return (
            f"[{self.captured_at.isoformat(timespec='milliseconds')}] "
            f"{self.protocol.value.upper()} "
            f"{self.src_ip or '?'} -> {self.dst_ip or '?'}{ports} "
            f"size={self.packet_size}{flags}"
        )
