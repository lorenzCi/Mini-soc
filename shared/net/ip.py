"""Convert IP strings to the VARBINARY form used in MySQL (packets, alerts)."""

import socket


def ip_to_varbinary(ip: str | None) -> bytes | None:
    """
    Map an IPv4/IPv6 string to bytes for VARBINARY(16).

    IPv4 → 4 bytes (MySQL INET6_ATON style). IPv6 → 16 bytes.
    Invalid or missing → None.
    """
    if not ip:
        return None
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            return socket.inet_pton(family, ip)
        except OSError:
            continue
    return None
