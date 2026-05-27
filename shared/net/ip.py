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


def varbinary_to_ip(value: bytes | None) -> str | None:
    """
    Convert VARBINARY(16) bytes back to an IPv4/IPv6 string.
    Accepts 4 bytes (IPv4) or 16 bytes (IPv6). Anything else returns None.
    """
    if not value:
        return None
    try:
        if len(value) == 4:
            return socket.inet_ntop(socket.AF_INET, value)
        if len(value) == 16:
            return socket.inet_ntop(socket.AF_INET6, value)
    except OSError:
        return None
    return None
