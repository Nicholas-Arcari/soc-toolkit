"""Network egress guard (SSRF defence).

Shared by the SOC link tracer and the OSINT website fingerprinter: both
fetch a user-supplied URL server-side, so both must refuse hosts that
resolve to private/loopback/reserved addresses.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlparse


async def host_blocked(host: str) -> bool:
    """True if ``host`` resolves to a non-public address (refuse the fetch)."""
    if not host:
        return True
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, host, None)
    except socket.gaierror:
        return True  # unresolvable → refuse
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return True
    return False


_ALLOWED_PORTS = frozenset({80, 443})


async def url_blocked(url: str) -> bool:
    """True if ``url`` is unsafe to fetch server-side.

    Layers a scheme + port allowlist on top of ``host_blocked``: only
    http/https on the default web ports (or an unspecified port) are allowed,
    so a redirect to ``http://host:22`` or a ``gopher://`` URL can't turn the
    fetcher into a port scanner. Re-run on every redirect hop.
    """
    parts = urlparse(url)
    if parts.scheme not in ("http", "https"):
        return True
    try:
        port = parts.port
    except ValueError:
        return True  # malformed port component
    if port is not None and port not in _ALLOWED_PORTS:
        return True
    return await host_blocked(parts.hostname or "")


__all__ = ["host_blocked", "url_blocked"]
