"""Live WHOIS lookup via python-whois.

WHOIS (RFC 3912) is a text protocol over TCP/43 whose response format is
registry-specific. ``python-whois`` handles the parsing but field
coverage varies by TLD. For historical records we delegate to
SecurityTrails (see ``securitytrails.py``).

Unlike HTTP-based integrations this doesn't extend BaseAPIClient - WHOIS
runs over raw TCP. Each lookup is wrapped in ``asyncio.to_thread`` so
blocking socket I/O doesn't stall the event loop.
"""
import asyncio
from typing import Any

try:
    import whois as _whois_lib
except ImportError:
    _whois_lib = None

from sec_common.cache import get_cached, set_cached


class WhoisClient:
    """Current-state WHOIS lookups with cache."""

    CACHE_TTL = 6 * 3600

    async def lookup(self, domain: str) -> dict:
        """Return the current WHOIS record for ``domain``.

        Yields ``{}`` on parser error, unregistered domain, or when
        python-whois isn't importable - the degraded mode other
        integrations use.
        """
        if _whois_lib is None:
            return {}

        cached = get_cached("whois", "live", domain)
        if cached is not None:
            return dict(cached)

        try:
            record = await asyncio.to_thread(_whois_lib.whois, domain)
        except Exception:
            return {}

        normalized = _normalize(record)
        set_cached("whois", "live", domain, normalized, ttl=self.CACHE_TTL)
        return normalized


def _normalize(record: Any) -> dict:
    """Flatten a python-whois ``WhoisEntry`` into plain JSON-safe fields.

    Dates arrive as ``datetime`` objects (serialized via ``isoformat``).
    Fields often come as list-or-scalar depending on registry - ``_first``
    picks the primary value, ``_list`` normalizes to list[str].
    """
    if record is None:
        return {}

    return {
        "registrar": _first(record.get("registrar")),
        "creation_date": _first(record.get("creation_date")),
        "expiration_date": _first(record.get("expiration_date")),
        "updated_date": _first(record.get("updated_date")),
        "name_servers": _list(record.get("name_servers")),
        "emails": _list(record.get("emails")),
        "status": _list(record.get("status")),
        "registrant_name": _first(record.get("name")),
        "registrant_org": _first(record.get("org")),
        "country": _first(record.get("country")),
    }


def _first(val: Any) -> str:
    if isinstance(val, list):
        val = val[0] if val else None
    if val is None:
        return ""
    if hasattr(val, "isoformat"):
        return str(val.isoformat())
    return str(val)


def _list(val: Any) -> list[str]:
    if isinstance(val, list):
        return [str(v) for v in val if v]
    if val:
        return [str(val)]
    return []
