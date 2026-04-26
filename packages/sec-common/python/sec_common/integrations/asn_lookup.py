"""ASN / RIR lookup via the ``ipwhois`` library.

Uses RDAP (RFC 9082) against the responsible RIR (ARIN, RIPE, APNIC,
LACNIC, AFRINIC) - no API key needed. ipwhois performs blocking HTTP
requests internally, so each lookup is wrapped in ``asyncio.to_thread``.
"""
import asyncio
from typing import Any

try:
    from ipwhois import IPWhois
except ImportError:
    IPWhois = None

from sec_common.cache import get_cached, set_cached


class ASNClient:
    """Resolve an IP to its ASN and announcing-CIDR metadata."""

    CACHE_TTL = 24 * 3600

    async def lookup(self, ip: str) -> dict:
        """Return ``{asn, asn_description, country, cidr, registry, source}``.

        Empty dict on lookup failure (private IP, RDAP unreachable,
        library unimportable) - degraded-mode pattern.
        """
        if IPWhois is None:
            return {}

        cached = get_cached("ipwhois", "asn", ip)
        if cached is not None:
            return dict(cached)

        try:
            result = await asyncio.to_thread(_do_lookup, ip)
        except Exception:
            return {}

        normalized = _normalize(result)
        set_cached("ipwhois", "asn", ip, normalized, ttl=self.CACHE_TTL)
        return normalized


def _do_lookup(ip: str) -> dict:
    """Run ipwhois.lookup_rdap - isolated so ``asyncio.to_thread`` can hold it."""
    obj = IPWhois(ip)
    return dict(obj.lookup_rdap(depth=1))


def _normalize(result: dict[str, Any]) -> dict:
    """Extract the pivot-relevant subset from ipwhois's verbose payload."""
    if not result:
        return {}

    asn_num = str(result.get("asn", "") or "")
    # ipwhois reports "15169" - prepend ``AS`` so downstream display
    # matches Shodan / Censys / BGP toolchain conventions.
    asn = f"AS{asn_num}" if asn_num and not asn_num.startswith("AS") else asn_num

    return {
        "asn": asn,
        "asn_description": str(result.get("asn_description", "") or ""),
        "country": str(result.get("asn_country_code", "") or ""),
        "cidr": str(result.get("asn_cidr", "") or ""),
        "registry": str(result.get("asn_registry", "") or ""),
        "source": "ipwhois",
    }
