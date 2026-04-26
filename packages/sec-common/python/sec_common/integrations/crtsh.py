"""crt.sh Certificate Transparency client.

Free, public, no auth. Certificate Transparency logs are public append-only
records of every SSL/TLS certificate issued by a trusted CA - indispensable
for subdomain enumeration because every issued cert leaks its SAN list.

Cached aggressively (24h) because:
- responses for popular domains can be 5-30 MB
- cert transparency is append-only and slow-moving
- crt.sh free infrastructure has no formal rate limit but is volunteer-run
"""
import json
import time
from typing import Any

import httpx

from sec_common.cache import get_cached, set_cached
from sec_common.http import BaseAPIClient


class CrtShClient(BaseAPIClient):
    """Query crt.sh for certs mentioning a domain.

    No API key. Emits `{subdomain, issuer, not_before, not_after, cert_id}`
    rows that downstream pivoting code can dedupe/join.
    """

    BASE_URL = "https://crt.sh"
    RATE_LIMIT = 5  # gentle - crt.sh is volunteer-run
    CACHE_TTL = 24 * 3600

    async def search(self, domain: str, include_expired: bool = True) -> list[dict]:
        """Return cert entries whose name_value references ``domain``.

        ``include_expired`` is True by default because expired certs still
        reveal historical infrastructure worth pivoting on.
        """
        cached = get_cached("crtsh", "domain", domain)
        if cached is not None:
            return _entries(cached)

        # crt.sh uses the `%.` wildcard prefix to also match subdomains
        params: dict[str, str] = {"q": f"%.{domain}", "output": "json"}
        if not include_expired:
            params["exclude"] = "expired"

        try:
            raw = await self._fetch_json(params)
        except Exception:
            return []

        set_cached("crtsh", "domain", domain, {"entries": raw}, ttl=self.CACHE_TTL)
        return _entries({"entries": raw})

    async def _fetch_json(self, params: dict[str, str]) -> list[dict]:
        """Low-level fetch that bypasses BaseAPIClient.get (which expects
        a dict response). crt.sh returns a top-level array.
        """
        await self.rate_limiter.acquire()
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.get(f"{self.BASE_URL}/", params=params)
            response.raise_for_status()
            try:
                data = response.json()
            except json.JSONDecodeError:
                return []
            return list(data) if isinstance(data, list) else []


def _entries(payload: dict[str, Any]) -> list[dict]:
    """Normalize a cached payload into analyst-friendly rows."""
    raw = payload.get("entries") or []
    rows: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for item in raw:
        # name_value can contain multiple subdomains separated by newlines
        # (each SAN entry on its own line). Split so each gets its own row.
        names = [n.strip().lower() for n in str(item.get("name_value", "")).split("\n")]
        issuer = str(item.get("issuer_name", ""))
        cert_id = item.get("id")
        not_before = str(item.get("not_before", ""))
        not_after = str(item.get("not_after", ""))

        for name in names:
            if not name:
                continue
            key = (name, str(cert_id))
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "subdomain": name,
                "issuer": issuer,
                "not_before": not_before,
                "not_after": not_after,
                "cert_id": cert_id,
                # Whether the cert was valid at the moment of export - lets
                # the UI gray out historical entries without losing them.
                "active": _is_active(not_after),
            })

    return rows


def _is_active(not_after: str) -> bool:
    """True if the cert's notAfter is in the future."""
    if not not_after:
        return False
    # crt.sh emits ISO-8601 timestamps; parse permissively
    try:
        parsed = time.strptime(not_after[:19], "%Y-%m-%dT%H:%M:%S")
        return time.mktime(parsed) > time.time()
    except ValueError:
        return False
