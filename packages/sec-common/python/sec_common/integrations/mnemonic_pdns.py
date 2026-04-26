"""Mnemonic Passive DNS client.

Mnemonic's pDNS v3 API has a generous anonymous tier - the
``/search/{value}`` endpoint answers without auth, with lower rate limits.
An ``Argus-API-Key`` header unlocks enhanced coverage (longer TLP
results, higher QPS). Designed as a primary pDNS source with
SecurityTrails as a paid supplement.
"""
from datetime import UTC, datetime
from typing import Any

from sec_common.cache import get_cached, set_cached
from sec_common.http import BaseAPIClient


class MnemonicPdnsClient(BaseAPIClient):
    """Passive DNS via Mnemonic v3.

    Emits rows shaped to match SecurityTrailsClient (``value``,
    ``record_type``, ``first_seen``, ``last_seen``, ``organizations``,
    ``source``) so the pivot engine can concatenate and dedupe results
    from both sources trivially. Adds a ``query`` field because
    Mnemonic's search is bidirectional - useful for reverse (IP→domain)
    pivots.
    """

    BASE_URL = "https://api.mnemonic.no/pdns/v3"
    RATE_LIMIT = 3
    CACHE_TTL = 12 * 3600

    def __init__(self, api_key: str = "") -> None:
        super().__init__()
        self.api_key = api_key

    def _get_headers(self) -> dict:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Argus-API-Key"] = self.api_key
        return headers

    async def search(self, value: str) -> list[dict]:
        """Passive DNS records mentioning ``value`` (domain or IP).

        Forward lookups (domain input) return `value = answer`
        (the resolved IP/host). Reverse lookups (IP input) return
        `value = query_name` (the domain that resolved to the IP).
        """
        cached = get_cached("mnemonic", "pdns-search", value)
        if cached is not None:
            return list(cached.get("rows", []))

        try:
            data = await self.get(f"/search/{value}")
        except Exception:
            return []

        rows: list[dict] = []
        for rec in data.get("data", []) or []:
            query_str = str(rec.get("query", ""))
            answer = str(rec.get("answer", ""))
            rrtype = str(rec.get("rrtype", "")).upper()
            if not rrtype or (not query_str and not answer):
                continue

            # Pick the "other side" as the pivot target. If neither
            # field matches the input exactly (subdomain/substring
            # match), prefer the answer as SecurityTrails does.
            if answer == value and query_str:
                pivot_value = query_str
            else:
                pivot_value = answer or query_str

            if not pivot_value:
                continue

            rows.append({
                "value": pivot_value,
                "query": query_str,
                "record_type": rrtype,
                "first_seen": _iso(rec.get("firstSeenTimestamp")),
                "last_seen": _iso(rec.get("lastSeenTimestamp")),
                "organizations": [],
                "source": "mnemonic",
            })

        set_cached("mnemonic", "pdns-search", value, {"rows": rows}, ttl=self.CACHE_TTL)
        return rows


def _iso(ts: Any) -> str:
    """Mnemonic emits epoch-ms integers; convert to ISO-8601 UTC strings."""
    if ts is None:
        return ""
    try:
        return datetime.fromtimestamp(int(ts) / 1000, tz=UTC).isoformat()
    except (ValueError, TypeError):
        return ""
