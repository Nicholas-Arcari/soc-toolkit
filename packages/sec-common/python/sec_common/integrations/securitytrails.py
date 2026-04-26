"""SecurityTrails API client.

Free tier is ~50 req/month, so this client is cache-heavy and declines
politely when no key is configured. The passive DNS (``/history/.../dns/a``)
endpoint is the one that matters for pivoting; WHOIS history is the other
major feature and lives in whois_history.py.
"""
from sec_common.cache import get_cached, set_cached
from sec_common.http import BaseAPIClient


class SecurityTrailsClient(BaseAPIClient):
    """Passive DNS + WHOIS history from SecurityTrails."""

    BASE_URL = "https://api.securitytrails.com/v1"
    RATE_LIMIT = 2
    CACHE_TTL = 6 * 3600  # free tier is ~50 req/month; cache 6h

    def __init__(self, api_key: str = "") -> None:
        super().__init__()
        self.api_key = api_key

    def _get_headers(self) -> dict:
        return {"Accept": "application/json", "APIKEY": self.api_key}

    async def dns_history(self, domain: str, record_type: str = "a") -> list[dict]:
        """Historical A/AAAA/MX/NS records for a domain.

        Returns `{value, first_seen, last_seen, organizations, source}` rows
        normalized across record types for the pivot engine.
        """
        if not self.api_key:
            return []

        cached = get_cached("securitytrails", f"dns-history-{record_type}", domain)
        if cached is not None:
            return list(cached.get("rows", []))

        try:
            data = await self.get(f"/history/{domain}/dns/{record_type}")
        except Exception:
            return []

        rows: list[dict] = []
        for rec in data.get("records", []):
            first_seen = str(rec.get("first_seen", ""))
            last_seen = str(rec.get("last_seen", ""))
            organizations = rec.get("organizations", []) or []

            for val in rec.get("values", []) or []:
                # SecurityTrails emits `{ip, ip_count, country}` for A records
                # and `{host}` for NS/MX - pick whichever is present.
                value = val.get("ip") or val.get("host") or val.get("mail")
                if not value:
                    continue
                rows.append({
                    "value": value,
                    "record_type": record_type.upper(),
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "organizations": organizations,
                    "source": "securitytrails",
                })

        set_cached(
            "securitytrails",
            f"dns-history-{record_type}",
            domain,
            {"rows": rows},
            ttl=self.CACHE_TTL,
        )
        return rows

    async def whois_history(self, domain: str) -> list[dict]:
        """Historical WHOIS snapshots for ``domain``.

        Each row captures a WHOIS record as it was observed at a point
        in time - useful for spotting ownership transitions or
        registrar hops that often precede infrastructure reuse.
        """
        if not self.api_key:
            return []

        cached = get_cached("securitytrails", "whois-history", domain)
        if cached is not None:
            return list(cached.get("rows", []))

        try:
            data = await self.get(f"/history/{domain}/whois")
        except Exception:
            return []

        rows: list[dict] = []
        for rec in data.get("result", {}).get("items", []) or []:
            rows.append({
                "registrar": str(rec.get("registrarName", "")),
                "contact_email": str(rec.get("contactEmail", "")),
                "creation_date": str(rec.get("createdDate", "")),
                "expiration_date": str(rec.get("expiresDate", "")),
                "updated_date": str(rec.get("updatedDate", "")),
                "name_servers": list(rec.get("nameServers", []) or []),
                "status": str(rec.get("status", "") or ""),
                "source": "securitytrails",
            })

        set_cached(
            "securitytrails",
            "whois-history",
            domain,
            {"rows": rows},
            ttl=self.CACHE_TTL,
        )
        return rows

    async def subdomains(self, domain: str) -> list[str]:
        """List subdomains known to SecurityTrails (first-level only)."""
        if not self.api_key:
            return []

        cached = get_cached("securitytrails", "subdomains", domain)
        if cached is not None:
            return list(cached.get("subdomains", []))

        try:
            data = await self.get(f"/domain/{domain}/subdomains")
        except Exception:
            return []

        subs = [
            f"{label}.{domain}".lower()
            for label in data.get("subdomains", []) or []
            if label
        ]
        set_cached("securitytrails", "subdomains", domain, {"subdomains": subs}, ttl=self.CACHE_TTL)
        return subs
