from sec_common.http import BaseAPIClient


class AlienVaultOTXClient(BaseAPIClient):
    """AlienVault OTX API client. Free tier: unlimited with API key."""

    BASE_URL = "https://otx.alienvault.com/api/v1"
    RATE_LIMIT = 10

    def __init__(self, api_key: str = "") -> None:
        super().__init__()
        self.api_key = api_key

    def _get_headers(self) -> dict:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key
        return headers

    async def check_ip(self, ip: str) -> dict:
        """Look up an IP on AlienVault OTX."""
        if not self.api_key:
            return {"error": "API key not configured"}

        try:
            general = await self.get(f"/indicators/IPv4/{ip}/general")
            reputation = await self.get(f"/indicators/IPv4/{ip}/reputation")

            pulses = general.get("pulse_info", {})
            return {
                "ip": ip,
                "pulse_count": pulses.get("count", 0),
                "pulse_names": [
                    p.get("name", "") for p in pulses.get("pulses", [])[:5]
                ],
                "country": general.get("country_name", ""),
                "reputation_score": reputation.get("reputation", {})
                .get("threat_score", 0),
                "activities": reputation.get("reputation", {})
                .get("activities", []),
            }
        except Exception:
            return {"ip": ip, "pulse_count": 0, "error": "lookup failed"}

    async def check_domain(self, domain: str) -> dict:
        """Look up a domain on AlienVault OTX."""
        if not self.api_key:
            return {"error": "API key not configured"}

        try:
            general = await self.get(f"/indicators/domain/{domain}/general")
            pulses = general.get("pulse_info", {})
            return {
                "domain": domain,
                "pulse_count": pulses.get("count", 0),
                "pulse_names": [
                    p.get("name", "") for p in pulses.get("pulses", [])[:5]
                ],
                "alexa_rank": general.get("alexa", ""),
            }
        except Exception:
            return {"domain": domain, "pulse_count": 0, "error": "lookup failed"}

    async def check_hash(self, file_hash: str) -> dict:
        """Look up a file hash on AlienVault OTX."""
        if not self.api_key:
            return {"error": "API key not configured"}

        try:
            data = await self.get(f"/indicators/file/{file_hash}/general")
            pulses = data.get("pulse_info", {})
            return {
                "pulse_count": pulses.get("count", 0),
                "pulse_names": [
                    p.get("name", "") for p in pulses.get("pulses", [])[:5]
                ],
            }
        except Exception:
            return {"pulse_count": 0, "error": "lookup failed"}

    async def passive_dns(self, indicator: str, kind: str = "domain") -> list[dict]:
        """Passive DNS rows for a domain or IPv4.

        Shaped like the other pDNS sources (``value`` / ``record_type`` /
        ``first_seen`` / ``last_seen`` / ``source``) so the pivot engine can
        concatenate and dedupe them. For a domain the value is the resolved
        address; for an IP it's the hostname that resolved to it (the "other
        side", matching MnemonicPdnsClient).
        """
        if not self.api_key:
            return []
        is_ip = kind.strip().lower() in {"ip", "ipv4", "ipv6"}
        section = "IPv4" if is_ip else "domain"
        try:
            data = await self.get(
                f"/indicators/{section}/{indicator}/passive_dns"
            )
        except Exception:
            return []

        rows: list[dict] = []
        for rec in data.get("passive_dns", []) or []:
            value = str((rec.get("hostname") if is_ip else rec.get("address")) or "")
            if not value:
                continue
            rows.append({
                "value": value,
                "record_type": str(rec.get("record_type", "")).upper(),
                "first_seen": str(rec.get("first", "")),
                "last_seen": str(rec.get("last", "")),
                "organizations": [],
                "source": "otx",
            })
        return rows
