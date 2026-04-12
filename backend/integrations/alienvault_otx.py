from config import settings
from integrations.base_client import BaseAPIClient


class AlienVaultOTXClient(BaseAPIClient):
    """AlienVault OTX API client. Free tier: unlimited with API key."""

    BASE_URL = "https://otx.alienvault.com/api/v1"
    RATE_LIMIT = 10

    def _get_headers(self) -> dict:
        headers = {"Accept": "application/json"}
        if settings.has_api_key("otx"):
            headers["X-OTX-API-KEY"] = settings.otx_api_key
        return headers

    async def check_ip(self, ip: str) -> dict:
        """Look up an IP on AlienVault OTX."""
        if not settings.has_api_key("otx"):
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
        if not settings.has_api_key("otx"):
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
        if not settings.has_api_key("otx"):
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
