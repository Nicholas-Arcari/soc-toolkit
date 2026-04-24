from config import settings
from integrations.base_client import BaseAPIClient


class ShodanClient(BaseAPIClient):
    """Shodan API client. Free tier: limited queries."""

    BASE_URL = "https://api.shodan.io"
    RATE_LIMIT = 1  # Free tier is very limited

    async def check_ip(self, ip: str) -> dict:
        """Look up an IP address on Shodan."""
        if not settings.has_api_key("shodan"):
            return {"error": "API key not configured"}

        try:
            data = await self.get(f"/shodan/host/{ip}", params={
                "key": settings.shodan_api_key,
            })
            return {
                "ip": data.get("ip_str", ip),
                "os": data.get("os", ""),
                "organization": data.get("org", ""),
                "isp": data.get("isp", ""),
                "country": data.get("country_name", ""),
                "city": data.get("city", ""),
                "open_ports": data.get("ports", []),
                "vulns": data.get("vulns", []),
                "hostnames": data.get("hostnames", []),
                "last_update": data.get("last_update", ""),
            }
        except Exception:
            return {"ip": ip, "error": "lookup failed"}
