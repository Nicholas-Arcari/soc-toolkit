import base64

from config import settings
from integrations.base_client import BaseAPIClient


class VirusTotalClient(BaseAPIClient):
    """VirusTotal API v3 client. Free tier: 4 requests/minute."""

    BASE_URL = "https://www.virustotal.com/api/v3"
    RATE_LIMIT = 4

    def _get_headers(self) -> dict:
        return {
            "Accept": "application/json",
            "x-apikey": settings.virustotal_api_key,
        }

    async def check_hash(self, file_hash: str) -> dict:
        """Look up a file hash (MD5, SHA1, SHA256)."""
        if not settings.has_api_key("virustotal"):
            return {"error": "API key not configured"}

        try:
            data = await self.get(f"/files/{file_hash}")
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "found": True,
                "positives": stats.get("malicious", 0),
                "total": sum(stats.values()),
                "threat_label": attrs.get("popular_threat_classification", {})
                .get("suggested_threat_label", ""),
                "reputation": attrs.get("reputation", 0),
            }
        except Exception:
            return {"found": False}

    async def check_url(self, url: str) -> dict:
        """Look up a URL."""
        if not settings.has_api_key("virustotal"):
            return {"error": "API key not configured"}

        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        try:
            data = await self.get(f"/urls/{url_id}")
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "positives": stats.get("malicious", 0),
                "total": sum(stats.values()),
                "categories": attrs.get("categories", {}),
            }
        except Exception:
            return {"positives": 0, "error": "lookup failed"}

    async def check_ip(self, ip: str) -> dict:
        """Look up an IP address."""
        if not settings.has_api_key("virustotal"):
            return {"error": "API key not configured"}

        try:
            data = await self.get(f"/ip_addresses/{ip}")
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "positives": stats.get("malicious", 0),
                "total": sum(stats.values()),
                "country": attrs.get("country", ""),
                "as_owner": attrs.get("as_owner", ""),
                "reputation": attrs.get("reputation", 0),
            }
        except Exception:
            return {"positives": 0, "error": "lookup failed"}

    async def check_domain(self, domain: str) -> dict:
        """Look up a domain."""
        if not settings.has_api_key("virustotal"):
            return {"error": "API key not configured"}

        try:
            data = await self.get(f"/domains/{domain}")
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "positives": stats.get("malicious", 0),
                "total": sum(stats.values()),
                "categories": attrs.get("categories", {}),
                "reputation": attrs.get("reputation", 0),
                "registrar": attrs.get("registrar", ""),
            }
        except Exception:
            return {"positives": 0, "error": "lookup failed"}
