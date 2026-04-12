from config import settings
from integrations.base_client import BaseAPIClient


class URLScanClient(BaseAPIClient):
    """URLScan.io API client. Free tier: 50 scans/day, 1000 results/day."""

    BASE_URL = "https://urlscan.io/api/v1"
    RATE_LIMIT = 2

    def _get_headers(self) -> dict:
        headers = {"Accept": "application/json"}
        if settings.has_api_key("urlscan"):
            headers["API-Key"] = settings.urlscan_api_key
        return headers

    async def check_url(self, url: str) -> dict:
        """Search for existing scans of a URL."""
        try:
            data = await self.get("/search/", params={
                "q": f"page.url:{url}",
                "size": 1,
            })
            results = data.get("results", [])
            if not results:
                return {"found": False}

            result = results[0]
            return {
                "found": True,
                "malicious": result.get("verdicts", {})
                .get("overall", {}).get("malicious", False),
                "score": result.get("verdicts", {})
                .get("overall", {}).get("score", 0),
                "categories": result.get("verdicts", {})
                .get("overall", {}).get("categories", []),
                "page_title": result.get("page", {}).get("title", ""),
                "page_ip": result.get("page", {}).get("ip", ""),
                "screenshot": result.get("screenshot", ""),
            }
        except Exception:
            return {"found": False, "error": "lookup failed"}
