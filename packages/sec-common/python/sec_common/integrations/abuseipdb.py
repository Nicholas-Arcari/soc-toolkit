from sec_common.http import BaseAPIClient


class AbuseIPDBClient(BaseAPIClient):
    """AbuseIPDB API v2 client. Free tier: 1000 checks/day."""

    BASE_URL = "https://api.abuseipdb.com/api/v2"
    RATE_LIMIT = 15

    def __init__(self, api_key: str = "") -> None:
        super().__init__()
        self.api_key = api_key

    def _get_headers(self) -> dict:
        return {
            "Accept": "application/json",
            "Key": self.api_key,
        }

    async def check_ip(self, ip: str) -> dict:
        """Check an IP address for abuse reports."""
        if not self.api_key:
            return {"error": "API key not configured"}

        try:
            data = await self.get("/check", params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": "",
            })
            result = data.get("data", {})
            return {
                "ip": result.get("ipAddress", ip),
                "abuse_score": result.get("abuseConfidenceScore", 0),
                "country": result.get("countryCode", ""),
                "isp": result.get("isp", ""),
                "domain": result.get("domain", ""),
                "total_reports": result.get("totalReports", 0),
                "last_reported": result.get("lastReportedAt", ""),
                "is_public": result.get("isPublic", True),
                "is_tor": result.get("isTor", False),
                "categories": result.get("reports", [{}])[0].get("categories", [])
                if result.get("reports") else [],
            }
        except Exception:
            return {"ip": ip, "abuse_score": 0, "error": "lookup failed"}
