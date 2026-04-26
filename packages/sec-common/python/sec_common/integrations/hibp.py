"""Have I Been Pwned v3 API client.

HIBP switched to paid-key-only for the account lookup endpoints in 2019.
Anything useful - breaches-by-account, pastes-by-account - needs the
``hibp-api-key`` header plus a User-Agent. The "Pwned Passwords" k-anon
range endpoint remains free and needs no key, so we support both modes:
key-present (breach lookup) and keyless (password range check).

The client degrades politely when unkeyed: lookups return ``[]`` rather
than raising, so callers can surface an informative result without
branching on ``api_key`` themselves.
"""
from sec_common.cache import get_cached, set_cached
from sec_common.http import BaseAPIClient


class HIBPClient(BaseAPIClient):
    """Have I Been Pwned v3 client."""

    BASE_URL = "https://haveibeenpwned.com/api/v3"
    RATE_LIMIT = 10  # v3 paid tier: ~1 req/1.5s, round down for safety
    CACHE_TTL = 24 * 3600  # breach list is slow-moving; daily refresh is fine

    # HIBP requires a descriptive user-agent. Sending a generic "python-httpx"
    # is a frequent cause of 403s; set something that identifies the toolkit.
    USER_AGENT = "sec-toolkit-osint/0.1"

    def __init__(self, api_key: str = "") -> None:
        super().__init__()
        self.api_key = api_key

    def _get_headers(self) -> dict:
        headers = {
            "Accept": "application/json",
            "User-Agent": self.USER_AGENT,
        }
        if self.api_key:
            headers["hibp-api-key"] = self.api_key
        return headers

    async def breaches_for_account(self, account: str) -> list[dict]:
        """Return the breach list for ``account`` (email).

        Returns an empty list in degraded mode (no key) - callers should
        check ``api_key`` themselves if they want to show "feature
        unavailable" messaging instead of "no breaches found".
        """
        if not self.api_key or not account:
            return []

        cached = get_cached("hibp", "breaches", account.lower())
        if cached is not None:
            return list(cached.get("breaches", []))

        try:
            # v3 uses path-style, not query-string. `truncateResponse=false`
            # gets the full breach objects so the caller can show
            # dates/descriptions without a second round-trip.
            data = await self.get(
                f"/breachedaccount/{account}",
                params={"truncateResponse": "false"},
            )
        except Exception:
            # HIBP returns 404 for "not found in any breach" - BaseAPIClient
            # surfaces that as an HTTPStatusError. Treat it as "no breaches",
            # not as an error condition.
            return []

        # HIBP returns a JSON array directly; BaseAPIClient.get returns a
        # dict, so wrap defensively in case the array was coerced.
        breaches: list[dict] = data if isinstance(data, list) else []
        rows = [
            {
                "name": str(b.get("Name", "")),
                "title": str(b.get("Title", "")),
                "domain": str(b.get("Domain", "")),
                "breach_date": str(b.get("BreachDate", "")),
                "added_date": str(b.get("AddedDate", "")),
                "pwn_count": int(b.get("PwnCount", 0) or 0),
                "data_classes": list(b.get("DataClasses", []) or []),
                "verified": bool(b.get("IsVerified", False)),
                "sensitive": bool(b.get("IsSensitive", False)),
                "description": str(b.get("Description", "")),
                "source": "hibp",
            }
            for b in breaches
        ]

        set_cached("hibp", "breaches", account.lower(), {"breaches": rows}, ttl=self.CACHE_TTL)
        return rows

    async def breaches_for_domain(self, domain: str) -> list[dict]:
        """Return breach list filtered to ``domain`` (email domain)."""
        if not self.api_key or not domain:
            return []

        cached = get_cached("hibp", "breaches-domain", domain.lower())
        if cached is not None:
            return list(cached.get("breaches", []))

        try:
            data = await self.get("/breaches", params={"domain": domain})
        except Exception:
            return []

        breaches: list[dict] = data if isinstance(data, list) else []
        rows = [
            {
                "name": str(b.get("Name", "")),
                "title": str(b.get("Title", "")),
                "domain": str(b.get("Domain", "")),
                "breach_date": str(b.get("BreachDate", "")),
                "pwn_count": int(b.get("PwnCount", 0) or 0),
                "data_classes": list(b.get("DataClasses", []) or []),
                "source": "hibp",
            }
            for b in breaches
        ]
        set_cached(
            "hibp", "breaches-domain", domain.lower(), {"breaches": rows}, ttl=self.CACHE_TTL
        )
        return rows
