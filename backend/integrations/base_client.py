import asyncio
import time

import httpx

from config import settings


class RateLimiter:
    """Token-bucket rate limiter for external API calls.

    Token bucket was chosen over sliding window because it allows short bursts
    (e.g., checking 4 URLs quickly) while still enforcing the per-minute cap.
    This matches how SOC analysts work: analyzing one email in a burst, then
    waiting before the next. The asyncio lock prevents race conditions when
    multiple coroutines query the same API concurrently.
    """

    def __init__(self, max_requests: int, period: float = 60.0):
        self.max_requests = max_requests
        self.period = period
        self.tokens = max_requests
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(
                self.max_requests,
                self.tokens + (elapsed / self.period) * self.max_requests,
            )
            self.last_refill = now

            if self.tokens < 1:
                wait_time = (1 - self.tokens) * (self.period / self.max_requests)
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class BaseAPIClient:
    """Base class for external API integrations with rate limiting and retries."""

    BASE_URL: str = ""
    RATE_LIMIT: int = 4  # requests per minute
    MAX_RETRIES: int = 3

    def __init__(self):
        self.rate_limiter = RateLimiter(self.RATE_LIMIT)

    def _get_headers(self) -> dict:
        return {"Accept": "application/json"}

    async def _request(
        self,
        method: str,
        endpoint: str,
        params: dict | None = None,
        json: dict | None = None,
        data: dict | None = None,
    ) -> dict:
        """Make an API request with rate limiting and retry logic."""
        await self.rate_limiter.acquire()

        url = f"{self.BASE_URL}{endpoint}"

        for attempt in range(self.MAX_RETRIES):
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.request(
                        method,
                        url,
                        headers=self._get_headers(),
                        params=params,
                        json=json,
                        data=data,
                    )

                    # Respect 429 (Too Many Requests) by honoring the Retry-After
                    # header - violating rate limits can get API keys revoked
                    if response.status_code == 429:
                        retry_after = int(response.headers.get("Retry-After", 60))
                        await asyncio.sleep(retry_after)
                        continue

                    response.raise_for_status()
                    return response.json()

            except httpx.TimeoutException:
                if attempt == self.MAX_RETRIES - 1:
                    raise
                # Exponential backoff (1s, 2s, 4s) to handle transient failures
                # without hammering the API server
                await asyncio.sleep(2 ** attempt)

        return {}

    async def get(self, endpoint: str, params: dict | None = None) -> dict:
        return await self._request("GET", endpoint, params=params)

    async def post(
        self,
        endpoint: str,
        json: dict | None = None,
        data: dict | None = None,
    ) -> dict:
        return await self._request("POST", endpoint, json=json, data=data)
