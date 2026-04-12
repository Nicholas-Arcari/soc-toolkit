import time
from collections import defaultdict

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware

from config import settings


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiter per client IP."""

    def __init__(self, app, max_requests: int | None = None, window: int = 60):
        super().__init__(app)
        self.max_requests = max_requests or settings.rate_limit_per_minute
        self.window = window
        self.requests: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/api/docs") or request.url.path == "/api/health":
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = time.time()

        # Clean old entries
        self.requests[client_ip] = [
            ts for ts in self.requests[client_ip]
            if now - ts < self.window
        ]

        if len(self.requests[client_ip]) >= self.max_requests:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Max {self.max_requests} requests per {self.window}s.",
            )

        self.requests[client_ip].append(now)
        return await call_next(request)
