"""JWT-verifying Starlette middleware.

Gates the whole app behind a bearer token. Exempts a minimal path list
(health probe, auth endpoints, API docs) so a brand-new install can
still boot its first-run setup flow before any user exists.

``ApiKeyMiddleware`` (same package) is a separate concern and can stack
on top - typical deployment puts ``ApiKeyMiddleware`` outside (a shared
secret between reverse proxy and app) and ``JwtAuthMiddleware`` inside
(per-user identity).
"""
from __future__ import annotations

from collections.abc import Iterable

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from .jwt import TokenError, decode_token

_DEFAULT_EXEMPT = (
    "/api/health",
    "/api/auth/",
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
    "/metrics",
)


class JwtAuthMiddleware(BaseHTTPMiddleware):
    """Require a valid ``Authorization: Bearer <jwt>`` on non-exempt routes.

    When ``secret`` is None the middleware is a no-op - same ergonomics
    as ``ApiKeyMiddleware``: zero friction for a dev kicking the tires,
    full gate once an operator configures a secret.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        secret: str | None,
        exempt_paths: Iterable[str] = _DEFAULT_EXEMPT,
    ) -> None:
        super().__init__(app)
        self.secret = secret or None
        self.exempt_paths = tuple(exempt_paths)

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        if self.secret is None:
            return await call_next(request)
        if request.url.path.startswith(self.exempt_paths):
            return await call_next(request)

        header = request.headers.get("authorization", "")
        if not header.lower().startswith("bearer "):
            return JSONResponse(
                status_code=401,
                content={"detail": "missing or malformed Authorization header"},
            )
        token = header.split(" ", 1)[1].strip()
        try:
            claims = decode_token(token, secret=self.secret)
        except TokenError as exc:
            return JSONResponse(
                status_code=401,
                content={"detail": f"invalid token: {exc}"},
            )

        # Attach to request.state so route handlers can access the
        # caller's identity without re-decoding the token.
        request.state.user = claims
        return await call_next(request)


__all__ = ["JwtAuthMiddleware"]
