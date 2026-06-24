"""Authentication primitives for sec-toolkit apps.

Two layers composable independently:

- ``ApiKeyMiddleware`` - shared-secret gate (reverse-proxy-to-app).
- ``JwtAuthMiddleware`` + ``build_auth_router`` + ``UserStore`` -
  per-user JWT auth with first-run admin signup.

Deploy both together in the typical posture: API key between proxy and
app + JWT for end-user identity.
"""
from __future__ import annotations

import hmac
from collections.abc import Iterable

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from .avatars import AvatarStorage, LocalAvatarStorage
from .jwt import TokenClaims, TokenError, decode_token, encode_token
from .middleware import JwtAuthMiddleware
from .passwords import hash_password, verify_password
from .routes import Credentials, LoginResponse, UserOut, build_auth_router
from .store import User, UserStore

# Paths always exempt - the health probe and docs pages are expected
# to be reachable without a key so load balancers / browsers can reach
# them without pre-provisioning the secret.
_DEFAULT_EXEMPT = (
    "/api/health",
    "/api/auth/",
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
    "/metrics",
)


class ApiKeyMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        *,
        api_key: str | None,
        header: str = "X-API-Key",
        exempt_paths: Iterable[str] = _DEFAULT_EXEMPT,
    ) -> None:
        super().__init__(app)
        # Empty string counts as "not configured" - common footgun when
        # an env var is set but blank in a .env file.
        self.api_key = api_key or None
        self.header = header
        self.exempt_paths = tuple(exempt_paths)

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        if self.api_key is None:
            return await call_next(request)
        if request.url.path.startswith(self.exempt_paths):
            return await call_next(request)

        provided = request.headers.get(self.header, "")
        # Constant-time compare to avoid early-return timing leaks.
        if not hmac.compare_digest(provided, self.api_key):
            return JSONResponse(
                status_code=401,
                content={"detail": "invalid or missing API key"},
            )
        return await call_next(request)


__all__ = [
    "ApiKeyMiddleware",
    "AvatarStorage",
    "Credentials",
    "JwtAuthMiddleware",
    "LocalAvatarStorage",
    "LoginResponse",
    "TokenClaims",
    "TokenError",
    "User",
    "UserOut",
    "UserStore",
    "build_auth_router",
    "decode_token",
    "encode_token",
    "hash_password",
    "verify_password",
]
