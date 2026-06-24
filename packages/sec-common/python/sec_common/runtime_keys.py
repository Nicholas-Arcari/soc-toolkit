"""Per-request API-key overrides.

Lets a SaaS user (who never clones the repo, so has no .env) supply their
own provider keys from the UI. The frontend sends them as
``X-Api-Key-<service>`` headers; this middleware stashes them in a
request-scoped ContextVar and ``request_api_key_override`` reads them back.
The server never persists these keys - they live only for the request.

Distinct from the shared-secret ``X-API-Key`` gate (``ApiKeyMiddleware``),
which has no trailing ``-<service>`` and so never collides here.
"""
from __future__ import annotations

from collections.abc import Mapping
from contextvars import ContextVar

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

_HEADER_PREFIX = "x-api-key-"
_request_keys: ContextVar[Mapping[str, str]] = ContextVar(
    "request_api_keys", default={}
)


def request_api_key_override(service: str) -> str:
    """The caller-supplied key for ``service`` this request, or "" if none."""
    return _request_keys.get().get(service.lower(), "").strip()


class ApiKeyOverrideMiddleware(BaseHTTPMiddleware):
    """Collect ``X-Api-Key-<service>`` headers into a request-scoped mapping."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        overrides: dict[str, str] = {}
        for name, value in request.headers.items():
            lname = name.lower()
            if lname.startswith(_HEADER_PREFIX) and value.strip():
                service = lname[len(_HEADER_PREFIX) :]
                if service:
                    overrides[service] = value.strip()
        token = _request_keys.set(overrides)
        try:
            return await call_next(request)
        finally:
            _request_keys.reset(token)


__all__ = ["ApiKeyOverrideMiddleware", "request_api_key_override"]
