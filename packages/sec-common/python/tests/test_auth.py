"""ApiKeyMiddleware: degrades without a key, enforces when set.

The gate lives in front of every route except the exempt probes -
those stay reachable so a load balancer can health-check without
provisioning the secret.
"""
from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from sec_common.auth import ApiKeyMiddleware


def _make_app(api_key: str | None) -> Starlette:
    async def protected(_: Request) -> JSONResponse:
        return JSONResponse({"ok": True})

    async def health(_: Request) -> JSONResponse:
        return JSONResponse({"status": "healthy"})

    app = Starlette(
        routes=[
            Route("/api/protected", protected),
            Route("/api/health", health),
        ]
    )
    app.add_middleware(ApiKeyMiddleware, api_key=api_key)
    return app


def test_no_key_configured_lets_every_request_through() -> None:
    client = TestClient(_make_app(None))
    assert client.get("/api/protected").status_code == 200


def test_blank_string_key_is_treated_as_unset() -> None:
    """Common footgun: `API_KEY=` in a .env file reads as empty string."""
    client = TestClient(_make_app(""))
    assert client.get("/api/protected").status_code == 200


def test_missing_header_is_rejected_when_key_required() -> None:
    client = TestClient(_make_app("s3cret"))
    r = client.get("/api/protected")
    assert r.status_code == 401
    assert r.json()["detail"].startswith("invalid or missing")


def test_wrong_header_is_rejected() -> None:
    client = TestClient(_make_app("s3cret"))
    r = client.get("/api/protected", headers={"X-API-Key": "nope"})
    assert r.status_code == 401


def test_correct_header_passes() -> None:
    client = TestClient(_make_app("s3cret"))
    r = client.get("/api/protected", headers={"X-API-Key": "s3cret"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_exempt_paths_skip_auth_check() -> None:
    client = TestClient(_make_app("s3cret"))
    # health probe must work without the key - load balancers can't
    # send the header without operator pre-config.
    assert client.get("/api/health").status_code == 200
