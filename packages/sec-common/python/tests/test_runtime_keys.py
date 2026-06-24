"""Per-request API-key override middleware + config resolution."""
from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from sec_common.config import BaseAppSettings
from sec_common.runtime_keys import (
    ApiKeyOverrideMiddleware,
    request_api_key_override,
)


def _override_app() -> TestClient:
    async def echo(request: Request) -> JSONResponse:
        return JSONResponse({"vt": request_api_key_override("virustotal")})

    app = Starlette(routes=[Route("/x", echo)])
    app.add_middleware(ApiKeyOverrideMiddleware)
    return TestClient(app)


def test_header_override_is_request_scoped() -> None:
    client = _override_app()
    got = client.get("/x", headers={"X-Api-Key-virustotal": "abc"})
    assert got.json()["vt"] == "abc"
    # a later request without the header must not see the previous value
    assert client.get("/x").json()["vt"] == ""


def test_shared_secret_header_is_not_an_override() -> None:
    client = _override_app()
    # X-API-Key (the gate header) has no trailing service - ignore it here
    got = client.get("/x", headers={"X-API-Key": "secret"})
    assert got.json()["vt"] == ""


def _config_app() -> TestClient:
    settings = BaseAppSettings(virustotal_api_key="")

    async def read(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "key": settings.get_api_key("virustotal"),
                "has": settings.has_api_key("virustotal"),
            }
        )

    app = Starlette(routes=[Route("/k", read)])
    app.add_middleware(ApiKeyOverrideMiddleware)
    return TestClient(app)


def test_get_api_key_prefers_request_override() -> None:
    client = _config_app()
    with_key = client.get(
        "/k", headers={"X-Api-Key-virustotal": "user-key"}
    ).json()
    assert with_key["key"] == "user-key"
    assert with_key["has"] is True

    without = client.get("/k").json()
    assert without["key"] == ""
    assert without["has"] is False
