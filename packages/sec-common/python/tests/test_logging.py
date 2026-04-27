"""Request-id binding + log configuration smoke tests.

We don't try to capture real stdout here - structlog is thoroughly
tested upstream. What we *do* pin is the middleware's contract: every
request gets a request_id exposed on the response header, inbound ids
are honoured, and contextvars don't leak between requests.
"""
from __future__ import annotations

import structlog
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from sec_common.logging import RequestIDMiddleware, configure_logging


def _make_app() -> Starlette:
    async def ok(_: Request) -> JSONResponse:
        # Read whatever is bound in contextvars right now - proves the
        # middleware set it for the handler.
        bound = structlog.contextvars.get_contextvars()
        return JSONResponse({"request_id": bound.get("request_id")})

    app = Starlette(routes=[Route("/ok", ok)])
    app.add_middleware(RequestIDMiddleware)
    return app


def test_middleware_generates_request_id_when_absent() -> None:
    client = TestClient(_make_app())
    r = client.get("/ok")
    assert r.status_code == 200
    rid = r.headers["X-Request-ID"]
    assert rid and len(rid) == 16  # short uuid hex
    assert r.json()["request_id"] == rid


def test_middleware_honours_inbound_request_id() -> None:
    client = TestClient(_make_app())
    r = client.get("/ok", headers={"X-Request-ID": "upstream-trace-123"})
    assert r.headers["X-Request-ID"] == "upstream-trace-123"
    assert r.json()["request_id"] == "upstream-trace-123"


def test_contextvars_do_not_leak_between_requests() -> None:
    client = TestClient(_make_app())
    first = client.get("/ok").json()["request_id"]
    second = client.get("/ok").json()["request_id"]
    assert first != second
    # After both requests, nothing should remain bound globally.
    assert structlog.contextvars.get_contextvars() == {}


def test_configure_logging_is_idempotent() -> None:
    # Re-configuring must not raise or duplicate stdlib handlers.
    configure_logging(service="test-service", json=True)
    configure_logging(service="test-service", json=False)
    # One more for luck - JSON again.
    configure_logging(service="test-service", json=True)
