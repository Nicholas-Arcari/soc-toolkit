"""Wire-level behavior of BaseAPIClient.

respx mounts a mock transport at the httpx layer so we exercise the
real request/response path without touching the network.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from sec_common.http import BaseAPIClient


class _Example(BaseAPIClient):
    BASE_URL = "https://api.example.test/v1"
    RATE_LIMIT = 60  # high so rate limiter doesn't interfere with assertions


@pytest.mark.asyncio
@respx.mock
async def test_get_returns_json() -> None:
    route = respx.get("https://api.example.test/v1/lookup").mock(
        return_value=httpx.Response(200, json={"ok": True, "n": 7})
    )
    client = _Example()
    result = await client.get("/lookup")
    assert result == {"ok": True, "n": 7}
    assert route.called


@pytest.mark.asyncio
@respx.mock
async def test_post_sends_json_body() -> None:
    captured = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.content
        return httpx.Response(200, json={"accepted": True})

    respx.post("https://api.example.test/v1/submit").mock(side_effect=_handler)

    client = _Example()
    result = await client.post("/submit", json={"query": "hello"})
    assert result == {"accepted": True}
    assert b'"query"' in captured["body"]


@pytest.mark.asyncio
@respx.mock
async def test_non_2xx_raises_through_request() -> None:
    """A 500 that keeps returning 500 should exhaust retries and raise."""
    respx.get("https://api.example.test/v1/broken").mock(
        return_value=httpx.Response(500)
    )

    class _FastExample(_Example):
        MAX_RETRIES = 1  # speed the test up

    with pytest.raises(httpx.HTTPStatusError):
        await _FastExample().get("/broken")


@pytest.mark.asyncio
@respx.mock
async def test_timeout_retries_then_raises() -> None:
    """Timeouts should be retried MAX_RETRIES times. On the last one we
    re-raise instead of swallowing."""
    respx.get("https://api.example.test/v1/slow").mock(
        side_effect=httpx.TimeoutException("boom")
    )

    class _FastExample(_Example):
        MAX_RETRIES = 2

    with pytest.raises(httpx.TimeoutException):
        await _FastExample().get("/slow")


@pytest.mark.asyncio
@respx.mock
async def test_429_honors_retry_after_then_succeeds() -> None:
    """One 429 with a short Retry-After, then a 200. The client should
    wait and eventually return the 200 payload."""
    route = respx.get("https://api.example.test/v1/lookup")

    responses = iter([
        httpx.Response(429, headers={"Retry-After": "0"}),
        httpx.Response(200, json={"ok": True}),
    ])
    route.mock(side_effect=lambda _r: next(responses))

    result = await _Example().get("/lookup")
    assert result == {"ok": True}
    assert route.call_count == 2


@pytest.mark.asyncio
@respx.mock
async def test_custom_headers_are_sent() -> None:
    """Subclasses override `_get_headers` to add auth - make sure that
    hook actually reaches the wire."""
    class _WithKey(_Example):
        def _get_headers(self) -> dict:
            return {"x-api-key": "secret"}

    captured: dict = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return httpx.Response(200, json={})

    respx.get("https://api.example.test/v1/lookup").mock(side_effect=_handler)

    await _WithKey().get("/lookup")
    assert captured["headers"]["x-api-key"] == "secret"
