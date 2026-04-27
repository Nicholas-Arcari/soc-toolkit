from __future__ import annotations

import httpx
import pytest
import respx

from sec_common.integrations import URLScanClient


@pytest.mark.asyncio
@respx.mock
async def test_check_url_flags_malicious() -> None:
    respx.get("https://urlscan.io/api/v1/search/").mock(
        return_value=httpx.Response(200, json={
            "results": [{
                "verdicts": {"overall": {
                    "malicious": True, "score": 90,
                    "categories": ["phishing"],
                }},
                "page": {"title": "Fake Login", "ip": "198.51.100.1"},
                "screenshot": "https://urlscan.io/screenshots/abc.png",
            }]
        })
    )
    result = await URLScanClient().check_url("https://evil.test/login")
    assert result["found"] is True
    assert result["malicious"] is True
    assert result["score"] == 90
    assert result["page_title"] == "Fake Login"


@pytest.mark.asyncio
@respx.mock
async def test_check_url_not_found() -> None:
    respx.get("https://urlscan.io/api/v1/search/").mock(
        return_value=httpx.Response(200, json={"results": []})
    )
    result = await URLScanClient().check_url("https://unknown.test")
    assert result == {"found": False}


@pytest.mark.asyncio
@respx.mock
async def test_api_key_forwarded_when_provided() -> None:
    captured: dict = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return httpx.Response(200, json={"results": []})

    respx.get("https://urlscan.io/api/v1/search/").mock(side_effect=_handler)
    await URLScanClient(api_key="my-urlscan-key").check_url("https://x.test")
    assert captured["headers"].get("api-key") == "my-urlscan-key"


@pytest.mark.asyncio
@respx.mock
async def test_upstream_error_returns_found_false() -> None:
    respx.get("https://urlscan.io/api/v1/search/").mock(
        return_value=httpx.Response(500)
    )

    class _Fast(URLScanClient):
        MAX_RETRIES = 1

    result = await _Fast().check_url("https://x.test")
    assert result["found"] is False
    assert result["error"] == "lookup failed"
