"""VirusTotal client: auth header, degraded-mode shape, response parsing."""
from __future__ import annotations

import httpx
import pytest
import respx

from sec_common.integrations import VirusTotalClient


@pytest.mark.asyncio
async def test_no_key_returns_structured_error() -> None:
    """Degraded mode never raises - callers expect a dict."""
    client = VirusTotalClient(api_key="")
    assert await client.check_ip("8.8.8.8") == {"error": "API key not configured"}
    assert await client.check_hash("abc") == {"error": "API key not configured"}
    assert await client.check_url("https://e.test") == {"error": "API key not configured"}
    assert await client.check_domain("e.test") == {"error": "API key not configured"}


@pytest.mark.asyncio
@respx.mock
async def test_check_ip_parses_stats() -> None:
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").mock(
        return_value=httpx.Response(200, json={
            "data": {"attributes": {
                "last_analysis_stats": {"malicious": 2, "harmless": 80, "suspicious": 0},
                "country": "US",
                "as_owner": "GOOGLE",
                "reputation": -5,
            }},
        })
    )
    result = await VirusTotalClient(api_key="k").check_ip("8.8.8.8")
    assert result["positives"] == 2
    assert result["total"] == 82
    assert result["country"] == "US"
    assert result["as_owner"] == "GOOGLE"
    assert result["reputation"] == -5


@pytest.mark.asyncio
@respx.mock
async def test_api_key_header_is_sent() -> None:
    captured: dict = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return httpx.Response(200, json={"data": {"attributes": {}}})

    respx.get("https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1").mock(
        side_effect=_handler
    )
    await VirusTotalClient(api_key="super-secret").check_ip("1.1.1.1")
    assert captured["headers"].get("x-apikey") == "super-secret"


@pytest.mark.asyncio
@respx.mock
async def test_check_hash_returns_found_false_on_404() -> None:
    """VT 404 for unknown hash; the client swallows it and returns
    {found: false} so callers don't branch on HTTP errors."""
    respx.get("https://www.virustotal.com/api/v3/files/deadbeef").mock(
        return_value=httpx.Response(404, json={})
    )

    class _Fast(VirusTotalClient):
        MAX_RETRIES = 1

    result = await _Fast(api_key="k").check_hash("deadbeef")
    assert result == {"found": False}


@pytest.mark.asyncio
@respx.mock
async def test_check_domain_maps_fields() -> None:
    respx.get("https://www.virustotal.com/api/v3/domains/evil.test").mock(
        return_value=httpx.Response(200, json={
            "data": {"attributes": {
                "last_analysis_stats": {"malicious": 5, "harmless": 50},
                "categories": {"forcepoint": "phishing"},
                "reputation": -20,
                "registrar": "EvilRegistrar",
            }}
        })
    )
    result = await VirusTotalClient(api_key="k").check_domain("evil.test")
    assert result["positives"] == 5
    assert result["registrar"] == "EvilRegistrar"
    assert result["categories"] == {"forcepoint": "phishing"}
