from __future__ import annotations

import httpx
import pytest
import respx

from sec_common.integrations import AbuseIPDBClient


@pytest.mark.asyncio
async def test_no_key_returns_error() -> None:
    assert await AbuseIPDBClient().check_ip("8.8.8.8") == {"error": "API key not configured"}


@pytest.mark.asyncio
@respx.mock
async def test_check_ip_parses_response() -> None:
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json={
            "data": {
                "ipAddress": "1.2.3.4",
                "abuseConfidenceScore": 85,
                "countryCode": "CN",
                "isp": "EvilCorp",
                "domain": "evilcorp.test",
                "totalReports": 42,
                "lastReportedAt": "2026-04-20T10:00:00Z",
                "isPublic": True,
                "isTor": False,
                "reports": [{"categories": [18, 22]}],
            }
        })
    )
    result = await AbuseIPDBClient(api_key="k").check_ip("1.2.3.4")
    assert result["abuse_score"] == 85
    assert result["country"] == "CN"
    assert result["total_reports"] == 42
    assert result["categories"] == [18, 22]


@pytest.mark.asyncio
@respx.mock
async def test_key_header_is_sent() -> None:
    captured: dict = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return httpx.Response(200, json={"data": {}})

    respx.get("https://api.abuseipdb.com/api/v2/check").mock(side_effect=_handler)
    await AbuseIPDBClient(api_key="my-key").check_ip("1.1.1.1")
    assert captured["headers"]["key"] == "my-key"


@pytest.mark.asyncio
@respx.mock
async def test_api_error_degrades_gracefully() -> None:
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(500)
    )

    class _Fast(AbuseIPDBClient):
        MAX_RETRIES = 1

    result = await _Fast(api_key="k").check_ip("1.1.1.1")
    assert result["abuse_score"] == 0
    assert result["error"] == "lookup failed"
