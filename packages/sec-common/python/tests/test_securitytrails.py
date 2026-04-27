from __future__ import annotations

import httpx
import pytest
import respx

from sec_common.integrations import SecurityTrailsClient


@pytest.mark.asyncio
async def test_no_key_returns_empty() -> None:
    assert await SecurityTrailsClient().dns_history("acme.test") == []


@pytest.mark.asyncio
@respx.mock
async def test_dns_history_a_records() -> None:
    respx.get("https://api.securitytrails.com/v1/history/acme.test/dns/a").mock(
        return_value=httpx.Response(200, json={
            "records": [
                {
                    "first_seen": "2024-01-01",
                    "last_seen": "2024-06-01",
                    "organizations": ["Acme Hosting"],
                    "values": [{"ip": "192.0.2.10"}, {"ip": "192.0.2.11"}],
                },
                {
                    "first_seen": "2023-01-01",
                    "last_seen": "2023-12-31",
                    "organizations": ["Previous Host"],
                    "values": [{"ip": "198.51.100.5"}],
                },
            ]
        })
    )
    rows = await SecurityTrailsClient(api_key="k").dns_history("acme.test")
    assert len(rows) == 3
    assert {r["value"] for r in rows} == {"192.0.2.10", "192.0.2.11", "198.51.100.5"}
    assert all(r["record_type"] == "A" for r in rows)
    assert all(r["source"] == "securitytrails" for r in rows)


@pytest.mark.asyncio
@respx.mock
async def test_second_call_cached() -> None:
    route = respx.get("https://api.securitytrails.com/v1/history/acme.test/dns/a").mock(
        return_value=httpx.Response(200, json={"records": []})
    )
    client = SecurityTrailsClient(api_key="k")
    await client.dns_history("acme.test")
    await client.dns_history("acme.test")
    assert route.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_dns_history_error_returns_empty() -> None:
    respx.get("https://api.securitytrails.com/v1/history/acme.test/dns/a").mock(
        return_value=httpx.Response(500)
    )

    class _Fast(SecurityTrailsClient):
        MAX_RETRIES = 1

    rows = await _Fast(api_key="k").dns_history("acme.test")
    assert rows == []


@pytest.mark.asyncio
@respx.mock
async def test_apikey_header_forwarded() -> None:
    captured: dict = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return httpx.Response(200, json={"records": []})

    respx.get("https://api.securitytrails.com/v1/history/acme.test/dns/a").mock(
        side_effect=_handler
    )
    await SecurityTrailsClient(api_key="st-key").dns_history("acme.test")
    assert captured["headers"]["apikey"] == "st-key"
