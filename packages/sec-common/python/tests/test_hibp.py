from __future__ import annotations

import httpx
import pytest
import respx

from sec_common.integrations import HIBPClient


@pytest.mark.asyncio
async def test_no_key_returns_empty_list() -> None:
    """HIBP account lookup requires a paid key - degraded mode is []."""
    result = await HIBPClient(api_key="").breaches_for_account("test@example.test")
    assert result == []


@pytest.mark.asyncio
@respx.mock
async def test_breaches_for_account_parses_payload() -> None:
    respx.get(
        "https://haveibeenpwned.com/api/v3/breachedaccount/test@example.test"
    ).mock(return_value=httpx.Response(200, json=[
        {
            "Name": "Adobe",
            "Title": "Adobe",
            "Domain": "adobe.com",
            "BreachDate": "2013-10-04",
            "AddedDate": "2013-12-04T00:00:00Z",
            "PwnCount": 152445165,
            "DataClasses": ["Email addresses", "Password hints", "Passwords"],
            "IsVerified": True,
            "IsSensitive": False,
            "Description": "The Adobe breach.",
        }
    ]))
    result = await HIBPClient(api_key="k").breaches_for_account("test@example.test")
    assert len(result) == 1
    assert result[0]["name"] == "Adobe"
    assert result[0]["pwn_count"] == 152445165
    assert "Email addresses" in result[0]["data_classes"]


@pytest.mark.asyncio
@respx.mock
async def test_404_treated_as_no_breaches() -> None:
    """HIBP returns 404 for "not in any breach" - not an error."""
    respx.get(
        "https://haveibeenpwned.com/api/v3/breachedaccount/clean@example.test"
    ).mock(return_value=httpx.Response(404))

    class _Fast(HIBPClient):
        MAX_RETRIES = 1

    result = await _Fast(api_key="k").breaches_for_account("clean@example.test")
    assert result == []


@pytest.mark.asyncio
@respx.mock
async def test_user_agent_and_key_header_sent() -> None:
    captured: dict = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return httpx.Response(200, json=[])

    respx.get("https://haveibeenpwned.com/api/v3/breachedaccount/x").mock(
        side_effect=_handler
    )
    await HIBPClient(api_key="my-key").breaches_for_account("x")
    assert captured["headers"].get("hibp-api-key") == "my-key"
    assert "sec-toolkit" in captured["headers"].get("user-agent", "")


@pytest.mark.asyncio
@respx.mock
async def test_cached_second_call_short_circuits() -> None:
    route = respx.get(
        "https://haveibeenpwned.com/api/v3/breachedaccount/test@example.test"
    ).mock(return_value=httpx.Response(200, json=[
        {"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com",
         "BreachDate": "2013-10-04", "AddedDate": "2013-12-04T00:00:00Z",
         "PwnCount": 1, "DataClasses": [], "IsVerified": True,
         "IsSensitive": False, "Description": ""},
    ]))
    client = HIBPClient(api_key="k")
    await client.breaches_for_account("test@example.test")
    await client.breaches_for_account("test@example.test")
    assert route.call_count == 1
