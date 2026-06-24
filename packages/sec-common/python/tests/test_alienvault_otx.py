from __future__ import annotations

import httpx
import pytest
import respx

from sec_common.integrations import AlienVaultOTXClient


@pytest.mark.asyncio
async def test_no_key_returns_error_for_every_method() -> None:
    c = AlienVaultOTXClient()
    assert (await c.check_ip("1.1.1.1")) == {"error": "API key not configured"}
    assert (await c.check_domain("e.test")) == {"error": "API key not configured"}
    assert (await c.check_hash("d41d8cd98f00b204e9800998ecf8427e")) == {
        "error": "API key not configured"
    }


@pytest.mark.asyncio
@respx.mock
async def test_check_ip_hydrates_pulses_and_reputation() -> None:
    respx.get("https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/general").mock(
        return_value=httpx.Response(200, json={
            "pulse_info": {
                "count": 2,
                "pulses": [
                    {"name": "TA505 campaign"},
                    {"name": "Cobalt Strike IOC"},
                ],
            },
            "country_name": "RU",
        })
    )
    respx.get(
        "https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/reputation"
    ).mock(return_value=httpx.Response(200, json={
        "reputation": {"threat_score": 7, "activities": ["scanning"]}
    }))
    result = await AlienVaultOTXClient(api_key="k").check_ip("1.2.3.4")
    assert result["pulse_count"] == 2
    assert "TA505 campaign" in result["pulse_names"]
    assert result["reputation_score"] == 7


@pytest.mark.asyncio
@respx.mock
async def test_check_domain_truncates_pulses_to_5() -> None:
    pulses = [{"name": f"pulse-{i}"} for i in range(10)]
    respx.get(
        "https://otx.alienvault.com/api/v1/indicators/domain/evil.test/general"
    ).mock(return_value=httpx.Response(200, json={
        "pulse_info": {"count": 10, "pulses": pulses},
        "alexa": "12345",
    }))
    result = await AlienVaultOTXClient(api_key="k").check_domain("evil.test")
    assert result["pulse_count"] == 10
    assert len(result["pulse_names"]) == 5
    assert result["alexa_rank"] == "12345"


@pytest.mark.asyncio
@respx.mock
async def test_upstream_failure_returns_structured_error() -> None:
    respx.get(
        "https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/general"
    ).mock(return_value=httpx.Response(500))

    class _Fast(AlienVaultOTXClient):
        MAX_RETRIES = 1

    result = await _Fast(api_key="k").check_ip("1.2.3.4")
    assert result["pulse_count"] == 0
    assert result["error"] == "lookup failed"


@pytest.mark.asyncio
async def test_passive_dns_no_key_returns_empty() -> None:
    assert await AlienVaultOTXClient().passive_dns("e.test") == []


@pytest.mark.asyncio
@respx.mock
async def test_passive_dns_domain_uses_resolved_address() -> None:
    respx.get(
        "https://otx.alienvault.com/api/v1/indicators/domain/evil.test/passive_dns"
    ).mock(return_value=httpx.Response(200, json={
        "passive_dns": [
            {
                "address": "1.2.3.4",
                "hostname": "evil.test",
                "record_type": "A",
                "first": "2024-01-01",
                "last": "2024-02-01",
            },
        ]
    }))
    rows = await AlienVaultOTXClient(api_key="k").passive_dns("evil.test", "domain")
    assert rows == [{
        "value": "1.2.3.4",
        "record_type": "A",
        "first_seen": "2024-01-01",
        "last_seen": "2024-02-01",
        "organizations": [],
        "source": "otx",
    }]


@pytest.mark.asyncio
@respx.mock
async def test_passive_dns_ip_uses_hostname() -> None:
    respx.get(
        "https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/passive_dns"
    ).mock(return_value=httpx.Response(200, json={
        "passive_dns": [
            {"address": "1.2.3.4", "hostname": "evil.test", "record_type": "A"},
        ]
    }))
    rows = await AlienVaultOTXClient(api_key="k").passive_dns("1.2.3.4", "ip")
    assert rows[0]["value"] == "evil.test"
    assert rows[0]["source"] == "otx"
