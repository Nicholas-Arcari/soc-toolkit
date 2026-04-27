from __future__ import annotations

import httpx
import pytest
import respx

from sec_common.integrations import ShodanClient


@pytest.mark.asyncio
async def test_no_key_returns_error() -> None:
    assert await ShodanClient().check_ip("1.1.1.1") == {"error": "API key not configured"}


@pytest.mark.asyncio
@respx.mock
async def test_check_ip_extracts_ports_vulns_org() -> None:
    respx.get("https://api.shodan.io/shodan/host/1.2.3.4").mock(
        return_value=httpx.Response(200, json={
            "ip_str": "1.2.3.4",
            "os": "Linux 5.4",
            "org": "Acme Hosting",
            "isp": "Acme",
            "country_name": "United States",
            "city": "Seattle",
            "ports": [22, 80, 443],
            "vulns": ["CVE-2024-0001", "CVE-2024-0002"],
            "hostnames": ["host.acme.test"],
            "last_update": "2026-04-20T00:00:00.000000",
        })
    )
    result = await ShodanClient(api_key="k").check_ip("1.2.3.4")
    assert result["open_ports"] == [22, 80, 443]
    assert result["vulns"] == ["CVE-2024-0001", "CVE-2024-0002"]
    assert result["organization"] == "Acme Hosting"
    assert result["hostnames"] == ["host.acme.test"]


@pytest.mark.asyncio
@respx.mock
async def test_lookup_failure_degrades() -> None:
    respx.get("https://api.shodan.io/shodan/host/1.2.3.4").mock(
        return_value=httpx.Response(404)
    )

    class _Fast(ShodanClient):
        MAX_RETRIES = 1

    result = await _Fast(api_key="k").check_ip("1.2.3.4")
    assert result["ip"] == "1.2.3.4"
    assert result["error"] == "lookup failed"
