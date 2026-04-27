"""crt.sh: multi-SAN splitting, cache round-trip, error graceful-fail."""
from __future__ import annotations

import httpx
import pytest
import respx

from sec_common.integrations import CrtShClient


@pytest.mark.asyncio
@respx.mock
async def test_search_parses_entries_and_splits_sans() -> None:
    """`name_value` contains newline-separated SANs. Each becomes a row."""
    respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(200, json=[
            {
                "id": 1,
                "name_value": "www.acme.test\nacme.test\n*.acme.test",
                "issuer_name": "Let's Encrypt",
                "not_before": "2026-01-01T00:00:00",
                "not_after": "2099-12-31T23:59:59",
            },
            {
                "id": 2,
                "name_value": "api.acme.test",
                "issuer_name": "DigiCert",
                "not_before": "2025-06-01T00:00:00",
                "not_after": "2099-12-31T23:59:59",
            },
        ])
    )
    rows = await CrtShClient().search("acme.test")
    names = {r["subdomain"] for r in rows}
    assert "www.acme.test" in names
    assert "acme.test" in names
    assert "api.acme.test" in names


@pytest.mark.asyncio
@respx.mock
async def test_upstream_error_returns_empty() -> None:
    respx.get("https://crt.sh/").mock(return_value=httpx.Response(500))
    rows = await CrtShClient().search("acme.test")
    assert rows == []


@pytest.mark.asyncio
@respx.mock
async def test_second_call_hits_cache_not_network() -> None:
    """The second search for the same domain must not trigger a request."""
    route = respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(200, json=[
            {
                "id": 1,
                "name_value": "acme.test",
                "issuer_name": "L",
                "not_before": "2026-01-01T00:00:00",
                "not_after": "2099-12-31T23:59:59",
            },
        ])
    )
    client = CrtShClient()
    await client.search("acme.test")
    await client.search("acme.test")
    assert route.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_active_flag_based_on_not_after() -> None:
    respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(200, json=[
            {
                "id": 1,
                "name_value": "old.acme.test",
                "issuer_name": "L",
                "not_before": "2020-01-01T00:00:00",
                "not_after": "2021-01-01T00:00:00",
            },
            {
                "id": 2,
                "name_value": "new.acme.test",
                "issuer_name": "L",
                "not_before": "2026-01-01T00:00:00",
                "not_after": "2099-12-31T23:59:59",
            },
        ])
    )
    rows = await CrtShClient().search("acme.test")
    by_name = {r["subdomain"]: r for r in rows}
    assert by_name["old.acme.test"]["active"] is False
    assert by_name["new.acme.test"]["active"] is True
