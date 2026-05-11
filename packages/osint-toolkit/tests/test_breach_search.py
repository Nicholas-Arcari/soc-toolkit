"""HIBP breach search tests.

Focus on the two things that can quietly break:
1. Degraded mode (no key) must return a well-formed result, not raise.
2. The HIBP response shape must be normalized into ``BreachRecord``
   dataclasses - field renames here would silently drop data.
"""
from __future__ import annotations

import pytest
import respx
from httpx import Response
from sec_common.integrations import HIBPClient

from core.investigate.breach_search import (
    BreachSearchValidationError,
    search_breaches,
)


async def test_breach_degraded_mode_without_key() -> None:
    """No key → available=False, no HTTP call made."""
    client = HIBPClient(api_key="")
    result = await search_breaches("user@example.com", client=client)

    assert result.available is False
    assert result.kind == "email"
    assert result.breaches == []
    assert "paid API key" in result.note


async def test_breach_degraded_mode_for_domain() -> None:
    client = HIBPClient(api_key="")
    result = await search_breaches("example.com", client=client)

    assert result.available is False
    assert result.kind == "domain"
    assert "paid API key" in result.note


async def test_breach_email_lookup_returns_normalized_rows() -> None:
    """Happy path: HIBP returns 2 breaches → 2 BreachRecord dataclasses."""
    client = HIBPClient(api_key="fake-key")
    async with respx.mock(assert_all_called=True) as mock:
        mock.get("https://haveibeenpwned.com/api/v3/breachedaccount/user@example.com").mock(
            return_value=Response(
                200,
                json=[
                    {
                        "Name": "Adobe",
                        "Title": "Adobe",
                        "Domain": "adobe.com",
                        "BreachDate": "2013-10-04",
                        "AddedDate": "2013-12-04T00:00:00Z",
                        "PwnCount": 152445165,
                        "DataClasses": ["Email addresses", "Password hints"],
                        "IsVerified": True,
                        "IsSensitive": False,
                        "Description": "In October 2013...",
                    },
                    {
                        "Name": "LinkedIn",
                        "Title": "LinkedIn",
                        "Domain": "linkedin.com",
                        "BreachDate": "2012-05-05",
                        "PwnCount": 164611595,
                        "DataClasses": ["Email addresses", "Passwords"],
                        "IsVerified": True,
                    },
                ],
            )
        )
        result = await search_breaches("user@example.com", client=client)

    assert result.available is True
    assert len(result.breaches) == 2
    assert result.breaches[0].name == "Adobe"
    assert result.breaches[0].pwn_count == 152445165
    assert "Email addresses" in result.breaches[0].data_classes
    assert result.breaches[1].name == "LinkedIn"


async def test_breach_404_is_not_an_error() -> None:
    """HIBP returns 404 when the account is clean - treat as 'no breaches'."""
    client = HIBPClient(api_key="fake-key")
    async with respx.mock(assert_all_called=True) as mock:
        mock.get(
            "https://haveibeenpwned.com/api/v3/breachedaccount/clean@example.com"
        ).mock(return_value=Response(404))
        result = await search_breaches("clean@example.com", client=client)

    assert result.available is True
    assert result.breaches == []


async def test_breach_domain_lookup() -> None:
    client = HIBPClient(api_key="fake-key")
    async with respx.mock(assert_all_called=True) as mock:
        mock.get("https://haveibeenpwned.com/api/v3/breaches").mock(
            return_value=Response(
                200,
                json=[
                    {
                        "Name": "AcmeCorp",
                        "Title": "AcmeCorp",
                        "Domain": "acme.example",
                        "BreachDate": "2020-01-01",
                        "PwnCount": 1000,
                        "DataClasses": ["Email addresses"],
                    },
                ],
            )
        )
        result = await search_breaches("acme.example", client=client)

    assert result.kind == "domain"
    assert result.available is True
    assert len(result.breaches) == 1
    assert result.breaches[0].domain == "acme.example"


async def test_breach_invalid_query_raises() -> None:
    """Not an email, not a domain → 422 via ValidationError upstream."""
    client = HIBPClient(api_key="fake-key")
    with pytest.raises(BreachSearchValidationError):
        await search_breaches("not-an-identifier", client=client)
