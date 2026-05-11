"""Passive username presence probe tests.

The real username_search module fans out to a curated platform list
over the network; tests swap that list for a short fake one and use
respx to route the probes to fixed responses.
"""
from __future__ import annotations

import httpx
import pytest
import respx
from httpx import Response

from core.investigate.username_search import (
    UsernameValidationError,
    _Platform,
    search_username,
)


def test_username_validation_rejects_injection_chars() -> None:
    """Slash / space / question mark would change URL semantics - reject."""
    import asyncio

    with pytest.raises(UsernameValidationError):
        asyncio.run(search_username("bad/name"))
    with pytest.raises(UsernameValidationError):
        asyncio.run(search_username("with space"))
    with pytest.raises(UsernameValidationError):
        asyncio.run(search_username("has?query"))


async def test_username_classifies_200_as_present() -> None:
    platforms = (
        _Platform("Fake200", "https://fake200.test/{username}", "test"),
    )
    async with respx.mock(assert_all_called=True) as mock:
        mock.get("https://fake200.test/alice").mock(
            return_value=Response(200, text="alice's profile")
        )
        result = await search_username("alice", platforms=platforms)

    assert result.present_count == 1
    assert result.hits[0].status == "present"
    assert result.hits[0].http_status == 200


async def test_username_classifies_404_as_absent() -> None:
    platforms = (
        _Platform("Fake404", "https://fake404.test/{username}", "test"),
    )
    async with respx.mock(assert_all_called=True) as mock:
        mock.get("https://fake404.test/ghost").mock(return_value=Response(404))
        result = await search_username("ghost", platforms=platforms)

    assert result.present_count == 0
    assert result.hits[0].status == "absent"


async def test_username_classifies_403_429_as_inconclusive() -> None:
    """Rate-limited or blocked → can't tell. Must not count as 'present'."""
    platforms = (
        _Platform("FakeBlocked", "https://blocked.test/{username}", "test"),
        _Platform("FakeRate", "https://rate.test/{username}", "test"),
    )
    async with respx.mock(assert_all_called=True) as mock:
        mock.get("https://blocked.test/x").mock(return_value=Response(403))
        mock.get("https://rate.test/x").mock(return_value=Response(429))
        result = await search_username("x", platforms=platforms)

    assert result.present_count == 0
    assert {h.status for h in result.hits} == {"inconclusive"}


async def test_username_absence_marker_overrides_200() -> None:
    """Some platforms return 200 for unknown users - body-marker wins."""
    platforms = (
        _Platform(
            "HN",
            "https://hn.test/user?id={username}",
            "community",
            absence_marker="No such user.",
        ),
    )
    async with respx.mock(assert_all_called=True) as mock:
        mock.get("https://hn.test/user", params={"id": "nobody"}).mock(
            return_value=Response(200, text="No such user."),
        )
        result = await search_username("nobody", platforms=platforms)

    assert result.hits[0].status == "absent"


async def test_username_network_error_is_inconclusive() -> None:
    """Connect errors should not produce 'absent' - that's the wrong signal."""
    platforms = (
        _Platform("Unreachable", "https://unreachable.test/{username}", "test"),
    )
    async with respx.mock(assert_all_called=True) as mock:
        mock.get("https://unreachable.test/u").mock(
            side_effect=httpx.ConnectError("refused")
        )
        result = await search_username("u", platforms=platforms)

    assert result.hits[0].status == "inconclusive"
    assert result.hits[0].http_status == 0
    assert "failed" in result.hits[0].note
