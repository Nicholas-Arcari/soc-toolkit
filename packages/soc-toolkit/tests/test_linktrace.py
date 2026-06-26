"""Redirect tracer: SSRF guard + chain following (no network)."""

import pytest
from sec_common.netguard import host_blocked, url_blocked

from core.linktrace.tracer import trace_redirects


@pytest.mark.asyncio
async def test_blocks_private_loopback_and_linklocal() -> None:
    assert await host_blocked("127.0.0.1") is True
    assert await host_blocked("10.0.0.1") is True
    assert await host_blocked("192.168.1.5") is True
    assert await host_blocked("169.254.169.254") is True
    assert await host_blocked("") is True
    # a public IP literal needs no DNS and is allowed
    assert await host_blocked("8.8.8.8") is False


@pytest.mark.asyncio
async def test_url_blocked_rejects_scheme_and_port() -> None:
    assert await url_blocked("gopher://8.8.8.8/") is True  # bad scheme
    assert await url_blocked("http://8.8.8.8:22/") is True  # non-web port
    assert await url_blocked("http://127.0.0.1/") is True  # loopback host
    assert await url_blocked("https://8.8.8.8/") is False  # public + 443
    assert await url_blocked("http://8.8.8.8:80/x") is False  # explicit :80


@pytest.mark.asyncio
async def test_rejects_non_http_scheme() -> None:
    result = await trace_redirects("ftp://example.com/x")
    assert result["chain"] == []
    assert result["error"]
    assert "http" in result["error"]


@pytest.mark.asyncio
async def test_follows_redirect_chain() -> None:
    redirects = {
        "http://93.184.216.34/a": (301, "http://93.184.216.34/b"),
        "http://93.184.216.34/b": (200, None),
    }

    async def fake_fetch(_client: object, url: str) -> tuple[int, str | None]:
        return redirects.get(url, (200, None))

    result = await trace_redirects("http://93.184.216.34/a", fetch=fake_fetch)
    assert result["final_url"] == "http://93.184.216.34/b"
    assert result["hops"] == 1
    assert [hop["status"] for hop in result["chain"]] == [301, 200]
    assert result["blocked"] is False
    assert result["error"] is None


@pytest.mark.asyncio
async def test_blocks_redirect_to_internal_host() -> None:
    async def fake_fetch(_client: object, url: str) -> tuple[int, str | None]:
        if url.endswith("/a"):
            return 302, "http://127.0.0.1/admin"
        return 200, None

    result = await trace_redirects("http://93.184.216.34/a", fetch=fake_fetch)
    assert result["blocked"] is True
    # only the safe hop was recorded; the internal target was never fetched
    assert [hop["url"] for hop in result["chain"]] == ["http://93.184.216.34/a"]
