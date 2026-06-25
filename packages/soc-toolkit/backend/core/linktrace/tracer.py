"""Redirect/unshorten tracer for the link analyzer.

Follows a URL's redirect chain server-side (HEAD, falling back to a
body-less GET) to reveal where a shortened link really lands. An SSRF guard
refuses any hop whose host resolves to a private/loopback/reserved address,
so a user-supplied link can't make the server probe internal services.

The per-hop fetch is injectable (``fetch=``) so the loop/SSRF/redirect logic
is testable without network or an HTTP mock library.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from sec_common.netguard import url_blocked

_MAX_HOPS = 10
_TIMEOUT = 8.0
_HEADERS = {"User-Agent": "soc-toolkit-link/1.0"}

Fetch = Callable[[httpx.AsyncClient, str], Awaitable[tuple[int, "str | None"]]]


async def _fetch_hop(client: httpx.AsyncClient, url: str) -> tuple[int, str | None]:
    """One hop: HEAD, falling back to a body-less GET if HEAD is refused."""
    resp = await client.head(url)
    status = resp.status_code
    location = resp.headers.get("location")
    if status in (403, 405, 501):
        async with client.stream("GET", url) as streamed:
            status = streamed.status_code
            location = streamed.headers.get("location")
    return status, location


async def trace_redirects(
    url: str, max_hops: int = _MAX_HOPS, *, fetch: Fetch = _fetch_hop
) -> dict[str, Any]:
    """Walk the redirect chain of ``url`` and report where it lands."""
    if urlparse(url).scheme not in ("http", "https"):
        return {
            "input": url,
            "final_url": url,
            "hops": 0,
            "chain": [],
            "blocked": False,
            "error": "only http/https URLs are supported",
        }

    chain: list[dict[str, Any]] = []
    current = url
    error: str | None = None
    blocked = False

    async with httpx.AsyncClient(
        follow_redirects=False, timeout=_TIMEOUT, headers=_HEADERS
    ) as client:
        for _ in range(max_hops):
            if await url_blocked(current):
                blocked = True
                error = "destination host/port/scheme is not allowed"
                break
            try:
                status, location = await fetch(client, current)
            except httpx.HTTPError as exc:
                error = f"request failed: {exc}"
                break

            chain.append({"url": current, "status": status})
            if 300 <= status < 400 and location:
                current = urljoin(current, location)
                continue
            break

    return {
        "input": url,
        "final_url": chain[-1]["url"] if chain else url,
        "hops": max(0, len(chain) - 1),
        "chain": chain,
        "blocked": blocked,
        "error": error,
    }
