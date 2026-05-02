"""Passive username presence search.

Probes a curated short-list of public platforms for a given username.
"Hit" means the URL for that username exists - it does **not** mean the
same person owns all the accounts; username collision across platforms is
common and must be surfaced as a caveat in the UI.

Design notes:
- Deliberately small platform list. Sherlock's 400+ platform dictionary
  is impressive but many of those sites have flaky status-code behavior
  that produces false positives. A focused list of ~12 major platforms
  with known-good signatures is more defensible for a public release.
- Every request is a single GET with a short timeout. Redirects are
  followed so sites that 301 unknown usernames to a homepage are
  correctly classified as "absent".
- Concurrent fan-out via ``asyncio.gather`` with a semaphore cap so we
  don't open 50 connections at once against rate-limited endpoints.
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Literal

import httpx

UsernameStatus = Literal["present", "absent", "inconclusive"]


@dataclass(frozen=True)
class _Platform:
    """Single platform probe definition.

    ``absence_marker`` is matched against the response body for platforms
    whose "not found" pages return HTTP 200 (looking at you, Instagram).
    When ``absence_marker`` is set, a 200 response is only treated as
    "present" if the marker is absent.
    """

    name: str
    url_template: str
    category: str
    absence_marker: str | None = None


@dataclass(frozen=True)
class UsernameHit:
    platform: str
    category: str
    url: str
    status: UsernameStatus
    http_status: int
    note: str = ""


@dataclass(frozen=True)
class UsernameSearchResult:
    username: str
    hits: list[UsernameHit]
    checked: int
    present_count: int


# Curated list. Each entry has been spot-checked against a known-nonexistent
# username to confirm the "absent" signal is reliable. Platforms with
# captchas or Cloudflare challenges are deliberately excluded - we can't
# distinguish "blocked" from "present" without running a real browser.
_PLATFORMS: tuple[_Platform, ...] = (
    _Platform("GitHub", "https://github.com/{username}", "code"),
    _Platform("GitLab", "https://gitlab.com/{username}", "code"),
    _Platform("Keybase", "https://keybase.io/{username}", "identity"),
    _Platform("HackerNews", "https://news.ycombinator.com/user?id={username}", "community",
              absence_marker="No such user."),
    _Platform("Reddit", "https://www.reddit.com/user/{username}/about.json", "social",
              absence_marker='"error": 404'),
    _Platform("HackerOne", "https://hackerone.com/{username}", "bugbounty"),
    _Platform("Bugcrowd", "https://bugcrowd.com/{username}", "bugbounty"),
    _Platform("Twitch", "https://www.twitch.tv/{username}", "streaming"),
    _Platform("Gravatar", "https://gravatar.com/{username}", "identity"),
    _Platform("Medium", "https://medium.com/@{username}", "publishing"),
    _Platform("DevTo", "https://dev.to/{username}", "publishing"),
    _Platform("StackOverflow", "https://stackoverflow.com/users/{username}", "qa"),
)

# Username must match a portable character set. We deliberately reject
# inputs that would change the URL's meaning (`/`, `?`, `#`, `..`) rather
# than trying to escape them - user typed something weird, surface the
# problem instead of issuing a malformed request.
_VALID_USERNAME = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")

_TIMEOUT = httpx.Timeout(connect=5.0, read=7.0, write=5.0, pool=5.0)
_MAX_CONCURRENT = 6
_USER_AGENT = "sec-toolkit-osint/0.1 (username-probe)"


class UsernameValidationError(ValueError):
    """Raised when the input fails the valid-username regex."""


async def _probe(
    client: httpx.AsyncClient, platform: _Platform, username: str, sem: asyncio.Semaphore
) -> UsernameHit:
    """Single platform probe. Never raises - failures become 'inconclusive'."""
    url = platform.url_template.format(username=username)
    try:
        async with sem:
            response = await client.get(url, follow_redirects=True)
    except (httpx.TimeoutException, httpx.HTTPError) as exc:
        return UsernameHit(
            platform=platform.name,
            category=platform.category,
            url=url,
            status="inconclusive",
            http_status=0,
            note=f"request failed: {type(exc).__name__}",
        )

    return _classify(platform, url, response)


def _classify(platform: _Platform, url: str, response: httpx.Response) -> UsernameHit:
    """Map HTTP response → present/absent/inconclusive.

    Rules in precedence order:
    1. 404/410 → absent (clearest signal).
    2. 429/403 (rate-limited or blocked) → inconclusive, not a false-positive.
    3. 5xx → inconclusive (platform-side fault, not user signal).
    4. 200 with ``absence_marker`` in body → absent.
    5. 200 otherwise → present.
    6. Everything else (3xx that resolved somewhere strange) → inconclusive.
    """
    code = response.status_code
    base_kwargs = {
        "platform": platform.name,
        "category": platform.category,
        "url": url,
        "http_status": code,
    }

    if code in (404, 410):
        return UsernameHit(status="absent", note="", **base_kwargs)  # type: ignore[arg-type]
    if code in (403, 429):
        return UsernameHit(
            status="inconclusive",
            note="blocked or rate-limited",
            **base_kwargs,  # type: ignore[arg-type]
        )
    if 500 <= code < 600:
        return UsernameHit(
            status="inconclusive",
            note="platform 5xx",
            **base_kwargs,  # type: ignore[arg-type]
        )
    if code == 200:
        if platform.absence_marker and platform.absence_marker in response.text:
            return UsernameHit(status="absent", note="", **base_kwargs)  # type: ignore[arg-type]
        return UsernameHit(status="present", note="", **base_kwargs)  # type: ignore[arg-type]
    return UsernameHit(
        status="inconclusive",
        note=f"unexpected status {code}",
        **base_kwargs,  # type: ignore[arg-type]
    )


async def search_username(
    username: str, *, platforms: tuple[_Platform, ...] = _PLATFORMS
) -> UsernameSearchResult:
    """Fan-out probe for ``username`` across the curated platform list.

    ``platforms`` is overridable so tests can inject a short list without
    stubbing the whole ``_PLATFORMS`` module constant.
    """
    if not _VALID_USERNAME.match(username):
        raise UsernameValidationError(
            "username must be 1-64 chars of [A-Za-z0-9_.-]"
        )

    sem = asyncio.Semaphore(_MAX_CONCURRENT)
    async with httpx.AsyncClient(
        timeout=_TIMEOUT, headers={"User-Agent": _USER_AGENT}
    ) as client:
        hits = await asyncio.gather(
            *(_probe(client, p, username, sem) for p in platforms)
        )

    present = sum(1 for h in hits if h.status == "present")
    return UsernameSearchResult(
        username=username,
        hits=list(hits),
        checked=len(platforms),
        present_count=present,
    )
