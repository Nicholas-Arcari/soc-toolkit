"""Website technology fingerprinter.

Given an authorized URL, fetches the page once and infers the software +
versions from HTTP headers, the ``<meta generator>`` tag, asset/path
signatures and common JS libraries. This is active recon (it touches the
target), so the route gates it behind an explicit authorization
acknowledgment; this module additionally refuses private/loopback hosts via
the shared SSRF guard and re-checks the host on every redirect hop.

The per-hop fetch is injectable (``fetch=``) so detection + redirect/SSRF
logic is testable without network.
"""
from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx
from sec_common.netguard import url_blocked

_TIMEOUT = 10.0
_MAX_BODY = 512 * 1024  # the <head> is enough for fingerprints
_HEADERS = {"User-Agent": "osint-toolkit-fp/1.0"}
_MAX_REDIRECTS = 4

# fetch(client, url) -> (status, headers, body, location)
Fetch = Callable[
    [httpx.AsyncClient, str],
    Awaitable[tuple[int, "dict[str, str]", str, "str | None"]],
]

_META_GENERATOR = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']""", re.I
)
_JQUERY = re.compile(r"jquery[-/](\d+\.\d+(?:\.\d+)?)", re.I)
_BOOTSTRAP = re.compile(r"bootstrap[-/](\d+\.\d+(?:\.\d+)?)", re.I)

_COOKIE_SIGNS: dict[str, tuple[str, str]] = {
    "phpsessid": ("PHP", "language"),
    "wordpress_": ("WordPress", "cms"),
    "wp-settings": ("WordPress", "cms"),
    "laravel_session": ("Laravel", "framework"),
    "jsessionid": ("Java", "language"),
    "asp.net_sessionid": ("ASP.NET", "framework"),
    "csrftoken": ("Django", "framework"),
}
_BODY_SIGNS: tuple[tuple[str, str, str], ...] = (
    ("wp-content", "WordPress", "cms"),
    ("wp-includes", "WordPress", "cms"),
    ("/sites/default/files", "Drupal", "cms"),
    ("drupal.settings", "Drupal", "cms"),
    ("cdn.shopify.com", "Shopify", "cms"),
    ("/_next/", "Next.js", "framework"),
    ("/_nuxt/", "Nuxt.js", "framework"),
    ("static.parastorage.com", "Wix", "cms"),
    ("squarespace.com", "Squarespace", "cms"),
)


@dataclass
class Technology:
    name: str
    category: str
    version: str = ""
    evidence: str = ""


@dataclass
class FingerprintResult:
    url: str
    final_url: str
    status: int
    technologies: list[Technology] = field(default_factory=list)
    error: str = ""


def _split_name_version(text: str) -> tuple[str, str]:
    match = re.match(r"^(.*?)\s+(\d[\w.\-]*)\s*$", text.strip())
    if match:
        return match.group(1).strip(), match.group(2)
    return text.strip(), ""


def _detect_from_headers(headers: dict[str, str]) -> list[Technology]:
    lower = {k.lower(): v for k, v in headers.items()}
    techs: list[Technology] = []

    server = lower.get("server", "")
    if server:
        name, _, version = server.partition("/")
        techs.append(
            Technology(
                name=name.strip() or server,
                category="server",
                version=version.split()[0] if version else "",
                evidence="Server header",
            )
        )
    powered = lower.get("x-powered-by", "")
    if powered:
        name, _, version = powered.partition("/")
        techs.append(
            Technology(
                name=name.strip(),
                category="language",
                version=version.strip(),
                evidence="X-Powered-By",
            )
        )
    if lower.get("x-aspnet-version"):
        techs.append(
            Technology(
                name="ASP.NET",
                category="framework",
                version=lower["x-aspnet-version"].strip(),
                evidence="X-AspNet-Version",
            )
        )
    if lower.get("x-generator"):
        name, version = _split_name_version(lower["x-generator"])
        techs.append(
            Technology(name=name, category="cms", version=version, evidence="X-Generator")
        )
    if "x-drupal-cache" in lower or "x-drupal-dynamic-cache" in lower:
        techs.append(Technology("Drupal", "cms", evidence="X-Drupal-* header"))
    if "x-shopify-stage" in lower or "x-shopid" in lower:
        techs.append(Technology("Shopify", "cms", evidence="Shopify header"))
    if "cf-ray" in lower or "cloudflare" in server.lower():
        techs.append(Technology("Cloudflare", "cdn", evidence="CF-Ray/Server"))

    cookies = lower.get("set-cookie", "").lower()
    for needle, (name, category) in _COOKIE_SIGNS.items():
        if needle in cookies:
            techs.append(
                Technology(name, category, evidence=f"cookie '{needle}'")
            )
    return techs


def detect(headers: dict[str, str], body: str) -> list[Technology]:
    """Infer technologies from response headers + HTML (pure, no network)."""
    techs = _detect_from_headers(headers)

    meta = _META_GENERATOR.search(body)
    if meta:
        name, version = _split_name_version(meta.group(1))
        techs.append(
            Technology(name, "cms", version=version, evidence="meta generator")
        )

    lower_body = body.lower()
    for needle, name, category in _BODY_SIGNS:
        if needle in lower_body:
            techs.append(
                Technology(name, category, evidence=f"asset/path '{needle}'")
            )

    jquery = _JQUERY.search(body)
    if jquery:
        techs.append(
            Technology("jQuery", "js", version=jquery.group(1), evidence="script src")
        )
    bootstrap = _BOOTSTRAP.search(body)
    if bootstrap:
        techs.append(
            Technology("Bootstrap", "js", version=bootstrap.group(1), evidence="asset")
        )

    return _dedupe(techs)


def _dedupe(techs: list[Technology]) -> list[Technology]:
    by_name: dict[str, Technology] = {}
    for tech in techs:
        key = tech.name.lower()
        existing = by_name.get(key)
        if existing is None or (not existing.version and tech.version):
            by_name[key] = tech
    return list(by_name.values())


async def _fetch(
    client: httpx.AsyncClient, url: str
) -> tuple[int, dict[str, str], str, str | None]:
    # Stream so a malicious huge body is capped at _MAX_BODY, not fully buffered.
    async with client.stream("GET", url) as resp:
        location = resp.headers.get("location")
        if resp.status_code >= 300:
            return resp.status_code, dict(resp.headers), "", location
        chunks: list[str] = []
        total = 0
        async for chunk in resp.aiter_text():
            chunks.append(chunk)
            total += len(chunk)
            if total >= _MAX_BODY:
                break
        return resp.status_code, dict(resp.headers), "".join(chunks)[:_MAX_BODY], location


async def fingerprint_site(url: str, *, fetch: Fetch = _fetch) -> FingerprintResult:
    """Fetch ``url`` (following redirects safely) and fingerprint its stack."""
    if urlparse(url).scheme not in ("http", "https"):
        return FingerprintResult(
            url=url, final_url=url, status=0,
            error="only http/https URLs are supported",
        )

    current = url
    async with httpx.AsyncClient(
        follow_redirects=False, timeout=_TIMEOUT, headers=_HEADERS
    ) as client:
        for _ in range(_MAX_REDIRECTS + 1):
            if await url_blocked(current):
                return FingerprintResult(
                    url=url, final_url=current, status=0,
                    error="destination host/port/scheme is blocked",
                )
            try:
                status, headers, body, location = await fetch(client, current)
            except httpx.HTTPError as exc:
                return FingerprintResult(
                    url=url, final_url=current, status=0,
                    error=f"request failed: {exc}",
                )
            if 300 <= status < 400 and location:
                current = urljoin(current, location)
                continue
            return FingerprintResult(
                url=url,
                final_url=current,
                status=status,
                technologies=detect(headers, body),
            )

    return FingerprintResult(
        url=url, final_url=current, status=0, error="too many redirects"
    )
