"""Security-news aggregation from free RSS/Atom feeds.

Fetched server-side (avoids browser CORS), parsed with the stdlib (no extra
dependency), and cached in-process for a few minutes so the page is snappy
and we stay polite to the upstream feeds. Individual feed failures degrade
gracefully - the others still render.
"""
from __future__ import annotations

import asyncio
import html
import re
import time
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from xml.etree import ElementTree as ET

import httpx
from pydantic import BaseModel

# Curated free feeds. Hardcoded (not user input) so XML parsing stays on
# trusted sources.
SOURCES: list[tuple[str, str]] = [
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    ("CISA", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
]

_CACHE_TTL = 1200.0  # 20 minutes
_MAX_SUMMARY = 280
_TIMEOUT = 10.0

_cache_items: list[NewsItem] = []
_cache_ts = 0.0
_lock = asyncio.Lock()


class NewsItem(BaseModel):
    title: str
    link: str
    source: str
    published: str | None = None  # ISO 8601 UTC, or None if unparseable
    summary: str = ""


def _local(tag: str) -> str:
    """Local tag name without the XML namespace (Atom uses one, RSS doesn't)."""
    return tag.rsplit("}", 1)[-1].lower()


def _clean(text: str | None) -> str:
    if not text:
        return ""
    out = re.sub(r"<[^>]+>", "", text)
    out = re.sub(r"\s+", " ", html.unescape(out)).strip()
    if len(out) > _MAX_SUMMARY:
        out = out[:_MAX_SUMMARY].rstrip() + "…"
    return out


def _parse_date(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    dt: datetime | None
    try:
        dt = parsedate_to_datetime(value)  # RSS RFC 822
    except (TypeError, ValueError):
        dt = None
    if dt is None:
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))  # Atom ISO
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat()


def parse_feed(xml_text: str | bytes, source: str) -> list[NewsItem]:
    """Parse an RSS 2.0 or Atom document into NewsItems (best-effort)."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    items: list[NewsItem] = []
    for node in root.iter():
        if _local(node.tag) not in ("item", "entry"):
            continue
        title = ""
        link = ""
        published: str | None = None
        summary = ""
        for child in node:
            cname = _local(child.tag)
            if cname == "title":
                title = (child.text or "").strip()
            elif cname == "link":
                href = child.get("href")
                link = href.strip() if href else (child.text or "").strip()
            elif cname in ("pubdate", "published", "updated", "date") and not published:
                published = _parse_date(child.text)
            elif cname in ("description", "summary", "content") and not summary:
                summary = _clean(child.text)
        if title and link:
            items.append(
                NewsItem(
                    title=html.unescape(title),
                    link=link,
                    source=source,
                    published=published,
                    summary=summary,
                )
            )
    return items


async def _fetch_one(
    client: httpx.AsyncClient, source: str, url: str
) -> list[NewsItem]:
    try:
        resp = await client.get(
            url, headers={"User-Agent": "soc-toolkit-news/1.0"}
        )
        resp.raise_for_status()
    except httpx.HTTPError:
        return []
    return parse_feed(resp.text, source)


async def fetch_news(limit: int = 40, *, force: bool = False) -> list[NewsItem]:
    """Merged, newest-first security news across SOURCES (cached ~20 min)."""
    global _cache_items, _cache_ts
    fresh = _cache_items and (time.monotonic() - _cache_ts) < _CACHE_TTL
    if not force and fresh:
        return _cache_items[:limit]
    async with _lock:
        fresh = _cache_items and (time.monotonic() - _cache_ts) < _CACHE_TTL
        if not force and fresh:
            return _cache_items[:limit]
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, follow_redirects=True
        ) as client:
            batches = await asyncio.gather(
                *(_fetch_one(client, name, url) for name, url in SOURCES)
            )
        merged = [item for batch in batches for item in batch]
        # Newest first; items without a parseable date sink to the bottom.
        merged.sort(key=lambda item: item.published or "", reverse=True)
        _cache_items = merged
        _cache_ts = time.monotonic()
        return merged[:limit]
