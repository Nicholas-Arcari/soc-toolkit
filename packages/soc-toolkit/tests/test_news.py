"""RSS/Atom parsing for the security-news aggregator (no network)."""

from core.news.feeds import NewsItem, parse_feed

RSS = """<?xml version="1.0"?>
<rss version="2.0"><channel>
  <title>Feed</title>
  <item>
    <title>Critical RCE in Widget</title>
    <link>https://example.com/rce</link>
    <pubDate>Tue, 10 Jun 2025 08:00:00 GMT</pubDate>
    <description>&lt;p&gt;A &lt;b&gt;serious&lt;/b&gt; bug.&lt;/p&gt;</description>
  </item>
  <item>
    <title>No link is skipped</title>
  </item>
</channel></rss>"""

ATOM = """<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>Atom Advisory</title>
    <link href="https://example.com/atom" rel="alternate"/>
    <updated>2025-06-09T12:30:00Z</updated>
    <summary>Patch now.</summary>
  </entry>
</feed>"""


def test_parse_rss_extracts_and_cleans() -> None:
    items = parse_feed(RSS, "Src")
    assert len(items) == 1  # the link-less item is skipped
    item = items[0]
    assert isinstance(item, NewsItem)
    assert item.title == "Critical RCE in Widget"
    assert item.link == "https://example.com/rce"
    assert item.source == "Src"
    assert item.summary == "A serious bug."  # HTML stripped
    assert item.published is not None
    assert item.published.startswith("2025-06-10T08:00:00")


def test_parse_atom_uses_link_href_and_iso_date() -> None:
    items = parse_feed(ATOM, "Atom")
    assert len(items) == 1
    assert items[0].link == "https://example.com/atom"
    assert items[0].summary == "Patch now."
    assert items[0].published is not None
    assert items[0].published.startswith("2025-06-09T12:30:00")


def test_parse_garbage_returns_empty() -> None:
    assert parse_feed("definitely not xml <<<", "x") == []
