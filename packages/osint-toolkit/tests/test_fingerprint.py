"""Website fingerprinter: pure detection + SSRF/redirect/auth gating."""

import pytest
from fastapi import HTTPException

from api.routes.investigate import FingerprintQuery, investigate_fingerprint
from core.fingerprint.fingerprinter import detect, fingerprint_site


def test_detect_headers_meta_and_assets() -> None:
    headers = {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.1.2"}
    body = (
        '<meta name="generator" content="WordPress 6.4.2">'
        '<link href="/wp-content/themes/x/style.css">'
        '<script src="/js/jquery-3.6.0.min.js"></script>'
    )
    techs = {t.name: t for t in detect(headers, body)}
    assert techs["nginx"].version == "1.18.0"
    assert techs["PHP"].version == "8.1.2"
    assert techs["WordPress"].version == "6.4.2"
    assert techs["jQuery"].version == "3.6.0"


def test_detect_dedupes_and_prefers_versioned() -> None:
    techs = detect(
        {}, '<meta name="generator" content="WordPress 6.4"> wp-includes'
    )
    wordpress = [t for t in techs if t.name == "WordPress"]
    assert len(wordpress) == 1
    assert wordpress[0].version == "6.4"


@pytest.mark.asyncio
async def test_fingerprint_blocks_private_host() -> None:
    result = await fingerprint_site("http://127.0.0.1/")
    assert "private" in result.error or "blocked" in result.error
    assert result.technologies == []


@pytest.mark.asyncio
async def test_fingerprint_rejects_non_http_scheme() -> None:
    result = await fingerprint_site("ftp://example.com/x")
    assert "http" in result.error


@pytest.mark.asyncio
async def test_fingerprint_follows_redirect_with_fake_fetch() -> None:
    pages: dict[str, tuple[int, dict[str, str], str, str | None]] = {
        "http://93.184.216.34/": (301, {}, "", "http://93.184.216.34/home"),
        "http://93.184.216.34/home": (
            200, {"Server": "Apache/2.4.41"}, "<html>wp-content</html>", None,
        ),
    }

    async def fake_fetch(
        _client: object, url: str
    ) -> tuple[int, dict[str, str], str, str | None]:
        return pages[url]

    result = await fingerprint_site("http://93.184.216.34/", fetch=fake_fetch)
    assert result.final_url == "http://93.184.216.34/home"
    assert result.status == 200
    names = {t.name for t in result.technologies}
    assert "Apache" in names
    assert "WordPress" in names


@pytest.mark.asyncio
async def test_fingerprint_route_requires_authorization() -> None:
    with pytest.raises(HTTPException) as exc:
        await investigate_fingerprint(
            FingerprintQuery(url="http://example.com", authorized=False)
        )
    assert exc.value.status_code == 403
