"""Tests for the OSINT pivot orchestrator.

Mocks are applied at the client-method level (``AsyncMock`` on
``search``, ``lookup``, etc.) - bypasses sec-common's cache layer
without needing a DB fixture, while still exercising the real
orchestration logic in ``pivot_engine``.
"""
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.osint_pivot.pivot_engine import PivotClients, pivot


def _make_clients(**overrides: object) -> PivotClients:
    """Build a PivotClients bundle where each client is a MagicMock.

    Per-test code overrides specific methods with AsyncMock returning
    canned data. Methods not overridden return MagicMock (which would
    break the real type signature but we only call what we override).
    """
    bundle = PivotClients(
        crtsh=MagicMock(),
        securitytrails=MagicMock(),
        mnemonic=MagicMock(),
        whois=MagicMock(),
        asn=MagicMock(),
        reverse_dns=MagicMock(),
        shodan=MagicMock(),
    )
    for key, val in overrides.items():
        setattr(bundle, key, val)
    return bundle


@pytest.mark.asyncio
async def test_pivot_domain_combines_sources() -> None:
    crtsh = MagicMock()
    crtsh.search = AsyncMock(return_value=[
        {"subdomain": "www.example.com", "issuer": "Let's Encrypt", "active": True},
    ])

    securitytrails = MagicMock()
    securitytrails.dns_history = AsyncMock(return_value=[
        {"value": "93.184.216.34", "record_type": "A", "source": "securitytrails"},
    ])
    securitytrails.whois_history = AsyncMock(return_value=[
        {"registrar": "Acme", "source": "securitytrails"},
    ])
    securitytrails.subdomains = AsyncMock(return_value=["www.example.com", "api.example.com"])

    mnemonic = MagicMock()
    mnemonic.search = AsyncMock(return_value=[
        {"value": "93.184.216.35", "record_type": "A", "source": "mnemonic"},
    ])

    whois = MagicMock()
    whois.lookup = AsyncMock(return_value={"registrar": "Acme", "country": "US"})

    clients = _make_clients(
        crtsh=crtsh, securitytrails=securitytrails, mnemonic=mnemonic, whois=whois,
    )

    result = await pivot("domain", "example.com", clients=clients)

    assert result["target"] == "example.com"
    assert result["target_type"] == "domain"
    assert len(result["pivot"]["certificates"]) == 1
    # passive_dns concatenates SecurityTrails + Mnemonic
    assert len(result["pivot"]["passive_dns"]) == 2
    assert result["pivot"]["whois"]["registrar"] == "Acme"
    assert len(result["pivot"]["subdomains"]) == 2
    assert result["summary"]["total_certificates"] == 1
    assert result["summary"]["has_whois"] is True


@pytest.mark.asyncio
async def test_pivot_ip_combines_sources() -> None:
    asn = MagicMock()
    asn.lookup = AsyncMock(return_value={
        "asn": "AS15169", "asn_description": "GOOGLE", "country": "US",
        "cidr": "8.8.8.0/24", "registry": "arin", "source": "ipwhois",
    })

    rdns = MagicMock()
    rdns.lookup = AsyncMock(return_value=["dns.google"])

    mnemonic = MagicMock()
    mnemonic.search = AsyncMock(return_value=[
        {"value": "dns.google", "record_type": "A", "source": "mnemonic"},
    ])

    shodan = MagicMock()
    shodan.check_ip = AsyncMock(return_value={
        "ip": "8.8.8.8", "organization": "Google LLC", "open_ports": [53, 443],
    })

    clients = _make_clients(asn=asn, reverse_dns=rdns, mnemonic=mnemonic, shodan=shodan)

    result = await pivot("ipv4", "8.8.8.8", clients=clients)

    assert result["target"] == "8.8.8.8"
    assert result["target_type"] == "ip"
    assert result["pivot"]["asn"]["asn"] == "AS15169"
    assert result["pivot"]["reverse_dns"] == ["dns.google"]
    assert len(result["pivot"]["passive_dns"]) == 1
    assert result["pivot"]["shodan"]["open_ports"] == [53, 443]
    assert result["summary"]["asn"] == "AS15169"
    assert result["summary"]["has_shodan"] is True


@pytest.mark.asyncio
async def test_pivot_handles_source_failure() -> None:
    """One client raising shouldn't abort the pivot."""
    crtsh = MagicMock()
    crtsh.search = AsyncMock(side_effect=RuntimeError("crt.sh down"))

    securitytrails = MagicMock()
    securitytrails.dns_history = AsyncMock(return_value=[])
    securitytrails.whois_history = AsyncMock(return_value=[])
    securitytrails.subdomains = AsyncMock(return_value=["www.example.com"])

    mnemonic = MagicMock()
    mnemonic.search = AsyncMock(return_value=[])

    whois = MagicMock()
    whois.lookup = AsyncMock(return_value={})

    clients = _make_clients(
        crtsh=crtsh, securitytrails=securitytrails, mnemonic=mnemonic, whois=whois,
    )

    result = await pivot("domain", "example.com", clients=clients)

    # crtsh failure → empty list, other sections still populated
    assert result["pivot"]["certificates"] == []
    assert result["pivot"]["subdomains"] == ["www.example.com"]


@pytest.mark.asyncio
async def test_pivot_degraded_mode_no_api_keys() -> None:
    """All sources empty simulates a fresh install with no API keys."""
    crtsh = MagicMock()
    crtsh.search = AsyncMock(return_value=[])
    securitytrails = MagicMock()
    securitytrails.dns_history = AsyncMock(return_value=[])
    securitytrails.whois_history = AsyncMock(return_value=[])
    securitytrails.subdomains = AsyncMock(return_value=[])
    mnemonic = MagicMock()
    mnemonic.search = AsyncMock(return_value=[])
    whois = MagicMock()
    whois.lookup = AsyncMock(return_value={})

    clients = _make_clients(
        crtsh=crtsh, securitytrails=securitytrails, mnemonic=mnemonic, whois=whois,
    )

    result = await pivot("domain", "example.com", clients=clients)

    # Envelope still well-formed, all sections empty - not an error
    assert result["target"] == "example.com"
    assert "error" not in result
    assert result["summary"]["total_certificates"] == 0
    assert result["summary"]["has_whois"] is False


@pytest.mark.asyncio
async def test_pivot_unsupported_type_returns_error() -> None:
    result = await pivot("sha256", "abc123", clients=_make_clients())
    assert "error" in result
    assert "Unsupported indicator type" in result["error"]
    assert result["target"] == "abc123"


@pytest.mark.asyncio
async def test_pivot_type_case_insensitive() -> None:
    crtsh = MagicMock()
    crtsh.search = AsyncMock(return_value=[])
    securitytrails = MagicMock()
    securitytrails.dns_history = AsyncMock(return_value=[])
    securitytrails.whois_history = AsyncMock(return_value=[])
    securitytrails.subdomains = AsyncMock(return_value=[])
    mnemonic = MagicMock()
    mnemonic.search = AsyncMock(return_value=[])
    whois = MagicMock()
    whois.lookup = AsyncMock(return_value={})

    clients = _make_clients(
        crtsh=crtsh, securitytrails=securitytrails, mnemonic=mnemonic, whois=whois,
    )

    result = await pivot("DOMAIN", "example.com", clients=clients)
    assert result["target_type"] == "domain"
    assert "error" not in result


@pytest.mark.asyncio
async def test_pivot_domain_mines_subdomains_from_certs() -> None:
    crtsh = MagicMock()
    crtsh.search = AsyncMock(return_value=[
        {"subdomain": "*.example.com", "cert_id": 1},
        {"subdomain": "Mail.Example.com", "cert_id": 2},
        {"subdomain": "other.org", "cert_id": 3},  # off-domain → dropped
    ])
    securitytrails = MagicMock()
    securitytrails.dns_history = AsyncMock(return_value=[])
    securitytrails.whois_history = AsyncMock(return_value=[])
    securitytrails.subdomains = AsyncMock(return_value=["api.example.com"])
    mnemonic = MagicMock()
    mnemonic.search = AsyncMock(return_value=[])
    whois = MagicMock()
    whois.lookup = AsyncMock(return_value={})

    clients = _make_clients(
        crtsh=crtsh, securitytrails=securitytrails, mnemonic=mnemonic, whois=whois,
    )
    result = await pivot("domain", "example.com", clients=clients)

    # wildcard stripped, case-normalized, off-domain dropped, deduped + sorted
    assert result["pivot"]["subdomains"] == ["api.example.com", "mail.example.com"]
    assert result["summary"]["total_subdomains"] == 2
    # certs collapsed to unique cert_ids
    assert len(result["pivot"]["certificates"]) == 3


@pytest.mark.asyncio
async def test_pivot_merges_and_dedupes_passive_dns_with_otx() -> None:
    crtsh = MagicMock()
    crtsh.search = AsyncMock(return_value=[])
    securitytrails = MagicMock()
    securitytrails.dns_history = AsyncMock(return_value=[
        {"value": "1.1.1.1", "record_type": "A", "source": "securitytrails"},
    ])
    securitytrails.whois_history = AsyncMock(return_value=[])
    securitytrails.subdomains = AsyncMock(return_value=[])
    mnemonic = MagicMock()
    mnemonic.search = AsyncMock(return_value=[
        {"value": "1.1.1.1", "record_type": "A", "source": "mnemonic"},  # dup
    ])
    whois = MagicMock()
    whois.lookup = AsyncMock(return_value={})
    otx = MagicMock()
    otx.passive_dns = AsyncMock(return_value=[
        {"value": "2.2.2.2", "record_type": "A", "source": "otx"},
    ])

    clients = _make_clients(
        crtsh=crtsh, securitytrails=securitytrails, mnemonic=mnemonic,
        whois=whois, otx=otx,
    )
    result = await pivot("domain", "example.com", clients=clients)

    # ST + Mnemonic duplicate collapses to one; OTX adds a distinct value
    assert sorted(r["value"] for r in result["pivot"]["passive_dns"]) == [
        "1.1.1.1",
        "2.2.2.2",
    ]
    otx.passive_dns.assert_awaited_once_with("example.com", "domain")


@pytest.mark.asyncio
async def test_pivot_ip_includes_otx_passive_dns() -> None:
    asn = MagicMock()
    asn.lookup = AsyncMock(return_value={"asn": "AS1", "asn_description": "X"})
    rdns = MagicMock()
    rdns.lookup = AsyncMock(return_value=[])
    mnemonic = MagicMock()
    mnemonic.search = AsyncMock(return_value=[])
    shodan = MagicMock()
    shodan.check_ip = AsyncMock(return_value={})
    otx = MagicMock()
    otx.passive_dns = AsyncMock(return_value=[
        {"value": "host.example.com", "record_type": "A", "source": "otx"},
    ])

    clients = _make_clients(
        asn=asn, reverse_dns=rdns, mnemonic=mnemonic, shodan=shodan, otx=otx,
    )
    result = await pivot("ipv4", "1.2.3.4", clients=clients)

    assert [r["value"] for r in result["pivot"]["passive_dns"]] == [
        "host.example.com"
    ]
    otx.passive_dns.assert_awaited_once_with("1.2.3.4", "ip")
