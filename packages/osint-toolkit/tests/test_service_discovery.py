"""Service discovery: Shodan enrichment + CVE finding emission.

Integration surface is mocked at two boundaries:

- DNS (`_FakeResolver`) - we don't want flaky DNS during CI.
- `ShodanClient.check_ip` - avoids real API hits and lets each test
  dictate the exact host payload the scan sees.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import dns.resolver
import pytest
from sqlalchemy import select

from core.asm import service_discovery as svc_mod
from db.models import Finding, Service, Subdomain, Target


@dataclass
class _FakeAnswer:
    values: list[str]

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter(self.values)


class _FakeResolver:
    def __init__(self, mapping: dict[str, list[str]]):
        self.mapping = mapping

    async def resolve(self, qname: str, rtype: str) -> _FakeAnswer:  # noqa: D401
        key = qname.rstrip(".").lower()
        if key not in self.mapping:
            raise dns.resolver.NoAnswer()
        return _FakeAnswer(self.mapping[key])


async def _make_target_with_subdomains(
    session, *, fqdns: list[str]
) -> Target:
    target = Target(
        name="acme",
        scope_domains=["acme.test"],
        authorized_to_scan=True,
        active=True,
    )
    session.add(target)
    await session.flush()

    for fqdn in fqdns:
        session.add(Subdomain(target_id=target.id, fqdn=fqdn, source="crtsh"))
    await session.flush()
    return target


async def test_degraded_mode_when_no_shodan_key(db_session: Any) -> None:
    """Without a Shodan key the scan short-circuits cleanly."""
    target = await _make_target_with_subdomains(db_session, fqdns=["www.acme.test"])

    shodan = MagicMock()
    shodan.api_key = ""
    result = await svc_mod.discover_services(
        target,
        clients=svc_mod.DiscoveryClients(shodan=shodan),
        session=db_session,
        resolver=_FakeResolver({}),  # type: ignore[arg-type]
    )

    assert result.skipped_reason == "no_shodan_key"
    summary = svc_mod.summarize(result)
    assert summary["skipped"] is True
    assert "SHODAN_API_KEY" in summary["note"]
    shodan.check_ip.assert_not_called() if hasattr(shodan.check_ip, "assert_not_called") else None


async def test_deduplicates_ips_across_subdomains(db_session: Any) -> None:
    """Multiple subdomains → same IP → one Shodan lookup."""
    target = await _make_target_with_subdomains(
        db_session, fqdns=["a.acme.test", "b.acme.test", "c.acme.test"]
    )
    resolver = _FakeResolver({
        "a.acme.test": ["192.0.2.10"],
        "b.acme.test": ["192.0.2.10"],  # same IP as a.
        "c.acme.test": ["192.0.2.11"],
    })

    shodan = MagicMock()
    shodan.api_key = "present"
    shodan.check_ip = AsyncMock(return_value={
        "ip": "192.0.2.10",
        "organization": "Example Corp",
        "open_ports": [443],
        "vulns": [],
    })

    result = await svc_mod.discover_services(
        target,
        clients=svc_mod.DiscoveryClients(shodan=shodan),
        session=db_session,
        resolver=resolver,  # type: ignore[arg-type]
    )

    assert shodan.check_ip.await_count == 2
    assert result.hosts_checked == 2


async def test_services_persisted_with_cves_and_finding(db_session: Any) -> None:
    """CVE list surfaces as Service.cves AND a high-severity Finding."""
    target = await _make_target_with_subdomains(db_session, fqdns=["www.acme.test"])
    resolver = _FakeResolver({"www.acme.test": ["192.0.2.20"]})

    shodan = MagicMock()
    shodan.api_key = "present"
    shodan.check_ip = AsyncMock(return_value={
        "ip": "192.0.2.20",
        "organization": "Acme Hosting",
        "open_ports": [22, 443],
        "vulns": ["CVE-2024-1234", "CVE-2024-5678"],
    })

    result = await svc_mod.discover_services(
        target,
        clients=svc_mod.DiscoveryClients(shodan=shodan),
        session=db_session,
        resolver=resolver,  # type: ignore[arg-type]
    )

    assert result.services_new == 2
    assert result.cves_seen == ["CVE-2024-1234", "CVE-2024-5678"]

    services = (await db_session.execute(select(Service))).scalars().all()
    assert len(services) == 2
    assert all(s.cves == ["CVE-2024-1234", "CVE-2024-5678"] for s in services)

    findings = (
        await db_session.execute(
            select(Finding).where(Finding.category == "cve_exposure")
        )
    ).scalars().all()
    assert len(findings) == 2
    assert all(f.severity == "high" for f in findings)


async def test_rescan_updates_last_seen_and_cves(db_session: Any) -> None:
    """Second scan over same (subdomain, ip, port) bumps last_seen and CVEs."""
    target = await _make_target_with_subdomains(db_session, fqdns=["api.acme.test"])
    resolver = _FakeResolver({"api.acme.test": ["192.0.2.30"]})

    shodan = MagicMock()
    shodan.api_key = "present"
    shodan.check_ip = AsyncMock(return_value={
        "ip": "192.0.2.30",
        "organization": "Acme",
        "open_ports": [443],
        "vulns": ["CVE-2024-0001"],
    })

    result_1 = await svc_mod.discover_services(
        target,
        clients=svc_mod.DiscoveryClients(shodan=shodan),
        session=db_session,
        resolver=resolver,  # type: ignore[arg-type]
    )
    assert result_1.services_new == 1

    # Simulate a re-scan where a new CVE got added upstream.
    shodan.check_ip = AsyncMock(return_value={
        "ip": "192.0.2.30",
        "organization": "Acme",
        "open_ports": [443],
        "vulns": ["CVE-2024-0001", "CVE-2024-0002"],
    })

    result_2 = await svc_mod.discover_services(
        target,
        clients=svc_mod.DiscoveryClients(shodan=shodan),
        session=db_session,
        resolver=resolver,  # type: ignore[arg-type]
    )
    assert result_2.services_updated == 1
    assert result_2.services_new == 0

    service = (await db_session.execute(select(Service))).scalars().one()
    assert set(service.cves) == {"CVE-2024-0001", "CVE-2024-0002"}


async def test_shodan_error_is_skipped_not_raised(db_session: Any) -> None:
    """Shodan-returned ``{"error": ...}`` is ignored; scan still completes."""
    target = await _make_target_with_subdomains(db_session, fqdns=["www.acme.test"])
    resolver = _FakeResolver({"www.acme.test": ["192.0.2.40"]})

    shodan = MagicMock()
    shodan.api_key = "present"
    shodan.check_ip = AsyncMock(return_value={"ip": "192.0.2.40", "error": "lookup failed"})

    result = await svc_mod.discover_services(
        target,
        clients=svc_mod.DiscoveryClients(shodan=shodan),
        session=db_session,
        resolver=resolver,  # type: ignore[arg-type]
    )

    assert result.services_new == 0
    assert result.hosts_checked == 1  # we *did* check, just got nothing


async def test_empty_subdomain_list_returns_clean(db_session: Any) -> None:
    target = Target(
        name="empty",
        scope_domains=["empty.test"],
        authorized_to_scan=True,
        active=True,
    )
    db_session.add(target)
    await db_session.flush()

    shodan = MagicMock()
    shodan.api_key = "present"

    result = await svc_mod.discover_services(
        target,
        clients=svc_mod.DiscoveryClients(shodan=shodan),
        session=db_session,
        resolver=_FakeResolver({}),  # type: ignore[arg-type]
    )

    assert result.hosts_checked == 0
    assert result.services_new == 0
