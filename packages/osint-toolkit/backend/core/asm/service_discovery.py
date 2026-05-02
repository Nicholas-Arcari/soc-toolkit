"""Service discovery via Shodan.

For every subdomain already discovered for a target, resolve it to an
IP and query Shodan for open ports / banners / CVEs. The passive model:
Shodan sees the target because *it* scanned the internet - we only read
cached results, never touch the target ourselves.

Design notes
------------
- **Degraded mode**: missing Shodan key short-circuits cleanly with a
  note in the scan summary; the endpoint stays 2xx so the UI can flag
  the gap instead of erroring.
- **IP deduplication**: multiple subdomains can share an IP. We query
  Shodan once per distinct IP and fan the result back out to every
  subdomain that resolved to it, so a free-tier rate budget doesn't
  get burned on duplicates.
- **Passive**: no active port scan. We only ingest what Shodan already
  observed. Anything Shodan hasn't scanned simply doesn't appear.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver
from sec_common.integrations import ShodanClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import Finding, Service, Subdomain, Target


@dataclass
class DiscoveryClients:
    shodan: ShodanClient


@dataclass
class DiscoveryResult:
    target_id: int
    hosts_checked: int
    services_new: int = 0
    services_updated: int = 0
    cves_seen: list[str] = field(default_factory=list)
    skipped_reason: str | None = None


async def _resolve_a(
    resolver: dns.asyncresolver.Resolver, fqdn: str
) -> list[str]:
    """Return IPv4 addresses for fqdn, or [] on any resolver error."""
    try:
        answer = await resolver.resolve(fqdn, "A")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return []
    return sorted(str(r) for r in answer)


async def discover_services(
    target: Target,
    *,
    clients: DiscoveryClients,
    session: AsyncSession,
    resolver: dns.asyncresolver.Resolver | None = None,
) -> DiscoveryResult:
    """Run service discovery against every subdomain currently known.

    The operation is idempotent at the (subdomain, port) grain: a second
    run updates `last_seen` on existing rows rather than duplicating.
    """
    resolver = resolver or dns.asyncresolver.Resolver()

    if not clients.shodan.api_key:
        return DiscoveryResult(
            target_id=target.id,
            hosts_checked=0,
            skipped_reason="no_shodan_key",
        )

    subdomains = (
        await session.execute(
            select(Subdomain).where(Subdomain.target_id == target.id)
        )
    ).scalars().all()

    if not subdomains:
        return DiscoveryResult(target_id=target.id, hosts_checked=0)

    resolutions = await asyncio.gather(*(_resolve_a(resolver, s.fqdn) for s in subdomains))
    fqdn_to_ips = dict(zip(subdomains, resolutions, strict=True))

    # Deduplicate IPs across subdomains - free-tier Shodan rate limit
    # is harsh (1 rps) and a single IP often backs many subdomains.
    unique_ips: set[str] = {ip for ips in resolutions for ip in ips}

    shodan_results: dict[str, dict[str, Any]] = {}
    for ip in unique_ips:
        shodan_results[ip] = await clients.shodan.check_ip(ip)

    now = datetime.now(UTC)
    services_new = 0
    services_updated = 0
    cves_seen: set[str] = set()

    for subdomain, ips in fqdn_to_ips.items():
        for ip in ips:
            data = shodan_results.get(ip, {})
            if "error" in data:
                # Skipped: key missing (caught above) or IP unknown to Shodan.
                # Latter is extremely common - most IPs aren't scanned.
                continue

            ports: list[int] = list(data.get("open_ports") or [])
            vulns: list[str] = list(data.get("vulns") or [])
            cves_seen.update(vulns)

            if not ports:
                continue

            existing_stmt = select(Service).where(
                Service.subdomain_id == subdomain.id,
                Service.ip == ip,
                Service.port.in_(ports),
            )
            existing = {
                (row.ip, row.port): row
                for row in (await session.execute(existing_stmt)).scalars()
            }

            for port in ports:
                row = existing.get((ip, port))
                if row is None:
                    session.add(
                        Service(
                            subdomain_id=subdomain.id,
                            ip=ip,
                            port=port,
                            banner=str(data.get("organization") or "")[:512],
                            cves=vulns,
                            first_seen=now,
                            last_seen=now,
                        )
                    )
                    services_new += 1
                else:
                    row.last_seen = now
                    # CVEs can expand over time - refresh the list so the
                    # UI reflects current Shodan knowledge, not the first scan.
                    row.cves = vulns
                    services_updated += 1

    # Emit a critical-severity finding for any CVE seen - actionable even
    # before the analyst opens the target workspace.
    for cve in sorted(cves_seen):
        session.add(
            Finding(
                target_id=target.id,
                severity="high",
                category="cve_exposure",
                description=f"{cve} observed on a host in scope (Shodan).",
            )
        )

    await session.flush()
    return DiscoveryResult(
        target_id=target.id,
        hosts_checked=len(unique_ips),
        services_new=services_new,
        services_updated=services_updated,
        cves_seen=sorted(cves_seen),
    )


def summarize(result: DiscoveryResult) -> dict[str, Any]:
    """Shape for Scan.summary - JSON-safe and UI-ready."""
    if result.skipped_reason:
        return {
            "skipped": True,
            "reason": result.skipped_reason,
            "note": "Set SHODAN_API_KEY in .env to enable service discovery.",
        }
    return {
        "hosts_checked": result.hosts_checked,
        "services_new": result.services_new,
        "services_updated": result.services_updated,
        "cves_seen": result.cves_seen,
    }
