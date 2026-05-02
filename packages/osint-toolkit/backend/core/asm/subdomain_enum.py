"""Passive subdomain enumeration.

Passive-by-default so a public open-source install is safe to point at
any authorized target: we only read data other people already published.
Sources:

1. **Certificate Transparency** (crt.sh) - no key, comprehensive, the
   baseline everyone else builds on.
2. **SecurityTrails subdomains** - adds coverage when a key is present;
   silently skipped otherwise (free tier is very limited).

Active scanning (Amass / Subfinder subprocess, zone walks) lives behind
``settings.enable_active_scanning`` and is deliberately not wired here.

Results are scope-filtered - any discovered FQDN that doesn't end in
one of the target's `scope_domains` is dropped. Prevents passive sources
from leaking neighbor domains into a scan for "example.com".
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sec_common.integrations import CrtShClient, SecurityTrailsClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import Subdomain, Target

logger = logging.getLogger(__name__)


@dataclass
class EnumClients:
    """Bundle injected by the route layer so core stays framework-free."""

    crtsh: CrtShClient
    securitytrails: SecurityTrailsClient


@dataclass
class EnumResult:
    """Shape returned to the API layer."""

    target_id: int
    discovered: list[str]
    new_count: int
    updated_count: int
    sources: dict[str, int]


def _in_scope(fqdn: str, scope_domains: list[str]) -> bool:
    """True when `fqdn` is a subdomain of one of the scope roots.

    Empty scope is treated as "no restriction" for development
    convenience - production targets should always define a scope.
    """
    if not scope_domains:
        return True
    fqdn = fqdn.strip().lower().rstrip(".")
    for root in scope_domains:
        root = root.strip().lower().rstrip(".")
        if fqdn == root or fqdn.endswith(f".{root}"):
            return True
    return False


async def _collect_from_crtsh(
    client: CrtShClient, scope_domains: list[str]
) -> dict[str, str]:
    """Discovered FQDN → source label, via CT logs for each scope root."""
    discovered: dict[str, str] = {}
    for root in scope_domains or []:
        try:
            entries = await client.search(root)
        except Exception:
            # One source failing (CT log timeout, DNS flake) must not wedge
            # the whole scan - log and skip so the operator can see why a
            # source returned zero rather than mistaking it for coverage.
            logger.warning("crtsh.search_failed", extra={"root": root}, exc_info=True)
            continue
        for entry in entries:
            fqdn = str(entry.get("subdomain", "")).strip().lower().rstrip(".")
            # Skip wildcard entries - "*.example.com" is not itself a host
            if not fqdn or fqdn.startswith("*"):
                continue
            if _in_scope(fqdn, scope_domains):
                discovered.setdefault(fqdn, "crtsh")
    return discovered


async def _collect_from_securitytrails(
    client: SecurityTrailsClient, scope_domains: list[str]
) -> dict[str, str]:
    """SecurityTrails subdomains - skipped entirely when no API key."""
    if not client.api_key:
        return {}
    discovered: dict[str, str] = {}
    for root in scope_domains or []:
        try:
            subs = await client.subdomains(root)
        except Exception:
            logger.warning(
                "securitytrails.subdomains_failed",
                extra={"root": root},
                exc_info=True,
            )
            continue
        for fqdn in subs:
            fqdn = fqdn.strip().lower().rstrip(".")
            if fqdn and _in_scope(fqdn, scope_domains):
                discovered.setdefault(fqdn, "securitytrails")
    return discovered


async def enumerate_subdomains(
    target: Target,
    *,
    clients: EnumClients,
    session: AsyncSession,
) -> EnumResult:
    """Run passive enum against `target` and upsert the results.

    Returns counts so the caller can surface a meaningful summary in the
    Scan row (what was discovered, how much was new).
    """
    scope = list(target.scope_domains or [])

    crtsh_task = _collect_from_crtsh(clients.crtsh, scope)
    st_task = _collect_from_securitytrails(clients.securitytrails, scope)
    crtsh_found, st_found = await asyncio.gather(crtsh_task, st_task)

    # Prefer crtsh as primary source label - SecurityTrails is supplementary
    merged: dict[str, str] = dict(crtsh_found)
    for fqdn, source in st_found.items():
        merged.setdefault(fqdn, source)

    now = datetime.now(UTC)
    new_count = 0
    updated_count = 0

    if merged:
        existing_stmt = select(Subdomain).where(
            Subdomain.target_id == target.id,
            Subdomain.fqdn.in_(list(merged.keys())),
        )
        existing = {s.fqdn: s for s in (await session.execute(existing_stmt)).scalars()}

        for fqdn, source in merged.items():
            row = existing.get(fqdn)
            if row is None:
                session.add(
                    Subdomain(
                        target_id=target.id,
                        fqdn=fqdn,
                        source=source,
                        first_seen=now,
                        last_seen=now,
                    )
                )
                new_count += 1
            else:
                row.last_seen = now
                updated_count += 1

        await session.flush()

    source_breakdown = {
        "crtsh": len(crtsh_found),
        "securitytrails": len(st_found),
    }
    return EnumResult(
        target_id=target.id,
        discovered=sorted(merged.keys()),
        new_count=new_count,
        updated_count=updated_count,
        sources=source_breakdown,
    )


def summarize(result: EnumResult) -> dict[str, Any]:
    """Shape stored in `Scan.summary` - JSON-safe by construction."""
    return {
        "discovered_total": len(result.discovered),
        "new": result.new_count,
        "updated": result.updated_count,
        "sources": result.sources,
    }
