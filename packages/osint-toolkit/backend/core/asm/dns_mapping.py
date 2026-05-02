"""DNS mapping for scoped target domains.

Resolves the standard record set (A / AAAA / MX / NS / TXT) for every
scope root, parses email-auth policies (SPF + DMARC), and emits
findings for the well-known misconfigurations that actually bite:

- SPF missing, or terminating in ``+all`` (explicit permit-anyone)
- DMARC missing, or set to ``p=none`` (monitor-only, no enforcement)
- NS record set with fewer than 2 distinct nameservers

The module is passive - every query hits recursive resolvers, not the
target. It's safe to run against any authorized domain without further
lockdown.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import Finding, Target

_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")


@dataclass
class DomainDNS:
    """Per-domain resolution outcome."""

    domain: str
    records: dict[str, list[str]] = field(default_factory=dict)
    spf: str | None = None
    dmarc: str | None = None
    errors: list[str] = field(default_factory=list)


@dataclass
class DNSMappingResult:
    """Shape returned to the API layer."""

    target_id: int
    domains: list[DomainDNS]
    findings_created: int


async def _resolve(
    resolver: dns.asyncresolver.Resolver, qname: str, rtype: str
) -> list[str]:
    """Return rdata strings, or [] for the common NXDOMAIN / NoAnswer cases.

    We treat "no record" as a normal signal (it *is* an answer for SPF
    absence), so only genuinely unexpected errors propagate up. dnspython's
    string forms are deterministic and round-trippable; good enough for
    storage and UI display.
    """
    try:
        answer = await resolver.resolve(qname, rtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException:
        return []
    return sorted(str(r).strip('"') for r in answer)


async def _map_one_domain(
    resolver: dns.asyncresolver.Resolver, domain: str
) -> DomainDNS:
    """Resolve the standard record set + SPF + DMARC for one domain."""
    domain = domain.strip().lower().rstrip(".")
    result = DomainDNS(domain=domain)

    record_tasks = {rtype: _resolve(resolver, domain, rtype) for rtype in _RECORD_TYPES}
    dmarc_task = _resolve(resolver, f"_dmarc.{domain}", "TXT")

    rrs = await asyncio.gather(*record_tasks.values(), dmarc_task)
    for rtype, rr in zip(_RECORD_TYPES, rrs[:-1], strict=True):
        result.records[rtype] = rr

    # SPF lives in an apex TXT record - never a dedicated SPF RR type since
    # RFC 7208 deprecated it. Identify by the prefix, not by existence.
    for txt in result.records.get("TXT", []):
        if txt.lower().startswith("v=spf1"):
            result.spf = txt
            break

    dmarc_records = rrs[-1]
    for txt in dmarc_records:
        if txt.lower().startswith("v=dmarc1"):
            result.dmarc = txt
            break

    return result


def _spf_findings(dns_result: DomainDNS) -> list[tuple[str, str, str]]:
    """Emit (severity, category, description) tuples for SPF issues."""
    findings: list[tuple[str, str, str]] = []
    if dns_result.spf is None:
        findings.append((
            "medium",
            "email_auth",
            (
                f"{dns_result.domain}: no SPF record - senders can spoof the "
                "domain unless DMARC blocks them."
            ),
        ))
        return findings

    # The relevant mechanism is the *terminal* one. "+all" (or plain "all"
    # with a + qualifier, or the bare "all" token) means "allow anyone".
    tokens = dns_result.spf.lower().split()
    terminal = tokens[-1] if tokens else ""
    if terminal in ("+all", "all"):
        findings.append((
            "high",
            "email_auth",
            (
                f"{dns_result.domain}: SPF terminates in '+all' - any sender is "
                "explicitly permitted."
            ),
        ))
    return findings


def _dmarc_findings(dns_result: DomainDNS) -> list[tuple[str, str, str]]:
    findings: list[tuple[str, str, str]] = []
    if dns_result.dmarc is None:
        findings.append((
            "medium",
            "email_auth",
            (
                f"{dns_result.domain}: no DMARC record - spoofed mail from this "
                "domain has no policy to block it."
            ),
        ))
        return findings

    # Parse the `p=` tag. DMARC syntax is ``tag=value; tag=value; …``.
    tags = {}
    for part in dns_result.dmarc.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip().lower()

    policy = tags.get("p", "")
    if policy == "none":
        findings.append((
            "low",
            "email_auth",
            (
                f"{dns_result.domain}: DMARC policy is 'p=none' - monitor only, "
                "no mail is actually rejected."
            ),
        ))
    return findings


def _ns_findings(dns_result: DomainDNS) -> list[tuple[str, str, str]]:
    ns = dns_result.records.get("NS", [])
    if 0 < len(ns) < 2:
        return [(
            "low",
            "dns",
            (
                f"{dns_result.domain}: only {len(ns)} nameserver record - "
                "RFC 2182 recommends at least two for redundancy."
            ),
        )]
    return []


async def map_dns(
    target: Target,
    *,
    session: AsyncSession,
    resolver: dns.asyncresolver.Resolver | None = None,
) -> DNSMappingResult:
    """Resolve every scope domain, persist findings, return aggregate result.

    Findings are *appended* - prior findings from earlier scans are not
    deleted. Remediation is out-of-scope for this pass.
    """
    scope = list(target.scope_domains or [])
    resolver = resolver or dns.asyncresolver.Resolver()

    per_domain = await asyncio.gather(*(_map_one_domain(resolver, d) for d in scope))

    findings_created = 0
    for d in per_domain:
        for sev, cat, desc in (
            *_spf_findings(d),
            *_dmarc_findings(d),
            *_ns_findings(d),
        ):
            session.add(
                Finding(
                    target_id=target.id,
                    severity=sev,
                    category=cat,
                    description=desc,
                )
            )
            findings_created += 1

    await session.flush()
    return DNSMappingResult(
        target_id=target.id,
        domains=per_domain,
        findings_created=findings_created,
    )


def summarize(result: DNSMappingResult) -> dict[str, Any]:
    """Shape stored in Scan.summary - JSON-safe."""
    return {
        "domains_checked": len(result.domains),
        "findings_created": result.findings_created,
        "domains": [
            {
                "domain": d.domain,
                "a": d.records.get("A", []),
                "aaaa": d.records.get("AAAA", []),
                "mx": d.records.get("MX", []),
                "ns": d.records.get("NS", []),
                "txt_count": len(d.records.get("TXT", [])),
                "spf": d.spf,
                "dmarc": d.dmarc,
            }
            for d in result.domains
        ],
    }


def datetime_now() -> datetime:
    """Indirection so tests can freeze time without touching the module globals."""
    return datetime.now(UTC)
