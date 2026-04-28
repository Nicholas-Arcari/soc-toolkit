"""Pivot-engine orchestrator.

Given an indicator (type + value), fan out to the relevant sec-common
OSINT clients in parallel and return a normalized `{target, target_type,
summary, pivot}` payload. Each source runs independently - a failure in
one doesn't abort the others (``return_exceptions=True`` + coercion).

Supported types:
    - ``domain`` / ``hostname`` / ``fqdn`` → CT logs + pDNS + WHOIS +
      WHOIS history + SecurityTrails subdomains
    - ``ipv4`` / ``ipv6`` / ``ip`` → ASN + reverse DNS + Mnemonic pDNS +
      Shodan host lookup
    - URLs and file hashes: out of scope for OSINT pivot (handled by the
      existing IOC-extractor enrichment path)
"""
import asyncio
from dataclasses import dataclass
from typing import Any

from sec_common.integrations import (
    ASNClient,
    CrtShClient,
    MnemonicPdnsClient,
    ReverseDNSClient,
    SecurityTrailsClient,
    ShodanClient,
    WhoisClient,
)


@dataclass
class PivotClients:
    """Bundle of OSINT clients used by the pivot engine.

    Keeps the ``pivot`` signature readable and lets callers build the
    bundle once per-request from Settings. Every field is mandatory -
    clients in degraded mode (no API key) no-op internally, so there's
    no value in distinguishing "missing client" from "no-key client".
    """

    crtsh: CrtShClient
    securitytrails: SecurityTrailsClient
    mnemonic: MnemonicPdnsClient
    whois: WhoisClient
    asn: ASNClient
    reverse_dns: ReverseDNSClient
    shodan: ShodanClient


async def pivot(ioc_type: str, value: str, *, clients: PivotClients) -> dict[str, Any]:
    """Dispatch to type-specific pivot and return normalized envelope."""
    normalized_type = ioc_type.strip().lower()

    if normalized_type in {"domain", "hostname", "fqdn"}:
        return await _pivot_domain(value, clients)
    if normalized_type in {"ipv4", "ipv6", "ip"}:
        return await _pivot_ip(value, clients)

    return {
        "target": value,
        "target_type": ioc_type,
        "summary": {},
        "pivot": {},
        "error": f"Unsupported indicator type for OSINT pivot: {ioc_type}",
    }


async def _pivot_domain(domain: str, clients: PivotClients) -> dict[str, Any]:
    """Domain → certificates, pDNS, WHOIS, WHOIS history, subdomains."""
    results = await asyncio.gather(
        clients.crtsh.search(domain),
        clients.securitytrails.dns_history(domain, "a"),
        clients.mnemonic.search(domain),
        clients.whois.lookup(domain),
        clients.securitytrails.whois_history(domain),
        clients.securitytrails.subdomains(domain),
        return_exceptions=True,
    )
    certs, pdns_st, pdns_mnem, whois_rec, whois_hist, subs = results

    passive_dns = _ensure_list(pdns_st) + _ensure_list(pdns_mnem)
    pivot_data = {
        "certificates": _ensure_list(certs),
        "passive_dns": passive_dns,
        "whois": _ensure_dict(whois_rec),
        "whois_history": _ensure_list(whois_hist),
        "subdomains": _ensure_list(subs),
    }

    return {
        "target": domain,
        "target_type": "domain",
        "summary": {
            "total_certificates": len(pivot_data["certificates"]),
            "total_passive_dns": len(pivot_data["passive_dns"]),
            "total_subdomains": len(pivot_data["subdomains"]),
            "has_whois": bool(pivot_data["whois"]),
            "whois_history_entries": len(pivot_data["whois_history"]),
        },
        "pivot": pivot_data,
    }


async def _pivot_ip(ip: str, clients: PivotClients) -> dict[str, Any]:
    """IP → ASN, PTR, pDNS reverse (via Mnemonic), Shodan host details."""
    results = await asyncio.gather(
        clients.asn.lookup(ip),
        clients.reverse_dns.lookup(ip),
        clients.mnemonic.search(ip),
        clients.shodan.check_ip(ip),
        return_exceptions=True,
    )
    asn_rec, rdns, pdns, shodan_rec = results

    asn_data = _ensure_dict(asn_rec)
    shodan_data = _ensure_dict(shodan_rec)
    pivot_data = {
        "asn": asn_data,
        "reverse_dns": _ensure_list(rdns),
        "passive_dns": _ensure_list(pdns),
        "shodan": shodan_data,
    }

    return {
        "target": ip,
        "target_type": "ip",
        "summary": {
            "asn": asn_data.get("asn", ""),
            "asn_description": asn_data.get("asn_description", ""),
            "total_reverse_dns": len(pivot_data["reverse_dns"]),
            "total_passive_dns": len(pivot_data["passive_dns"]),
            "has_shodan": bool(shodan_data) and "error" not in shodan_data,
        },
        "pivot": pivot_data,
    }


def _ensure_list(val: Any) -> list:
    """Coerce gather-result to list; swallow exceptions/None."""
    if isinstance(val, Exception) or val is None:
        return []
    return list(val) if isinstance(val, list) else []


def _ensure_dict(val: Any) -> dict:
    """Coerce gather-result to dict; swallow exceptions/None."""
    if isinstance(val, Exception) or val is None:
        return {}
    return dict(val) if isinstance(val, dict) else {}
