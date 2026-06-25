"""Pivot-engine orchestrator.

Given an indicator (type + value), fan out to the relevant sec-common
OSINT clients in parallel and return a normalized `{target, target_type,
summary, pivot}` payload. Each source runs independently - a failure in
one doesn't abort the others (``return_exceptions=True`` + coercion).

Coverage + precision notes:
    - Subdomains are mined from crt.sh certificate SANs (free, no key) and
      merged with SecurityTrails, then normalized (lowercased, wildcard-
      stripped, deduped, kept within the queried domain).
    - Passive DNS is concatenated across Mnemonic, SecurityTrails and OTX
      (free key, optional) and deduped by (value, record_type).

Supported types:
    - ``domain`` / ``hostname`` / ``fqdn`` → CT logs + pDNS + WHOIS +
      WHOIS history + subdomains
    - ``ipv4`` / ``ipv6`` / ``ip`` → ASN + reverse DNS + pDNS + Shodan
    - URLs and file hashes: out of scope (handled by IOC-extractor enrichment)
"""
import asyncio
from dataclasses import dataclass
from typing import Any

from sec_common.integrations import (
    AlienVaultOTXClient,
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
    bundle once per-request from Settings. Clients in degraded mode (no API
    key) no-op internally. ``otx`` is optional/defaulted so existing callers
    keep working; when present it adds free passive-DNS coverage.
    """

    crtsh: CrtShClient
    securitytrails: SecurityTrailsClient
    mnemonic: MnemonicPdnsClient
    whois: WhoisClient
    asn: ASNClient
    reverse_dns: ReverseDNSClient
    shodan: ShodanClient
    otx: AlienVaultOTXClient | None = None


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
        _otx_pdns(clients.otx, domain, "domain"),
        return_exceptions=True,
    )
    certs, pdns_st, pdns_mnem, whois_rec, whois_hist, subs, pdns_otx = results

    cert_rows = _ensure_list(certs)
    passive_dns = _dedupe_pdns(
        _ensure_list(pdns_st) + _ensure_list(pdns_mnem) + _ensure_list(pdns_otx)
    )
    # Mine subdomains from cert SANs + SecurityTrails, then normalize.
    cert_subdomains = [
        row.get("subdomain", "") for row in cert_rows if isinstance(row, dict)
    ]
    subdomains = _normalize_subdomains(domain, cert_subdomains, _ensure_list(subs))

    pivot_data = {
        "certificates": _dedupe_certs(cert_rows),
        "passive_dns": passive_dns,
        "whois": _ensure_dict(whois_rec),
        "whois_history": _ensure_list(whois_hist),
        "subdomains": subdomains,
    }

    return {
        "target": domain,
        "target_type": "domain",
        "summary": {
            "total_certificates": len(pivot_data["certificates"]),
            "total_passive_dns": len(passive_dns),
            "total_subdomains": len(subdomains),
            "has_whois": bool(pivot_data["whois"]),
            "whois_history_entries": len(pivot_data["whois_history"]),
        },
        "pivot": pivot_data,
    }


async def _pivot_ip(ip: str, clients: PivotClients) -> dict[str, Any]:
    """IP → ASN, PTR, passive DNS (Mnemonic + OTX), Shodan host details."""
    results = await asyncio.gather(
        clients.asn.lookup(ip),
        clients.reverse_dns.lookup(ip),
        clients.mnemonic.search(ip),
        clients.shodan.check_ip(ip),
        _otx_pdns(clients.otx, ip, "ip"),
        return_exceptions=True,
    )
    asn_rec, rdns, pdns_mnem, shodan_rec, pdns_otx = results

    asn_data = _ensure_dict(asn_rec)
    shodan_data = _ensure_dict(shodan_rec)
    passive_dns = _dedupe_pdns(_ensure_list(pdns_mnem) + _ensure_list(pdns_otx))
    pivot_data = {
        "asn": asn_data,
        "reverse_dns": _ensure_list(rdns),
        "passive_dns": passive_dns,
        "shodan": shodan_data,
    }

    return {
        "target": ip,
        "target_type": "ip",
        "summary": {
            "asn": asn_data.get("asn", ""),
            "asn_description": asn_data.get("asn_description", ""),
            "total_reverse_dns": len(pivot_data["reverse_dns"]),
            "total_passive_dns": len(passive_dns),
            "has_shodan": bool(shodan_data) and "error" not in shodan_data,
        },
        "pivot": pivot_data,
    }


async def _otx_pdns(
    otx: AlienVaultOTXClient | None, indicator: str, kind: str
) -> list[dict]:
    """OTX passive DNS, or [] when OTX isn't configured (keeps gather clean)."""
    if otx is None:
        return []
    return await otx.passive_dns(indicator, kind)


def _normalize_subdomains(domain: str, *sources: list) -> list[str]:
    """Lowercased, wildcard-stripped, deduped subdomains within ``domain``."""
    apex = domain.strip().lower().lstrip(".")
    suffix = "." + apex
    out: set[str] = set()
    for source in sources:
        for raw in source:
            name = str(raw).strip().lower().lstrip("*").lstrip(".")
            if name.endswith(suffix):
                out.add(name)
    return sorted(out)


def _dedupe_pdns(rows: list) -> list[dict]:
    """Dedupe passive-DNS rows by (value, record_type); newest last_seen first."""
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        value = str(row.get("value", "")).strip().lower()
        rtype = str(row.get("record_type", "")).upper()
        if not value or (value, rtype) in seen:
            continue
        seen.add((value, rtype))
        out.append(row)
    out.sort(key=lambda row: str(row.get("last_seen", "")), reverse=True)
    return out


def _dedupe_certs(rows: list) -> list[dict]:
    """Collapse crt.sh rows (one per name) to unique certificates."""
    seen: set[Any] = set()
    out: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        cert_id = row.get("cert_id")
        key = (
            cert_id
            if cert_id is not None
            else (row.get("subdomain"), row.get("not_after"))
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


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
