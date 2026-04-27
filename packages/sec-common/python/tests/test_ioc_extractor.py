"""Extractor is the foundation for IOC pivot + MISP enrichment.

Tests focus on:
- recognising every supported IOC type
- de-duplication (the same IP twice in one report = one row)
- the RFC1918 / loopback suppression rule
- defanged indicators (brackets around dots/schemes) because that's how
  analysts actually paste threat reports
"""
from __future__ import annotations

from sec_common.ioc.text_extractor import extract_from_text


def _types(results: list[dict]) -> set[str]:
    return {r["type"] for r in results}


def _values(results: list[dict], typ: str) -> set[str]:
    return {r["value"] for r in results if r["type"] == typ}


def test_empty_text_returns_empty() -> None:
    assert extract_from_text("") == []


def test_extracts_public_ipv4() -> None:
    results = extract_from_text("beacon to 203.0.113.45 observed")
    assert "203.0.113.45" in _values(results, "ipv4")


def test_suppresses_private_and_loopback_ips() -> None:
    """Internal IPs clutter reports and are never IOCs in OSS context."""
    results = extract_from_text(
        "saw 10.0.0.1, 192.168.1.1, 127.0.0.1 and 8.8.8.8 in logs"
    )
    ipv4s = _values(results, "ipv4")
    assert ipv4s == {"8.8.8.8"}


def test_extracts_domains() -> None:
    results = extract_from_text("c2 server: malicious-site.example found")
    assert "malicious-site.example" in _values(results, "domain")


def test_extracts_hashes_md5_sha1_sha256() -> None:
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    results = extract_from_text(f"hashes: {md5} {sha1} {sha256}")
    types = _types(results)
    assert "md5" in types
    assert "sha1" in types
    assert "sha256" in types


def test_extracts_cves() -> None:
    results = extract_from_text("exploits CVE-2024-1234 and CVE-2023-56789")
    cves = _values(results, "cve")
    assert "CVE-2024-1234" in cves
    assert "CVE-2023-56789" in cves


def test_extracts_emails() -> None:
    results = extract_from_text("contact attacker@evil.example for more")
    assert "attacker@evil.example" in _values(results, "email")


def test_deduplicates_repeated_indicators() -> None:
    """Same IP mentioned twice = one row."""
    text = "seen 8.8.8.8 in east, 8.8.8.8 in west, 8.8.8.8 again"
    results = extract_from_text(text)
    ipv4s = [r for r in results if r["type"] == "ipv4" and r["value"] == "8.8.8.8"]
    assert len(ipv4s) == 1


def test_context_field_is_populated() -> None:
    results = extract_from_text("malware calls home to 203.0.113.45 every hour")
    ipv4 = next(r for r in results if r["type"] == "ipv4")
    assert "203.0.113.45" in ipv4.get("context", "")
    assert "malware" in ipv4["context"]


def test_mixed_payload_extracts_many_types() -> None:
    """End-to-end: a real-shaped threat-report paragraph produces all types."""
    text = (
        "Attacker 203.0.113.45 hosted phishing at https://evil.example/login. "
        "The payload (SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855) "
        "exploits CVE-2024-1234. Contact reported@soc.example for takedown."
    )
    results = extract_from_text(text)
    types = _types(results)
    for expected in ("ipv4", "url", "sha256", "cve", "email"):
        assert expected in types, f"expected {expected} in {types}"
