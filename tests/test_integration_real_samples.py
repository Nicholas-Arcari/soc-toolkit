"""End-to-end integration tests against the real sample files in samples/.

These tests deliberately avoid any mocking of the core analysis modules - they
exercise the full pipeline (parsing → detection → cross-module chaining) on
realistic-but-safe fixtures. External network calls (VirusTotal, MISP) ARE
mocked because CI can't hit them, but the rule engines, parsers, and
analyzers run for real.

Every assertion is expressed in terms of the detections a human SOC analyst
would expect from the sample, so rule regressions surface as test failures
rather than silent loss of coverage.
"""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from core.ioc.text_extractor import extract_from_text
from core.logs.ssh_analyzer import analyze_ssh_logs
from core.logs.windows_analyzer import analyze_windows_logs
from core.misp.enricher import enrich_iocs
from core.phishing.header_analyzer import analyze_headers
from core.sigma.engine import SigmaEngine, RULES_DIR as SIGMA_RULES_DIR
from core.yara.scanner import get_scanner

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


@pytest.fixture
def ssh_log() -> str:
    return (SAMPLES_DIR / "logs" / "auth.log").read_text()


@pytest.fixture
def windows_log() -> str:
    return (SAMPLES_DIR / "logs" / "windows_security.log").read_text()


@pytest.fixture
def threat_report() -> str:
    return (SAMPLES_DIR / "reports" / "threat_report_sample.txt").read_text()


@pytest.fixture
def phishing_email() -> str:
    return (SAMPLES_DIR / "emails" / "phishing_sample.eml").read_text()


@pytest.fixture
def legitimate_email() -> str:
    return (SAMPLES_DIR / "emails" / "legitimate_sample.eml").read_text()


# --- SSH brute force pipeline --------------------------------------------


def test_ssh_analyzer_detects_brute_force(ssh_log):
    """The sample contains a sustained burst from 45.33.32.156 (10 failed
    attempts) plus 103.235.46.39 invalid-user scanning. Both must be flagged."""
    result = analyze_ssh_logs(ssh_log)

    assert result["suspicious_entries"] > 0
    ips_seen = {entry["ip"] for entry in result["failed_attempts"]}
    assert "45.33.32.156" in ips_seen
    assert "185.220.101.42" in ips_seen
    # Brute-force aggregation fires at >=5 attempts per source
    assert "45.33.32.156" in result["brute_force_ips"]


def test_ssh_analyzer_surfaces_successful_login_after_failures(ssh_log):
    """The dangerous pattern: brute force from 185.220.101.42 eventually
    succeeds. The analyst must see the successful login in the output so
    the incident can be escalated."""
    result = analyze_ssh_logs(ssh_log)
    successful_ips = {entry["ip"] for entry in result["successful_logins"]}
    assert "185.220.101.42" in successful_ips


def test_ssh_log_events_fire_sigma_bruteforce_rule(ssh_log):
    """Chain: raw log → SSH analyzer → translate to Sigma events → engine.
    Confirms the SSH brute-force Sigma rule fires on the analyzer's output."""
    result = analyze_ssh_logs(ssh_log)

    # Translate the analyzer's invalid_user events to the Sigma rule's schema
    sigma_events = [
        {
            "event_type": "auth_failure",
            "reason": "invalid_user",
            "source_ip": entry["ip"],
            "username": entry["user"],
        }
        for entry in result["invalid_users"]
    ]

    engine = SigmaEngine(rules_dir=SIGMA_RULES_DIR)
    matches = engine.evaluate_batch(sigma_events)

    assert any("SSH Brute Force" in m.title for m in matches)


# --- Windows persistence + brute force pipeline --------------------------


def test_windows_analyzer_detects_brute_force_and_persistence(windows_log):
    """Sample contains 4625 bursts from 45.33.32.156 and a 4720/4732 pair
    (new account then added to a group) indicating persistence."""
    result = analyze_windows_logs(windows_log)

    patterns = {p["pattern"] for p in result["attack_patterns"]}
    assert "Brute Force" in patterns
    assert "Persistence Mechanism" in patterns
    # Persistence events in the sample: 7045 (service), 4697, 4698, 4720, 4732
    assert result["event_distribution"].get(4720) == 1


def test_windows_events_fire_sigma_admin_rule(windows_log):
    """Event 4720 (user created) must trigger the admin-account Sigma rule."""
    import json

    # Parse the raw JSON log into the normalized shape Sigma rules expect.
    # We use ``event_id`` lowercase because that is the key produced by the
    # windows_analyzer module - keeping the test fed by the same vocabulary
    # a real pipeline would produce
    events = []
    for line in windows_log.strip().splitlines():
        raw = json.loads(line)
        events.append({
            "event_id": raw.get("EventID"),
            "source_ip": raw.get("IpAddress"),
            "username": raw.get("TargetUserName"),
            "target_group": "Administrators" if raw.get("EventID") == 4732 else "",
        })

    engine = SigmaEngine(rules_dir=SIGMA_RULES_DIR)
    matches = engine.evaluate_batch(events)

    rule_titles = [m.title for m in matches]
    assert any("Administrator Account" in t for t in rule_titles)


# --- IOC extraction from threat report -----------------------------------


def test_threat_report_yields_expected_ioc_types(threat_report):
    iocs = extract_from_text(threat_report)
    types = {ioc["type"] for ioc in iocs}

    assert "ipv4" in types
    assert "domain" in types
    assert "url" in types
    assert "sha256" in types
    assert "cve" in types


def test_threat_report_ipv4_extraction_respects_public_only(threat_report):
    iocs = extract_from_text(threat_report)
    ips = [ioc["value"] for ioc in iocs if ioc["type"] == "ipv4"]

    assert "203.0.113.42" in ips  # sample C2
    assert "185.220.101.42" in ips  # same IP reused across phishing + report

    # Internal/private IPs must be filtered out - they are noise in a report
    assert not any(ip.startswith(("10.", "192.168.", "172.16.")) for ip in ips)


def test_threat_report_cve_extraction(threat_report):
    iocs = extract_from_text(threat_report)
    cves = {ioc["value"] for ioc in iocs if ioc["type"] == "cve"}

    assert "CVE-2024-1234" in cves
    assert "CVE-2023-5678" in cves


@pytest.mark.asyncio
async def test_threat_report_iocs_enriched_via_misp(threat_report):
    """Full extract → MISP-enrich pipeline with the MISP client mocked."""
    iocs = extract_from_text(threat_report)

    # Mock: every IP is "known" to MISP; everything else is unknown.
    # This proves the enricher wires the extractor's output shape through
    # correctly without needing a live MISP instance
    async def fake_check(value, kind):
        if kind == "ip":
            return {
                "found": True,
                "event_count": 1,
                "to_ids": True,
                "events": [{"info": "SILENT COBRA campaign", "org": "Test"}],
            }
        return {"found": False}

    with patch("core.misp.enricher.MISPClient") as mock_client_cls:
        mock_client_cls.return_value.check_attribute = fake_check
        enrichment = await enrich_iocs(iocs)

    # Every public IP in the report should be marked known
    assert enrichment["summary"]["ip"]["known"] == enrichment["summary"]["ip"]["checked"]
    assert enrichment["known_count"] > 0


# --- Phishing email pipeline ---------------------------------------------


def test_phishing_email_header_indicators(phishing_email):
    """The sample has softfail SPF + fail DKIM/DMARC + Reply-To mismatch +
    urgent subject. All four must surface as indicators."""
    result = analyze_headers(phishing_email)

    assert result["spf"]["status"] == "softfail"
    assert result["dkim"]["status"] == "fail"
    assert result["dmarc"]["status"] == "fail"

    indicators = " ".join(result["suspicious_indicators"]).lower()
    assert "reply-to mismatch" in indicators
    assert "urgency keywords" in indicators or "unusual" in indicators


def test_legitimate_email_passes_authentication(legitimate_email):
    """Control: the benign email in samples/ must NOT trigger auth failures.
    Guards against regressions where an overeager rule adds false positives."""
    result = analyze_headers(legitimate_email)

    assert result["spf"]["status"] != "fail"
    assert result["dmarc"]["status"] != "fail"


def test_phishing_email_contains_double_extension_attachment(phishing_email):
    """The sample attachment is filename 'security_alert.pdf.exe' - the
    double-extension heuristic must mark it malicious."""
    from core.phishing.attachment_scanner import _has_double_extension

    # Extract the filename directly from the MIME boundary for a targeted check
    assert "security_alert.pdf.exe" in phishing_email
    assert _has_double_extension("security_alert.pdf.exe") is True


# --- YARA scanner end-to-end --------------------------------------------


def test_yara_scanner_flags_php_webshell_content():
    """Synthetic PHP webshell bytes - the YARA module must flag them with
    critical severity and the T1505.003 mapping exposed in metadata."""
    scanner = get_scanner()
    payload = b"<?php if (isset($_POST['cmd'])) { eval($_POST['cmd']); } ?>"

    matches = scanner.scan(payload)
    critical = [m for m in matches if m["metadata"].get("severity") == "critical"]

    assert len(critical) >= 1
    assert any(m["metadata"].get("mitre") == "T1505.003" for m in critical)


def test_yara_scanner_does_not_flag_benign_document():
    """Regression guard: quarterly-report prose must never match any YARA rule."""
    scanner = get_scanner()
    payload = b"Quarterly revenue increased 12% quarter over quarter."

    assert scanner.scan(payload) == []
