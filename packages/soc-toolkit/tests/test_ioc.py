from core.ioc.text_extractor import extract_from_text


SAMPLE_THREAT_REPORT = """
Threat Intelligence Report - APT-42 Campaign

The threat actor was observed communicating with C2 server at 203.0.113.42
and secondary infrastructure at 198.51.100.7. DNS queries were directed
to malicious-c2.evil.xyz and backup-c2.badactor.top.

The malware dropper (SHA256: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2)
was delivered via phishing email from attacker@phishing-domain.com with a link
to https://download.malware-host.tk/payload.exe.

The campaign exploits CVE-2024-1234 and CVE-2023-5678.
Contact soc-team@company.com for questions.
"""


def test_extract_ipv4():
    iocs = extract_from_text(SAMPLE_THREAT_REPORT)
    ips = [i for i in iocs if i["type"] == "ipv4"]

    ip_values = [i["value"] for i in ips]
    assert "203.0.113.42" in ip_values
    assert "198.51.100.7" in ip_values


def test_extract_domains():
    iocs = extract_from_text(SAMPLE_THREAT_REPORT)
    domains = [i for i in iocs if i["type"] == "domain"]

    domain_values = [i["value"] for i in domains]
    assert "malicious-c2.evil.xyz" in domain_values
    assert "backup-c2.badactor.top" in domain_values


def test_extract_urls():
    iocs = extract_from_text(SAMPLE_THREAT_REPORT)
    urls = [i for i in iocs if i["type"] == "url"]

    url_values = [i["value"] for i in urls]
    assert any("malware-host.tk" in u for u in url_values)


def test_extract_hashes():
    iocs = extract_from_text(SAMPLE_THREAT_REPORT)
    hashes = [i for i in iocs if i["type"] == "sha256"]

    assert len(hashes) == 1
    assert hashes[0]["value"] == "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"


def test_extract_emails():
    iocs = extract_from_text(SAMPLE_THREAT_REPORT)
    emails = [i for i in iocs if i["type"] == "email"]

    email_values = [i["value"] for i in emails]
    assert "attacker@phishing-domain.com" in email_values


def test_extract_cves():
    iocs = extract_from_text(SAMPLE_THREAT_REPORT)
    cves = [i for i in iocs if i["type"] == "cve"]

    cve_values = [i["value"] for i in cves]
    assert "CVE-2024-1234" in cve_values
    assert "CVE-2023-5678" in cve_values


def test_no_duplicates():
    text = "IP 203.0.113.42 was seen again at 203.0.113.42 and 203.0.113.42"
    iocs = extract_from_text(text)
    ips = [i for i in iocs if i["type"] == "ipv4" and i["value"] == "203.0.113.42"]
    assert len(ips) == 1


def test_skip_internal_ips():
    text = "Internal 192.168.1.1 and 10.0.0.1 and external 203.0.113.42"
    iocs = extract_from_text(text)
    ip_values = [i["value"] for i in iocs if i["type"] == "ipv4"]

    assert "192.168.1.1" not in ip_values
    assert "10.0.0.1" not in ip_values
    assert "203.0.113.42" in ip_values


def test_context_captured():
    iocs = extract_from_text(SAMPLE_THREAT_REPORT)
    ip_ioc = next(i for i in iocs if i["value"] == "203.0.113.42")
    assert ip_ioc["context"] is not None
    assert len(ip_ioc["context"]) > 0
