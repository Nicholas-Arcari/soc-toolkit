import re


def extract_from_text(text: str) -> list[dict]:
    """Extract IOCs (Indicators of Compromise) from plain text.

    Extraction order matters: URLs before domains to avoid extracting the
    domain portion of a URL as a separate IOC. Hashes are extracted last
    because their regex is greedy and could match substrings of longer hex
    values. Each IOC includes surrounding context to help analysts assess
    relevance without reading the entire source document.
    """
    iocs = []

    iocs.extend(_extract_ipv4(text))
    iocs.extend(_extract_domains(text))
    iocs.extend(_extract_urls(text))
    iocs.extend(_extract_emails(text))
    iocs.extend(_extract_hashes(text))
    iocs.extend(_extract_cves(text))

    # Deduplicate
    seen = set()
    unique = []
    for ioc in iocs:
        key = (ioc["type"], ioc["value"])
        if key not in seen:
            seen.add(key)
            unique.append(ioc)

    return unique


def _extract_ipv4(text: str) -> list[dict]:
    """Extract IPv4 addresses."""
    # Match IPs but exclude common false positives (version numbers, etc.)
    pattern = re.compile(
        r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
    )

    ips = []
    for match in pattern.finditer(text):
        ip = match.group(1)
        octets = ip.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            # Skip private, loopback, and link-local
            if not _is_internal_ip(ip):
                context = _get_context(text, match.start(), match.end())
                ips.append({"type": "ipv4", "value": ip, "context": context})

    return ips


def _extract_domains(text: str) -> list[dict]:
    """Extract domain names."""
    pattern = re.compile(
        r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?\."
        r"(?:[a-zA-Z]{2,})(?:\.[a-zA-Z]{2,})?)\b"
    )

    # Common false positive domains to skip
    skip_domains = {
        "example.com", "example.org", "example.net",
        "localhost.localdomain", "schema.org", "w3.org",
        "github.com", "googleapis.com", "microsoft.com",
    }

    domains = []
    for match in pattern.finditer(text):
        domain = match.group(1).lower()
        if domain not in skip_domains and len(domain) > 4:
            context = _get_context(text, match.start(), match.end())
            domains.append({"type": "domain", "value": domain, "context": context})

    return domains


def _extract_urls(text: str) -> list[dict]:
    """Extract URLs."""
    pattern = re.compile(
        r"(https?://[^\s\"'<>)\]]+)",
        re.IGNORECASE,
    )

    urls = []
    for match in pattern.finditer(text):
        url = match.group(1).rstrip(".,;:")
        context = _get_context(text, match.start(), match.end())
        urls.append({"type": "url", "value": url, "context": context})

    return urls


def _extract_emails(text: str) -> list[dict]:
    """Extract email addresses."""
    pattern = re.compile(
        r"\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b"
    )

    emails = []
    for match in pattern.finditer(text):
        email_addr = match.group(1).lower()
        if not email_addr.endswith(("@example.com", "@example.org")):
            context = _get_context(text, match.start(), match.end())
            emails.append({"type": "email", "value": email_addr, "context": context})

    return emails


def _extract_hashes(text: str) -> list[dict]:
    """Extract file hashes (MD5, SHA1, SHA256)."""
    hashes = []

    # SHA256
    for match in re.finditer(r"\b([a-fA-F0-9]{64})\b", text):
        context = _get_context(text, match.start(), match.end())
        hashes.append({"type": "sha256", "value": match.group(1).lower(), "context": context})

    # SHA1
    for match in re.finditer(r"\b([a-fA-F0-9]{40})\b", text):
        value = match.group(1).lower()
        # Skip if it's part of a SHA256
        if not any(h["value"].startswith(value) for h in hashes):
            context = _get_context(text, match.start(), match.end())
            hashes.append({"type": "sha1", "value": value, "context": context})

    # MD5
    for match in re.finditer(r"\b([a-fA-F0-9]{32})\b", text):
        value = match.group(1).lower()
        if not any(h["value"].startswith(value) for h in hashes):
            context = _get_context(text, match.start(), match.end())
            hashes.append({"type": "md5", "value": value, "context": context})

    return hashes


def _extract_cves(text: str) -> list[dict]:
    """Extract CVE identifiers."""
    pattern = re.compile(r"\b(CVE-\d{4}-\d{4,})\b", re.IGNORECASE)
    cves = []
    for match in pattern.finditer(text):
        context = _get_context(text, match.start(), match.end())
        cves.append({"type": "cve", "value": match.group(1).upper(), "context": context})
    return cves


def _is_internal_ip(ip: str) -> bool:
    """Check if IP is internal/private (RFC 1918, loopback, link-local).

    Internal IPs are filtered out because they appear frequently in logs
    and reports but are not actionable IOCs - they can't be blocked at
    the perimeter and are different for every organization.
    """
    octets = [int(o) for o in ip.split(".")]
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 127:
        return True
    if octets[0] == 0:
        return True
    return False


def _get_context(text: str, start: int, end: int, window: int = 50) -> str:
    """Get surrounding text context for an IOC."""
    ctx_start = max(0, start - window)
    ctx_end = min(len(text), end + window)
    context = text[ctx_start:ctx_end].strip()
    return re.sub(r"\s+", " ", context)
