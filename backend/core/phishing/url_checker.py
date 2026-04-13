import re
from urllib.parse import urlparse

from integrations.urlscan import URLScanClient
from integrations.virustotal import VirusTotalClient


async def check_urls(raw_input: str, single: bool = False) -> list[dict]:
    """Extract and check URLs against threat intelligence."""
    if single:
        urls = [raw_input]
    else:
        urls = _extract_urls(raw_input)

    if not urls:
        return []

    results = []
    vt = VirusTotalClient()
    urlscan = URLScanClient()

    # Cap at 20 URLs to stay within VirusTotal free tier (4 req/min).
    # A real phishing email rarely has more than 5-10 unique URLs anyway
    for url in urls[:20]:
        result = {
            "url": url,
            "domain": urlparse(url).netloc,
            "suspicious_patterns": _check_suspicious_patterns(url),
            "virustotal": None,
            "urlscan": None,
        }

        try:
            result["virustotal"] = await vt.check_url(url)
        except Exception:
            result["virustotal"] = {"error": "API unavailable"}

        try:
            result["urlscan"] = await urlscan.check_url(url)
        except Exception:
            result["urlscan"] = {"error": "API unavailable"}

        result["malicious"] = _is_malicious(result)
        results.append(result)

    return results


def _extract_urls(text: str) -> list[str]:
    """Extract URLs from text content."""
    url_pattern = re.compile(
        r"https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
        r"(?:/[^\s\"'<>)}\]]*)?",
        re.IGNORECASE,
    )
    urls = url_pattern.findall(text)
    # dict.fromkeys preserves insertion order while deduplicating - avoids
    # wasting API calls on the same URL appearing multiple times in an email
    return list(dict.fromkeys(urls))


def _check_suspicious_patterns(url: str) -> list[str]:
    """Check URL for suspicious patterns."""
    indicators = []
    parsed = urlparse(url)

    # Legitimate services almost never use raw IPs in URLs - attackers use them
    # to bypass domain-based blocklists and avoid DNS resolution logging
    if re.match(r"\d{1,3}(\.\d{1,3}){3}", parsed.netloc):
        indicators.append("Uses IP address instead of domain name")

    # Excessive subdomains
    parts = parsed.netloc.split(".")
    if len(parts) > 4:
        indicators.append(f"Excessive subdomains ({len(parts)} levels)")

    # Free/cheap TLDs heavily abused by phishing campaigns. Freenom TLDs
    # (.tk, .ml, .ga, .cf) are especially common because they're free to register
    suspicious_tlds = [".xyz", ".top", ".click", ".link", ".tk", ".ml", ".ga", ".cf"]
    if any(parsed.netloc.endswith(tld) for tld in suspicious_tlds):
        indicators.append(f"Suspicious TLD: {parsed.netloc.split('.')[-1]}")

    # URL shorteners
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"]
    if any(s in parsed.netloc for s in shorteners):
        indicators.append("URL shortener detected")

    # Brand impersonation: attackers put trusted brand names in subdomains
    # (e.g., "paypal.login.evil.com") to appear legitimate at first glance.
    # We only flag it when the brand is NOT in the actual registered domain
    brands = ["paypal", "microsoft", "apple", "google", "amazon", "netflix", "bank"]
    domain_lower = parsed.netloc.lower()
    for brand in brands:
        if brand in domain_lower and brand not in domain_lower.split(".")[-2]:
            indicators.append(f"Possible brand impersonation: '{brand}' in subdomain")

    # Null bytes (%00) and CRLF (%0a/%0d) are used in injection attacks -
    # null byte truncation can bypass extension filters, CRLF enables
    # HTTP header injection and response splitting
    if "%00" in url or "%0a" in url.lower() or "%0d" in url.lower():
        indicators.append("Suspicious encoded characters (null bytes or CRLF)")

    # Very long URL
    if len(url) > 200:
        indicators.append(f"Unusually long URL ({len(url)} characters)")

    # RFC 3986 allows user@host in URLs - attackers exploit this to show a
    # trusted domain before @, while the browser actually connects to the
    # host after @ (e.g., "http://google.com@evil.com" goes to evil.com)
    if "@" in parsed.netloc:
        indicators.append("Contains @ symbol (possible credential confusion attack)")

    return indicators


def _is_malicious(result: dict) -> bool:
    """Determine if URL is malicious based on all checks.

    Uses a multi-source correlation approach: pattern analysis alone needs 3+
    indicators to flag (reducing false positives), but a single VirusTotal or
    URLScan.io hit is enough since those are community-validated verdicts.
    """
    if result.get("suspicious_patterns"):
        if len(result["suspicious_patterns"]) >= 3:
            return True

    vt = result.get("virustotal")
    if isinstance(vt, dict) and vt.get("positives", 0) > 2:
        return True

    urlscan_result = result.get("urlscan")
    if isinstance(urlscan_result, dict) and urlscan_result.get("malicious"):
        return True

    return False
