from integrations.virustotal import VirusTotalClient
from integrations.abuseipdb import AbuseIPDBClient
from integrations.alienvault_otx import AlienVaultOTXClient


async def validate_and_enrich(raw_iocs: list[dict]) -> list[dict]:
    """Validate IOCs and enrich with threat intelligence data."""
    vt = VirusTotalClient()
    abuseipdb = AbuseIPDBClient()
    otx = AlienVaultOTXClient()

    enriched = []

    for ioc in raw_iocs:
        ioc_type = ioc["type"]
        value = ioc["value"]

        enrichment = {}
        malicious = None

        if ioc_type == "ipv4":
            enrichment = await _enrich_ip(value, vt, abuseipdb, otx)
            malicious = _is_ip_malicious(enrichment)

        elif ioc_type in ("domain", "url"):
            enrichment = await _enrich_domain_or_url(value, ioc_type, vt, otx)
            malicious = _is_domain_malicious(enrichment)

        elif ioc_type in ("md5", "sha1", "sha256"):
            enrichment = await _enrich_hash(value, vt, otx)
            malicious = _is_hash_malicious(enrichment)

        elif ioc_type == "email":
            enrichment = {"note": "Email address - manual verification recommended"}

        elif ioc_type == "cve":
            enrichment = {"note": f"Vulnerability identifier: {value}"}

        enriched.append({
            "type": ioc_type,
            "value": value,
            "context": ioc.get("context"),
            "enrichment": enrichment,
            "malicious": malicious,
        })

    return enriched


async def _enrich_ip(
    ip: str,
    vt: VirusTotalClient,
    abuseipdb: AbuseIPDBClient,
    otx: AlienVaultOTXClient,
) -> dict:
    """Enrich an IP with multiple sources."""
    enrichment = {}

    try:
        enrichment["virustotal"] = await vt.check_ip(ip)
    except Exception:
        enrichment["virustotal"] = {"error": "unavailable"}

    try:
        enrichment["abuseipdb"] = await abuseipdb.check_ip(ip)
    except Exception:
        enrichment["abuseipdb"] = {"error": "unavailable"}

    try:
        enrichment["otx"] = await otx.check_ip(ip)
    except Exception:
        enrichment["otx"] = {"error": "unavailable"}

    return enrichment


async def _enrich_domain_or_url(
    value: str,
    ioc_type: str,
    vt: VirusTotalClient,
    otx: AlienVaultOTXClient,
) -> dict:
    """Enrich a domain or URL."""
    enrichment = {}

    try:
        if ioc_type == "url":
            enrichment["virustotal"] = await vt.check_url(value)
        else:
            enrichment["virustotal"] = await vt.check_domain(value)
    except Exception:
        enrichment["virustotal"] = {"error": "unavailable"}

    if ioc_type == "domain":
        try:
            enrichment["otx"] = await otx.check_domain(value)
        except Exception:
            enrichment["otx"] = {"error": "unavailable"}

    return enrichment


async def _enrich_hash(
    file_hash: str,
    vt: VirusTotalClient,
    otx: AlienVaultOTXClient,
) -> dict:
    """Enrich a file hash."""
    enrichment = {}

    try:
        enrichment["virustotal"] = await vt.check_hash(file_hash)
    except Exception:
        enrichment["virustotal"] = {"error": "unavailable"}

    try:
        enrichment["otx"] = await otx.check_hash(file_hash)
    except Exception:
        enrichment["otx"] = {"error": "unavailable"}

    return enrichment


def _is_ip_malicious(enrichment: dict) -> bool:
    """Determine if an IP is malicious based on enrichment."""
    vt = enrichment.get("virustotal", {})
    if isinstance(vt, dict) and vt.get("positives", 0) > 3:
        return True

    abuse = enrichment.get("abuseipdb", {})
    if isinstance(abuse, dict) and abuse.get("abuse_score", 0) > 50:
        return True

    otx = enrichment.get("otx", {})
    if isinstance(otx, dict) and otx.get("pulse_count", 0) > 5:
        return True

    return False


def _is_domain_malicious(enrichment: dict) -> bool:
    """Determine if a domain/URL is malicious."""
    vt = enrichment.get("virustotal", {})
    if isinstance(vt, dict) and vt.get("positives", 0) > 2:
        return True
    return False


def _is_hash_malicious(enrichment: dict) -> bool:
    """Determine if a file hash is malicious."""
    vt = enrichment.get("virustotal", {})
    if isinstance(vt, dict) and vt.get("positives", 0) > 2:
        return True
    if isinstance(vt, dict) and vt.get("found") and vt.get("threat_label"):
        return True
    return False
