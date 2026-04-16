import logging

from integrations.abuseipdb import AbuseIPDBClient

logger = logging.getLogger(__name__)


async def generate_alerts(analysis: dict) -> list[dict]:
    """Generate alerts with threat intelligence enrichment."""
    alerts = []
    abuseipdb = AbuseIPDBClient()

    # Alert on brute force IPs
    for ip_info in analysis.get("top_ips", []):
        ip = ip_info.get("ip", "")
        count = ip_info.get("attempts", ip_info.get("requests", ip_info.get("events", 0)))

        if count < 5:
            continue

        # Enrich with threat intelligence. Enrichment failures (missing API key,
        # rate limit, network error) should never block alert generation - the
        # brute force alert is valuable even without geo/reputation context.
        geo = None
        try:
            abuse_data = await abuseipdb.check_ip(ip)
            geo = {
                "country": abuse_data.get("country", ""),
                "isp": abuse_data.get("isp", ""),
                "abuse_score": abuse_data.get("abuse_score", 0),
                "is_tor": abuse_data.get("is_tor", False),
                "total_reports": abuse_data.get("total_reports", 0),
            }
        except Exception as exc:
            logger.warning("AbuseIPDB enrichment failed for %s: %s", ip, exc)

        severity = "critical" if count >= 100 else "high" if count >= 50 else "medium"

        alerts.append({
            "severity": severity,
            "message": f"Brute force detected: {count} attempts from {ip}",
            "source_ip": ip,
            "geo": geo,
            "count": count,
            "mitre_technique": "T1110 - Brute Force",
        })

    # Alert on attack patterns (Windows logs)
    for pattern in analysis.get("attack_patterns", []):
        alerts.append({
            "severity": pattern.get("severity", "medium"),
            "message": f"{pattern['pattern']}: {pattern['description']}",
            "source_ip": None,
            "geo": None,
            "count": 1,
            "mitre_technique": pattern.get("mitre", ""),
        })

    # Alert on suspicious web requests
    for request in analysis.get("suspicious_requests", [])[:10]:
        alerts.append({
            "severity": "medium",
            "message": f"Suspicious request: {request.get('method', '')} {request.get('path', '')}",
            "source_ip": request.get("ip", ""),
            "geo": None,
            "count": 1,
            "mitre_technique": "T1190 - Exploit Public-Facing Application",
        })

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    alerts.sort(key=lambda a: severity_order.get(a["severity"], 5))

    return alerts
