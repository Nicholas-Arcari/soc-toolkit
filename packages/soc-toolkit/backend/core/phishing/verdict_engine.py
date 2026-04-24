def generate_verdict(headers: dict, urls: list[dict], attachments: list[dict]) -> dict:
    """Generate a final phishing verdict based on all analysis results.

    Scoring follows a weighted approach: authentication failures (SPF/DKIM/DMARC)
    carry the most weight because they're hard to fake in legitimate email, while
    pattern-based indicators are weighted lower to avoid false positives from
    marketing emails that happen to use urgency language.
    """
    indicators = []
    risk_score = 0

    header_indicators = headers.get("suspicious_indicators", [])
    indicators.extend(header_indicators)
    risk_score += len(header_indicators) * 10

    # SPF/DKIM/DMARC carry heavy weight (25/20/25 pts) because authentication
    # failures are objective, protocol-level evidence of spoofing - unlike
    # heuristic checks which can produce false positives
    if headers.get("spf", {}).get("status") == "fail":
        risk_score += 25
    if headers.get("dkim", {}).get("status") == "fail":
        risk_score += 20
    if headers.get("dmarc", {}).get("status") == "fail":
        risk_score += 25

    # URL-based scoring
    malicious_urls = [u for u in urls if u.get("malicious")]
    if malicious_urls:
        risk_score += len(malicious_urls) * 20
        for url in malicious_urls:
            indicators.append(f"Malicious URL detected: {url['url']}")

    suspicious_url_count = sum(
        len(u.get("suspicious_patterns", [])) for u in urls
    )
    risk_score += suspicious_url_count * 5

    # Attachments score highest (30 pts each) because a confirmed malicious
    # file is the most dangerous element - one click can compromise a system
    malicious_attachments = [a for a in attachments if a.get("malicious")]
    if malicious_attachments:
        risk_score += len(malicious_attachments) * 30
        for att in malicious_attachments:
            indicators.append(f"Malicious attachment: {att['filename']}")

    suspicious_ext = [a for a in attachments if a.get("suspicious_extension")]
    if suspicious_ext:
        risk_score += len(suspicious_ext) * 15
        for att in suspicious_ext:
            indicators.append(f"Suspicious file type: {att['filename']}")

    # Cap score at 100
    risk_score = min(risk_score, 100)

    # Four-tier verdict system aligned with SOC escalation workflows:
    # CLEAN = close ticket, CAUTIOUS = monitor, SUSPICIOUS = escalate to L2,
    # MALICIOUS = immediate containment and incident response
    if risk_score >= 70:
        verdict = "MALICIOUS"
        confidence = min(0.95, 0.7 + (risk_score - 70) * 0.008)
    elif risk_score >= 40:
        verdict = "SUSPICIOUS"
        confidence = 0.5 + (risk_score - 40) * 0.007
    elif risk_score >= 15:
        verdict = "CAUTIOUS"
        confidence = 0.4 + (risk_score - 15) * 0.004
    else:
        verdict = "CLEAN"
        confidence = max(0.6, 0.9 - risk_score * 0.02)

    return {
        "verdict": verdict,
        "confidence": round(confidence, 2),
        "risk_score": risk_score,
        "indicators": indicators,
        "recommendations": _generate_recommendations(verdict, indicators),
    }


def _generate_recommendations(verdict: str, indicators: list[str]) -> list[str]:
    """Generate actionable recommendations based on verdict."""
    recommendations = []

    if verdict == "MALICIOUS":
        recommendations.append("Do NOT click any links or download attachments from this email")
        recommendations.append("Report this email to your security team immediately")
        recommendations.append("Block the sender address at the email gateway")
        recommendations.append("Check if other users received the same email")
    elif verdict == "SUSPICIOUS":
        recommendations.append("Do not interact with this email until verified")
        recommendations.append("Contact the supposed sender through a known channel to confirm")
        recommendations.append("Forward to security team for further analysis")
    elif verdict == "CAUTIOUS":
        recommendations.append("Verify the sender identity before taking any action")
        recommendations.append("Hover over links to check actual destinations before clicking")

    # Specific recommendations based on indicators
    indicator_text = " ".join(indicators).lower()
    if "spf" in indicator_text or "dkim" in indicator_text:
        recommendations.append("Email authentication failed - sender may be spoofed")
    if "attachment" in indicator_text:
        recommendations.append("Scan any attachments in a sandbox before opening")
    if "url shortener" in indicator_text:
        recommendations.append("Expand shortened URLs before clicking to verify destination")

    return recommendations
