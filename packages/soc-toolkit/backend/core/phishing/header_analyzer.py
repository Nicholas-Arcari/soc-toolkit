import email
import re
from email.utils import parseaddr


def analyze_headers(raw_email: str) -> dict:
    """Analyze email headers for phishing indicators.

    Follows the SOC triage workflow: authenticate sender first (SPF/DKIM/DMARC),
    then check for header anomalies that indicate spoofing or impersonation.
    """
    msg = email.message_from_string(raw_email)

    # Extract key headers in triage order: identity first, then authentication,
    # then routing chain - mirrors how a SOC analyst would manually inspect
    results = {
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "return_path": msg.get("Return-Path", ""),
        "message_id": msg.get("Message-ID", ""),
        "received_chain": _parse_received_chain(msg),
        "spf": _check_spf(msg),
        "dkim": _check_dkim(msg),
        "dmarc": _check_dmarc(msg),
        "suspicious_indicators": [],
    }

    results["suspicious_indicators"] = _detect_header_anomalies(results, msg)
    return results


def _parse_received_chain(msg: email.message.Message) -> list[dict]:
    """Parse the Received headers to trace email path.

    Each mail server adds a Received header, creating a chain from origin to
    destination. Inconsistencies in this chain (e.g., unexpected hops through
    suspicious servers) are a strong indicator of email relay abuse or spoofing.
    """
    received_headers = msg.get_all("Received", [])
    chain = []

    for header in received_headers:
        entry = {"raw": header.strip()}

        ip_match = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", header)
        if ip_match:
            entry["ip"] = ip_match.group(1)

        from_match = re.search(r"from\s+([\w.-]+)", header, re.IGNORECASE)
        if from_match:
            entry["from_host"] = from_match.group(1)

        chain.append(entry)

    return chain


def _check_spf(msg: email.message.Message) -> dict:
    """Check SPF (Sender Policy Framework) authentication results.

    SPF verifies that the sending mail server is authorized by the domain's
    DNS records. A fail/softfail means the email came from an unauthorized
    server - common in spoofing attacks where attackers forge the From address.
    """
    auth_results = msg.get("Authentication-Results", "")
    received_spf = msg.get("Received-SPF", "")

    spf_status = "missing"
    if "spf=pass" in auth_results.lower() or "pass" in received_spf.lower():
        spf_status = "pass"
    elif "spf=fail" in auth_results.lower() or "fail" in received_spf.lower():
        spf_status = "fail"
    elif "spf=softfail" in auth_results.lower():
        spf_status = "softfail"
    elif "spf=neutral" in auth_results.lower():
        spf_status = "neutral"

    return {"status": spf_status, "raw": received_spf or auth_results}


def _check_dkim(msg: email.message.Message) -> dict:
    """Check DKIM (DomainKeys Identified Mail) authentication results.

    DKIM uses cryptographic signatures to verify email integrity - if DKIM
    fails, the email body or headers were modified in transit, which could
    indicate tampering or a man-in-the-middle attack.
    """
    auth_results = msg.get("Authentication-Results", "")
    dkim_signature = msg.get("DKIM-Signature", "")

    dkim_status = "missing"
    if "dkim=pass" in auth_results.lower():
        dkim_status = "pass"
    elif "dkim=fail" in auth_results.lower():
        dkim_status = "fail"
    elif dkim_signature:
        dkim_status = "present_unverified"

    return {"status": dkim_status, "has_signature": bool(dkim_signature)}


def _check_dmarc(msg: email.message.Message) -> dict:
    """Check DMARC (Domain-based Message Authentication) results.

    DMARC builds on SPF and DKIM - it tells the receiving server what to do
    when authentication fails (reject, quarantine, or none). A DMARC fail
    means both SPF and DKIM alignment failed, strongly suggesting spoofing.
    """
    auth_results = msg.get("Authentication-Results", "")

    dmarc_status = "missing"
    if "dmarc=pass" in auth_results.lower():
        dmarc_status = "pass"
    elif "dmarc=fail" in auth_results.lower():
        dmarc_status = "fail"

    return {"status": dmarc_status}


def _detect_header_anomalies(results: dict, msg: email.message.Message) -> list[str]:
    """Detect suspicious patterns in email headers."""
    indicators = []

    # Display name spoofing: attackers put an email address in the display name
    # (e.g., "admin@company.com <attacker@evil.com>") to trick users who only
    # see the display name in their email client
    from_header = results["from"]
    display_name, from_addr = parseaddr(from_header)
    if display_name and "@" in display_name:
        indicators.append(
            f"Display name contains email address: '{display_name}' (possible impersonation)"
        )

    # Return-Path mismatch: the Return-Path (envelope sender) should match the
    # From address. A mismatch means bounces go to a different address than the
    # claimed sender - a classic indicator of phishing infrastructure
    _, return_addr = parseaddr(results["return_path"])
    if from_addr and return_addr and from_addr.lower() != return_addr.lower():
        indicators.append(
            f"Return-Path mismatch: From={from_addr}, Return-Path={return_addr}"
        )

    # SPF/DKIM/DMARC failures
    if results["spf"]["status"] in ("fail", "softfail"):
        indicators.append(f"SPF {results['spf']['status']}: sender not authorized")
    if results["dkim"]["status"] == "fail":
        indicators.append("DKIM verification failed: email may have been tampered with")
    if results["dmarc"]["status"] == "fail":
        indicators.append("DMARC failed: domain authentication not passed")

    # Missing authentication
    auth_missing = []
    if results["spf"]["status"] == "missing":
        auth_missing.append("SPF")
    if results["dkim"]["status"] == "missing":
        auth_missing.append("DKIM")
    if results["dmarc"]["status"] == "missing":
        auth_missing.append("DMARC")
    if auth_missing:
        indicators.append(f"Missing authentication: {', '.join(auth_missing)}")

    # Suspicious subject patterns
    subject = results["subject"].lower()
    urgency_keywords = [
        "urgent", "immediate", "action required", "verify your account",
        "suspended", "locked", "expire", "confirm your", "click here",
        "act now", "limited time", "reset your password",
    ]
    found = [kw for kw in urgency_keywords if kw in subject]
    if found:
        indicators.append(f"Urgency keywords in subject: {', '.join(found)}")

    # Reply-To hijacking: attacker sets Reply-To to a different address so
    # responses go to them instead of the spoofed sender. Common in BEC
    # (Business Email Compromise) attacks targeting financial departments
    reply_to = msg.get("Reply-To", "")
    if reply_to:
        _, reply_addr = parseaddr(reply_to)
        if reply_addr and from_addr and reply_addr.lower() != from_addr.lower():
            indicators.append(
                f"Reply-To mismatch: From={from_addr}, Reply-To={reply_addr}"
            )

    return indicators
