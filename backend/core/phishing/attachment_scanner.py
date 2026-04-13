import email
import hashlib
from email import policy

from integrations.malwarebazaar import MalwareBazaarClient
from integrations.virustotal import VirusTotalClient


async def scan_attachment(raw_email: str) -> list[dict]:
    """Extract and scan email attachments for malware."""
    msg = email.message_from_string(raw_email, policy=policy.default)
    results = []

    # Walk the MIME tree to find all attachments, including inline ones.
    # Inline attachments are checked too because malware can be embedded
    # as "inline" content to bypass filters that only scan "attachment" parts
    for part in msg.walk():
        content_disposition = str(part.get("Content-Disposition", ""))
        if "attachment" not in content_disposition and "inline" not in content_disposition:
            continue

        filename = part.get_filename() or "unknown"
        content = part.get_payload(decode=True)
        if not content:
            continue

        file_info = _analyze_file(filename, content)
        file_info["virustotal"] = await _check_virustotal(file_info["hashes"]["sha256"])
        file_info["malwarebazaar"] = await _check_malwarebazaar(file_info["hashes"]["sha256"])
        file_info["malicious"] = _is_attachment_malicious(file_info)

        results.append(file_info)

    return results


def _analyze_file(filename: str, content: bytes) -> dict:
    """Analyze file metadata and compute hashes."""
    return {
        "filename": filename,
        "size": len(content),
        "extension": filename.rsplit(".", 1)[-1].lower() if "." in filename else "",
        # Compute all three hash types: MD5 for legacy IOC databases,
        # SHA1 for compatibility, SHA256 for modern threat intel lookups.
        # VirusTotal and MalwareBazaar primarily use SHA256
        "hashes": {
            "md5": hashlib.md5(content).hexdigest(),
            "sha1": hashlib.sha1(content).hexdigest(),
            "sha256": hashlib.sha256(content).hexdigest(),
        },
        "suspicious_extension": _is_suspicious_extension(filename),
        "double_extension": _has_double_extension(filename),
    }


def _is_suspicious_extension(filename: str) -> bool:
    """Check if file has a suspicious extension.

    These are file types that can execute code on Windows. Macro-enabled
    Office files (.docm, .xlsm, .pptm) are included because VBA macros
    are the #1 initial access vector in enterprise phishing campaigns.
    """
    dangerous = {
        "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe",
        "js", "jse", "wsf", "wsh", "ps1", "msi", "dll", "hta",
        "cpl", "inf", "reg", "lnk", "docm", "xlsm", "pptm",
    }
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in dangerous


def _has_double_extension(filename: str) -> bool:
    """Detect double extension tricks (e.g., invoice.pdf.exe).

    Windows hides known extensions by default, so "invoice.pdf.exe" appears
    as "invoice.pdf" to the user. This is one of the oldest and most
    effective social engineering tricks for malware delivery.
    """
    parts = filename.rsplit(".", 2)
    return len(parts) >= 3


async def _check_virustotal(sha256: str) -> dict | None:
    """Check file hash against VirusTotal."""
    try:
        vt = VirusTotalClient()
        return await vt.check_hash(sha256)
    except Exception:
        return {"error": "API unavailable"}


async def _check_malwarebazaar(sha256: str) -> dict | None:
    """Check file hash against MalwareBazaar."""
    try:
        mb = MalwareBazaarClient()
        return await mb.check_hash(sha256)
    except Exception:
        return {"error": "API unavailable"}


def _is_attachment_malicious(file_info: dict) -> bool:
    """Determine if attachment is malicious."""
    if file_info.get("double_extension"):
        return True

    vt = file_info.get("virustotal")
    if isinstance(vt, dict) and vt.get("positives", 0) > 2:
        return True

    mb = file_info.get("malwarebazaar")
    if isinstance(mb, dict) and mb.get("found"):
        return True

    return False
