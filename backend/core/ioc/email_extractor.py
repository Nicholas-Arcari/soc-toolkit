import email
from email import policy

from core.ioc.text_extractor import extract_from_text


def extract_from_email(raw_email: str) -> list[dict]:
    """Extract IOCs from an email (.eml) file."""
    msg = email.message_from_string(raw_email, policy=policy.default)

    # Collect all text parts
    text_parts = []

    # Headers
    for header in ("From", "To", "Subject", "Return-Path", "Reply-To", "Received"):
        values = msg.get_all(header, [])
        text_parts.extend(str(v) for v in values)

    # Body
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ("text/plain", "text/html"):
                payload = part.get_payload(decode=True)
                if payload:
                    text_parts.append(payload.decode("utf-8", errors="replace"))
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            text_parts.append(payload.decode("utf-8", errors="replace"))

    combined_text = "\n".join(text_parts)
    return extract_from_text(combined_text)
