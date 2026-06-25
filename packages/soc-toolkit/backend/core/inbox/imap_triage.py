"""IMAP inbox triage.

Pulls the most recent messages from a mailbox over IMAPS and runs each through
the existing phishing pipeline, returning a compact per-message verdict.
Credentials are used transiently (per request) and never stored. The mail host
is SSRF-guarded so this can't be pointed at internal services.
"""
from __future__ import annotations

import asyncio
import email
import imaplib
from email.header import decode_header, make_header
from typing import Any

from sec_common.netguard import host_blocked

from core.phishing.attachment_scanner import scan_attachment
from core.phishing.header_analyzer import analyze_headers
from core.phishing.url_checker import check_urls
from core.phishing.verdict_engine import generate_verdict


class InboxError(Exception):
    """A user-facing inbox-triage failure (connection/login/select)."""


def _decode(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _fetch_raw_emails(
    host: str, port: int, username: str, password: str, folder: str, limit: int
) -> list[bytes]:
    """Synchronous IMAP fetch (run in a thread): newest ``limit`` messages."""
    try:
        conn = imaplib.IMAP4_SSL(host, port, timeout=10)
    except Exception as exc:
        raise InboxError(f"could not connect to {host}:{port}") from exc
    try:
        conn.login(username, password)
    except imaplib.IMAP4.error as exc:
        raise InboxError("login failed (check username / app password)") from exc

    raws: list[bytes] = []
    try:
        status, _ = conn.select(folder, readonly=True)
        if status != "OK":
            raise InboxError(f"mailbox folder not found: {folder}")
        _, data = conn.search(None, "ALL")
        ids = data[0].split() if data and data[0] else []
        for msg_id in reversed(ids[-limit:]):
            _, msg_data = conn.fetch(msg_id, "(RFC822)")
            if msg_data and isinstance(msg_data[0], tuple):
                raws.append(msg_data[0][1])
    finally:
        try:
            conn.logout()
        except Exception:
            pass
    return raws


async def triage_inbox(
    *,
    host: str,
    username: str,
    password: str,
    port: int = 993,
    folder: str = "INBOX",
    limit: int = 10,
) -> list[dict[str, Any]]:
    if await host_blocked(host):
        raise InboxError("mail host resolves to a private/blocked address")
    capped = max(1, min(limit, 25))
    raws = await asyncio.to_thread(
        _fetch_raw_emails, host, port, username, password, folder, capped
    )

    results: list[dict[str, Any]] = []
    for raw in raws:
        raw_email = raw.decode("utf-8", errors="replace")
        msg = email.message_from_string(raw_email)
        headers = analyze_headers(raw_email)
        urls = await check_urls(raw_email)
        attachments = await scan_attachment(raw_email)
        verdict = generate_verdict(headers, urls, attachments)
        results.append(
            {
                "subject": _decode(msg.get("Subject")),
                "from": _decode(msg.get("From")),
                "date": _decode(msg.get("Date")),
                "verdict": verdict["verdict"],
                "risk_score": verdict["risk_score"],
                "indicators": verdict["indicators"][:5],
            }
        )
    return results


__all__ = ["InboxError", "triage_inbox"]
