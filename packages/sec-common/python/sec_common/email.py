"""Email delivery for verification + password-reset links.

The dev default (`ConsoleEmailSender`) logs the message so the flows work
without an SMTP account; production uses `SmtpEmailSender` (stdlib smtplib,
no extra dependency). Apps pick one based on whether SMTP is configured.
"""
from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from typing import Protocol

logger = logging.getLogger(__name__)


class EmailSender(Protocol):
    def send(self, *, to: str, subject: str, body: str) -> None: ...


class ConsoleEmailSender:
    """Logs the email instead of sending it (dev / no SMTP configured)."""

    def send(self, *, to: str, subject: str, body: str) -> None:
        logger.info("[email:dev] to=%s subject=%r\n%s", to, subject, body)


class SmtpEmailSender:
    """Sends via SMTP (STARTTLS by default). stdlib only."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str,
        password: str,
        from_addr: str,
        starttls: bool = True,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.starttls = starttls

    def send(self, *, to: str, subject: str, body: str) -> None:
        msg = EmailMessage()
        msg["From"] = self.from_addr
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(self.host, self.port, timeout=10) as smtp:
            if self.starttls:
                smtp.starttls()
            if self.username:
                smtp.login(self.username, self.password)
            smtp.send_message(msg)


__all__ = ["ConsoleEmailSender", "EmailSender", "SmtpEmailSender"]
