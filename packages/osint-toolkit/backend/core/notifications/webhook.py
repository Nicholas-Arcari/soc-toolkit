"""POST one JSON payload per severe finding.

The webhook body is deliberately flat and aggregator-agnostic - it's
close enough to a Slack/Discord "plain JSON" incoming webhook to drop
straight in, and easy to re-shape for anything else. We do not retry
on failure: the DB is the source of truth, and a missed notification
is a visibility issue, not a data-loss issue.
"""
from __future__ import annotations

import logging
from collections.abc import Iterable

import httpx

from db.models import Finding, Target

_SEVERE = {"high", "critical"}
_log = logging.getLogger(__name__)


def _payload(target: Target, finding: Finding) -> dict[str, object]:
    return {
        "event": "finding.created",
        "target": {
            "id": target.id,
            "name": target.name,
        },
        "finding": {
            "id": finding.id,
            "severity": finding.severity,
            "category": finding.category,
            "description": finding.description,
            "status": finding.status,
        },
    }


async def notify_severe_findings(
    *,
    target: Target,
    findings: Iterable[Finding],
    webhook_url: str,
    client: httpx.AsyncClient | None = None,
    timeout: float = 5.0,
) -> int:
    """POST one webhook per severe finding; return how many were sent.

    ``webhook_url`` is passed in rather than read from settings so tests
    and alternate transports can drive this function directly. When
    empty, the function is a no-op - nothing to send.
    """
    if not webhook_url:
        return 0

    severe = [f for f in findings if (f.severity or "").lower() in _SEVERE]
    if not severe:
        return 0

    sent = 0
    owns_client = client is None
    c = client or httpx.AsyncClient(timeout=timeout)
    try:
        for finding in severe:
            try:
                resp = await c.post(webhook_url, json=_payload(target, finding))
                resp.raise_for_status()
                sent += 1
            except httpx.HTTPError as exc:
                # Log and keep going - one bad hook shouldn't swallow
                # the others, and we don't want the scan endpoint to
                # fail just because the operator's Slack is down.
                _log.warning(
                    "webhook delivery failed",
                    extra={"finding_id": finding.id, "error": str(exc)},
                )
    finally:
        if owns_client:
            await c.aclose()
    return sent
