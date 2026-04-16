"""MISP enrichment for IOC-extractor output.

Takes the list produced by core/ioc/text_extractor.py and checks each IOC
against the configured MISP instance. The goal is triage speed: an analyst
pastes a threat report, the toolkit extracts IOCs, and this module flags
which ones are already known to MISP so the analyst can skip re-investigating
them and focus on the novel ones.
"""
from __future__ import annotations

import asyncio
from typing import Any

from integrations.misp import MISPClient

# Map the IOC-extractor type names to the MISP client's IOC-kind parameter.
# CVEs are intentionally excluded: MISP stores CVEs but they are metadata
# about vulnerabilities, not indicators-of-compromise in the triage sense
_IOC_TYPE_TO_KIND: dict[str, str] = {
    "ipv4": "ip",
    "ipv6": "ip",
    "domain": "domain",
    "url": "url",
    "email": "email",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
}


async def enrich_iocs(iocs: list[dict[str, Any]]) -> dict[str, Any]:
    """Look up every IOC in the list against MISP.

    Parameters
    ----------
    iocs:
        List of ``{"type": ..., "value": ..., "context": ...}`` as produced
        by ``core.ioc.text_extractor.extract_from_text``.

    Returns
    -------
    dict with:
        - ``known_count``: total number of IOCs MISP recognised
        - ``results``: per-value enrichment keyed by the IOC value
        - ``summary``: aggregate ``{checked, known}`` stats per IOC kind
    """
    client = MISPClient()

    # Deduplicate by (type, value) - the same IOC can appear many times in a
    # single threat report and checking it repeatedly wastes MISP rate-limit
    seen: set[tuple[str, str]] = set()
    lookups: list[tuple[str, str]] = []
    for ioc in iocs:
        kind = _IOC_TYPE_TO_KIND.get(ioc.get("type", ""))
        value = ioc.get("value", "")
        if not kind or not value:
            continue
        key = (kind, value)
        if key in seen:
            continue
        seen.add(key)
        lookups.append(key)

    if not lookups:
        return {"known_count": 0, "results": {}, "summary": {}}

    # asyncio.gather overlaps I/O; the client's internal rate limiter still
    # enforces the per-minute cap on the MISP instance
    responses = await asyncio.gather(
        *(client.check_attribute(value, kind) for kind, value in lookups),
        return_exceptions=True,
    )

    results: dict[str, Any] = {}
    summary: dict[str, dict[str, int]] = {}
    known_count = 0

    for (kind, value), response in zip(lookups, responses, strict=True):
        bucket = summary.setdefault(kind, {"checked": 0, "known": 0})
        bucket["checked"] += 1

        if isinstance(response, BaseException):
            # One failing lookup shouldn't abort the whole enrichment run -
            # record the error and keep going so the analyst gets partial data
            results[value] = {"error": str(response)}
            continue

        results[value] = response
        if response.get("found"):
            known_count += 1
            bucket["known"] += 1

    return {
        "known_count": known_count,
        "results": results,
        "summary": summary,
    }
