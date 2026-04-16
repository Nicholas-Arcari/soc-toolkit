"""MISP (Malware Information Sharing Platform) REST client.

MISP is one of the most widely deployed community threat-intel platforms.
During triage a SOC analyst typically asks: "has this IOC been seen in any
event on our MISP instance or the feeds we subscribe to?" This client answers
that question and returns the matching event metadata so the analyst can
pivot to the full event in the MISP UI.
"""
from __future__ import annotations

from typing import Any

import httpx

from config import settings
from integrations.base_client import BaseAPIClient

# MISP accepts many attribute "types" - we map the IOC-extractor kinds to the
# type names MISP expects in the /attributes/restSearch payload
_IOC_TYPE_MAP: dict[str, list[str]] = {
    "ip": ["ip-src", "ip-dst"],
    "domain": ["domain", "hostname"],
    "url": ["url"],
    "email": ["email-src", "email-dst", "email"],
    "md5": ["md5"],
    "sha1": ["sha1"],
    "sha256": ["sha256"],
}


class MISPClient(BaseAPIClient):
    """MISP REST API client.

    Unlike public feeds (VirusTotal, AbuseIPDB), MISP is self-hosted - the
    BASE_URL is taken from settings at request time, not a class constant.
    Rate limiting is conservative (20/min) because MISP instances are often
    shared across multiple teams and hammering one can disrupt others.
    """

    RATE_LIMIT = 20

    @property
    def base_url(self) -> str:
        # MISP URL is tenant-specific so we read it per-request.
        # Strip trailing slash to avoid double slashes in constructed URLs
        return settings.misp_url.rstrip("/")

    def _get_headers(self) -> dict:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            # MISP uses a raw API key in Authorization (no Bearer prefix)
            "Authorization": settings.misp_api_key,
        }

    def _configured(self) -> bool:
        return bool(settings.misp_url) and settings.has_api_key("misp")

    async def _post_search(self, payload: dict) -> dict:
        """Direct POST to MISP - skips base-client because MISP lives on a
        tenant-specific URL that BaseAPIClient doesn't know about."""
        await self.rate_limiter.acquire()
        url = f"{self.base_url}/attributes/restSearch"

        async with httpx.AsyncClient(timeout=30.0, verify=settings.misp_verify_tls) as client:
            response = await client.post(url, headers=self._get_headers(), json=payload)
            response.raise_for_status()
            data: dict = response.json()
            return data

    async def check_attribute(self, value: str, ioc_kind: str) -> dict:
        """Check if an IOC value exists as an attribute in any MISP event.

        ``ioc_kind`` is the toolkit's IOC category (ip, domain, url, email,
        md5, sha1, sha256); it is translated to the MISP attribute type(s).
        Returns a dict with ``found`` and, when found, a condensed list of
        the events the attribute appeared in so the analyst can pivot.
        """
        if not self._configured():
            return {"error": "MISP not configured"}

        misp_types = _IOC_TYPE_MAP.get(ioc_kind)
        if not misp_types:
            return {"found": False, "error": f"unsupported IOC kind: {ioc_kind}"}

        try:
            # returnFormat=json gives consistent shape; limit=10 keeps the
            # payload small for triage use (analysts pivot to UI for more)
            data = await self._post_search({
                "returnFormat": "json",
                "value": value,
                "type": misp_types,
                "limit": 10,
            })
        except httpx.HTTPError as exc:
            return {"found": False, "error": f"MISP lookup failed: {exc}"}

        attributes = data.get("response", {}).get("Attribute", [])
        if not attributes:
            return {"found": False}

        events = []
        for attr in attributes:
            event = attr.get("Event", {})
            events.append({
                "event_id": event.get("id"),
                "uuid": event.get("uuid"),
                "info": event.get("info", ""),
                "threat_level_id": event.get("threat_level_id"),
                "org": event.get("Orgc", {}).get("name", ""),
                "date": event.get("date", ""),
                "attribute_category": attr.get("category", ""),
                "attribute_type": attr.get("type", ""),
                "to_ids": attr.get("to_ids", False),
            })

        return {
            "found": True,
            "event_count": len(events),
            # Highest-confidence signal: any attribute with to_ids=True is
            # intended to be exported to detection systems - treat as malicious
            "to_ids": any(e["to_ids"] for e in events),
            "events": events,
        }

    async def get_event(self, uuid: str) -> dict:
        """Fetch a full MISP event by UUID."""
        if not self._configured():
            return {"error": "MISP not configured"}

        await self.rate_limiter.acquire()
        url = f"{self.base_url}/events/view/{uuid}"

        try:
            async with httpx.AsyncClient(
                timeout=30.0, verify=settings.misp_verify_tls
            ) as client:
                response = await client.get(url, headers=self._get_headers())
                response.raise_for_status()
                data: dict[str, Any] = response.json()
        except httpx.HTTPError as exc:
            return {"error": f"MISP event fetch failed: {exc}"}

        return data.get("Event", {})
