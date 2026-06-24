"""Client for the separate license-server (SaaS "doppio binario").

Only used when the SaaS instance has `license_server_url` configured. A
self-hosted clone leaves it empty and never reaches out. Failures degrade to
``{"valid": False, ...}`` so a redeem attempt fails closed rather than 500s.
"""
from __future__ import annotations

from typing import Any

import httpx


async def validate_license(
    server_url: str, api_key: str, key: str
) -> dict[str, Any]:
    """Ask the license-server whether ``key`` is currently valid."""
    url = server_url.rstrip("/") + "/api/v1/validate"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(
                url, json={"key": key}, headers={"X-API-Key": api_key}
            )
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError:
        return {"valid": False, "reason": "license server unreachable"}
    if not isinstance(data, dict):
        return {"valid": False, "reason": "malformed license-server response"}
    return data


__all__ = ["validate_license"]
