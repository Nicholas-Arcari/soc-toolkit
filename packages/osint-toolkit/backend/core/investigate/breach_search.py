"""Breach search - wraps the HIBP client with domain-aware result shape.

The route-facing surface returns a consistent ``BreachSearchResult`` in
two modes:

- **Keyed (normal)**: ``breaches`` contains the HIBP records.
- **Degraded (no key)**: ``available=False``, ``breaches=[]``, and a
  human-readable ``note`` so the UI can render "configure HIBP_API_KEY
  to enable this feature" instead of an error toast.

The degraded path exists because HIBP dropped free account lookups in
2019. A public install without the paid subscription should still
surface the feature in the UI - just with a clear explanation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from sec_common.integrations import HIBPClient


@dataclass
class BreachRecord:
    name: str
    title: str
    domain: str
    breach_date: str
    pwn_count: int
    data_classes: list[str]
    verified: bool = False
    sensitive: bool = False
    description: str = ""


@dataclass
class BreachSearchResult:
    query: str
    kind: str  # "email" | "domain"
    available: bool
    breaches: list[BreachRecord] = field(default_factory=list)
    note: str = ""


_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN = re.compile(r"^[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


class BreachSearchValidationError(ValueError):
    """Raised for malformed query inputs."""


async def search_breaches(query: str, *, client: HIBPClient) -> BreachSearchResult:
    """Dispatch to email or domain lookup based on the query shape.

    Callers pass the ``HIBPClient`` in so the API route can reuse the
    same keyed instance across requests (and so tests can inject a
    mock).
    """
    query = query.strip()

    if _EMAIL.match(query):
        kind = "email"
        if not client.api_key:
            return BreachSearchResult(
                query=query,
                kind=kind,
                available=False,
                note="HIBP account lookup requires a paid API key (HIBP_API_KEY).",
            )
        rows = await client.breaches_for_account(query)

    elif _DOMAIN.match(query):
        kind = "domain"
        if not client.api_key:
            return BreachSearchResult(
                query=query,
                kind=kind,
                available=False,
                note="HIBP domain filter requires a paid API key (HIBP_API_KEY).",
            )
        rows = await client.breaches_for_domain(query)

    else:
        raise BreachSearchValidationError(
            "query must be an email address or a domain"
        )

    return BreachSearchResult(
        query=query,
        kind=kind,
        available=True,
        breaches=[
            BreachRecord(
                name=r.get("name", ""),
                title=r.get("title", ""),
                domain=r.get("domain", ""),
                breach_date=r.get("breach_date", ""),
                pwn_count=int(r.get("pwn_count", 0) or 0),
                data_classes=list(r.get("data_classes", []) or []),
                verified=bool(r.get("verified", False)),
                sensitive=bool(r.get("sensitive", False)),
                description=r.get("description", ""),
            )
            for r in rows
        ],
    )
