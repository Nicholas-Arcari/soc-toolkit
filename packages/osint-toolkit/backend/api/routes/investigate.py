"""Investigative OSINT routes.

Distinct persona from target-based scans: the operator has an
identifier (username, email, image) and wants the graph of connected
entities. No DB persistence - investigative lookups are interactive,
not historical. If we ever decide to remember searches, that becomes
an opt-in audit-log toggle rather than the default.
"""
from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from pydantic import BaseModel, Field
from sec_common.integrations import HIBPClient
from sec_common.ratelimit import SlidingWindowLimiter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from core.fingerprint.fingerprinter import fingerprint_site
from core.investigate.breach_search import (
    BreachSearchValidationError,
    search_breaches,
)
from core.investigate.entity_graph import (
    graph_from_breaches,
    graph_from_image,
    graph_from_username,
)
from core.investigate.image_metadata import (
    ImageValidationError,
    extract_metadata,
)
from core.investigate.person import PersonValidationError, investigate_person
from core.investigate.username_search import (
    UsernameValidationError,
    search_username,
)
from db.models import Investigation
from db.session import get_session, new_session

router = APIRouter()


async def _save_investigation(
    kind: str, query: str, summary: str, result: dict
) -> None:
    """Best-effort persistence; never break an investigation if the DB is down."""
    try:
        async with new_session() as session:
            session.add(
                Investigation(
                    kind=kind, query=query, summary=summary, result=result
                )
            )
            await session.commit()
    except Exception:
        pass


@router.get("/history", status_code=status.HTTP_200_OK)
async def investigation_history(
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Recent saved person/fingerprint investigations (newest first)."""
    rows = (
        (
            await session.execute(
                select(Investigation)
                .order_by(Investigation.created_at.desc())
                .limit(25)
            )
        )
        .scalars()
        .all()
    )
    return {
        "investigations": [
            {
                "id": row.id,
                "kind": row.kind,
                "query": row.query,
                "summary": row.summary,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ]
    }


class UsernameQuery(BaseModel):
    username: str = Field(min_length=1, max_length=64)


class EmailOrDomainQuery(BaseModel):
    query: str = Field(min_length=1, max_length=253)


def _dump_dataclass(obj: object) -> dict:
    """``dataclasses.asdict`` + camel-friendly for the frontend.

    We keep snake_case on the wire and let the frontend handle the
    mapping - changing it here would break the graph component that
    already expects ``data.id`` / ``data.label``.
    """
    return asdict(obj)  # type: ignore[call-overload]


@router.post("/username", status_code=status.HTTP_200_OK)
async def investigate_username(payload: UsernameQuery) -> dict:
    """Probe the curated platform list for ``username``.

    Returns the raw hits (for the tabular view) plus the entity graph
    (for cytoscape). The frontend picks whichever shape its current
    tab needs.
    """
    try:
        result = await search_username(payload.username)
    except UsernameValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    graph = graph_from_username(result)
    return {
        "username": result.username,
        "checked": result.checked,
        "present_count": result.present_count,
        "hits": [asdict(h) for h in result.hits],
        "graph": _dump_dataclass(graph),
    }


@router.post("/breaches", status_code=status.HTTP_200_OK)
async def investigate_breaches(payload: EmailOrDomainQuery) -> dict:
    """HIBP lookup for an email or domain.

    Returns a well-formed "unavailable" response (HTTP 200) when no key
    is configured, so the frontend can show the feature gate without
    treating it as an error state.
    """
    client = HIBPClient(api_key=settings.get_api_key("hibp"))
    try:
        result = await search_breaches(payload.query, client=client)
    except BreachSearchValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    graph = graph_from_breaches(result)
    return {
        "query": result.query,
        "kind": result.kind,
        "available": result.available,
        "note": result.note,
        "breaches": [asdict(b) for b in result.breaches],
        "graph": _dump_dataclass(graph),
    }


@router.post("/image", status_code=status.HTTP_200_OK)
async def investigate_image(file: UploadFile = File(...)) -> dict:
    """Extract EXIF / GPS / camera metadata from an uploaded image."""
    content = await file.read()
    try:
        result = extract_metadata(
            filename=file.filename or "uploaded",
            content=content,
        )
    except ImageValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    graph = graph_from_image(result)
    return {
        "filename": result.filename,
        "format": result.format,
        "size_px": list(result.size_px),
        "size_bytes": result.size_bytes,
        "exif": result.exif,
        "gps": asdict(result.gps) if result.gps else None,
        "note": result.note,
        "graph": _dump_dataclass(graph),
    }


class PersonQuery(BaseModel):
    email: str = Field(default="", max_length=253)
    name: str = Field(default="", max_length=128)
    org: str = Field(default="", max_length=128)
    location: str = Field(default="", max_length=128)
    handle: str = Field(default="", max_length=64)


@router.post("/person", status_code=status.HTTP_200_OK)
async def investigate_person_route(payload: PersonQuery) -> dict:
    """Aggregate free public sources around an email and/or name."""
    try:
        result = await investigate_person(
            email=payload.email,
            name=payload.name,
            org=payload.org,
            location=payload.location,
            handle=payload.handle,
        )
    except PersonValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    data = asdict(result)
    await _save_investigation(
        "person", payload.email or payload.name, str(data.get("note", "")), data
    )
    return data


_fingerprint_limiter = SlidingWindowLimiter(settings.outbound_fetch_per_minute, 60.0)


async def _fingerprint_ratelimit(request: Request) -> None:
    client = request.client.host if request.client else "unknown"
    if not _fingerprint_limiter.allow(client):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many fingerprint requests; slow down",
        )


class FingerprintQuery(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    authorized: bool = False


@router.post(
    "/fingerprint",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(_fingerprint_ratelimit)],
)
async def investigate_fingerprint(payload: FingerprintQuery) -> dict:
    """Fingerprint a site's tech stack - active recon, authorization-gated."""
    if not payload.authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="authorization acknowledgment required to fingerprint a site",
        )
    result = await fingerprint_site(payload.url)
    data = asdict(result)
    techs = data.get("technologies", [])
    await _save_investigation(
        "fingerprint", payload.url, f"{len(techs)} technologies", data
    )
    return data
