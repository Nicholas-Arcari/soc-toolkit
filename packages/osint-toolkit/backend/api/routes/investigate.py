"""Investigative OSINT routes.

Distinct persona from target-based scans: the operator has an
identifier (username, email, image) and wants the graph of connected
entities. No DB persistence - investigative lookups are interactive,
not historical. If we ever decide to remember searches, that becomes
an opt-in audit-log toggle rather than the default.
"""
from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, File, HTTPException, UploadFile, status
from pydantic import BaseModel, Field
from sec_common.integrations import HIBPClient

from config import settings
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
from core.investigate.username_search import (
    UsernameValidationError,
    search_username,
)

router = APIRouter()


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
