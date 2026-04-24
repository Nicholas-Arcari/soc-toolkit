from fastapi import APIRouter, Body
from pydantic import BaseModel

from core.ioc.text_extractor import extract_from_text
from core.misp.enricher import enrich_iocs
from integrations.misp import MISPClient

router = APIRouter()


class MISPAttributeLookup(BaseModel):
    value: str
    kind: str  # ip | domain | url | email | md5 | sha1 | sha256


@router.post("/lookup")
async def lookup_attribute(query: MISPAttributeLookup) -> dict:
    """Check a single IOC value against MISP and return matching events."""
    client = MISPClient()
    return await client.check_attribute(query.value, query.kind)


@router.get("/event/{uuid}")
async def get_event(uuid: str) -> dict:
    """Fetch a full MISP event by UUID for pivot/context."""
    client = MISPClient()
    return await client.get_event(uuid)


@router.post("/enrich")
async def enrich(text: str = Body(..., embed=True)) -> dict:
    """Extract IOCs from free text, then enrich each against MISP.

    Returns both the extracted IOC list and the MISP enrichment result so
    the analyst can see coverage (extracted vs. known) in a single call.
    """
    extracted = extract_from_text(text)
    enrichment = await enrich_iocs(extracted)

    return {
        "extracted_count": len(extracted),
        "iocs": extracted,
        "misp": enrichment,
    }
