from fastapi import APIRouter, Body, File, UploadFile
from pydantic import BaseModel
from sec_common.integrations import (
    AbuseIPDBClient,
    AlienVaultOTXClient,
    VirusTotalClient,
)
from sec_common.ioc import extract_from_text, validate_and_enrich

from config import settings
from core.ioc.email_extractor import extract_from_email
from core.ioc.pdf_extractor import extract_from_pdf

router = APIRouter()


class IOC(BaseModel):
    type: str
    value: str
    context: str | None = None
    enrichment: dict | None = None
    malicious: bool | None = None


class IOCExtractionResult(BaseModel):
    source: str
    total_iocs: int
    iocs: list[IOC]
    stats: dict


def _build_enrichment_clients() -> tuple[VirusTotalClient, AbuseIPDBClient, AlienVaultOTXClient]:
    """Settings → DI wiring for the shared IOC validator."""
    return (
        VirusTotalClient(api_key=settings.get_api_key("virustotal")),
        AbuseIPDBClient(api_key=settings.get_api_key("abuseipdb")),
        AlienVaultOTXClient(api_key=settings.get_api_key("otx")),
    )


@router.post("/extract", response_model=IOCExtractionResult)
async def extract_iocs(file: UploadFile = File(...)) -> IOCExtractionResult:
    """
    Extract IOCs from a file (PDF threat report, .eml email, or plain text).

    Supported formats: .pdf, .eml, .txt, .html, .csv
    """
    content = await file.read()
    filename = file.filename or "unknown"

    if filename.endswith(".pdf"):
        raw_iocs = extract_from_pdf(content)
    elif filename.endswith(".eml"):
        raw_iocs = extract_from_email(content.decode("utf-8", errors="replace"))
    else:
        raw_iocs = extract_from_text(content.decode("utf-8", errors="replace"))

    vt, abuseipdb, otx = _build_enrichment_clients()
    enriched = await validate_and_enrich(raw_iocs, vt=vt, abuseipdb=abuseipdb, otx=otx)

    stats: dict[str, int] = {}
    for ioc in enriched:
        stats[ioc["type"]] = stats.get(ioc["type"], 0) + 1

    return IOCExtractionResult(
        source=filename,
        total_iocs=len(enriched),
        iocs=[IOC(**ioc) for ioc in enriched],
        stats=stats,
    )


@router.post("/extract-text", response_model=IOCExtractionResult)
async def extract_iocs_from_text(text: str = Body(..., embed=True)) -> IOCExtractionResult:
    """Extract IOCs from raw text input."""
    raw_iocs = extract_from_text(text)
    vt, abuseipdb, otx = _build_enrichment_clients()
    enriched = await validate_and_enrich(raw_iocs, vt=vt, abuseipdb=abuseipdb, otx=otx)

    stats: dict[str, int] = {}
    for ioc in enriched:
        stats[ioc["type"]] = stats.get(ioc["type"], 0) + 1

    return IOCExtractionResult(
        source="text_input",
        total_iocs=len(enriched),
        iocs=[IOC(**ioc) for ioc in enriched],
        stats=stats,
    )
