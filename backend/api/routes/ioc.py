from fastapi import APIRouter, Body, File, UploadFile
from pydantic import BaseModel

from core.ioc.pdf_extractor import extract_from_pdf
from core.ioc.text_extractor import extract_from_text
from core.ioc.email_extractor import extract_from_email
from core.ioc.ioc_validator import validate_and_enrich

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


@router.post("/extract", response_model=IOCExtractionResult)
async def extract_iocs(file: UploadFile = File(...)):
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

    enriched = await validate_and_enrich(raw_iocs)

    stats = {}
    for ioc in enriched:
        stats[ioc["type"]] = stats.get(ioc["type"], 0) + 1

    return IOCExtractionResult(
        source=filename,
        total_iocs=len(enriched),
        iocs=[IOC(**ioc) for ioc in enriched],
        stats=stats,
    )


@router.post("/extract-text", response_model=IOCExtractionResult)
async def extract_iocs_from_text(text: str = Body(..., embed=True)):
    """Extract IOCs from raw text input."""
    raw_iocs = extract_from_text(text)
    enriched = await validate_and_enrich(raw_iocs)

    stats = {}
    for ioc in enriched:
        stats[ioc["type"]] = stats.get(ioc["type"], 0) + 1

    return IOCExtractionResult(
        source="text_input",
        total_iocs=len(enriched),
        iocs=[IOC(**ioc) for ioc in enriched],
        stats=stats,
    )
