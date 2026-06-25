from fastapi import APIRouter, Body, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from core.inbox.imap_triage import InboxError, triage_inbox
from core.phishing.attachment_scanner import scan_attachment
from core.phishing.header_analyzer import analyze_headers
from core.phishing.url_checker import check_urls
from core.phishing.verdict_engine import generate_verdict

router = APIRouter()


class PhishingResult(BaseModel):
    verdict: str
    confidence: float
    risk_score: int
    headers: dict
    urls: list[dict]
    attachments: list[dict]
    indicators: list[str]
    recommendations: list[str]


@router.post("/analyze", response_model=PhishingResult)
async def analyze_email(file: UploadFile = File(...)) -> PhishingResult:
    """Analyze an email file (.eml) for phishing indicators."""
    content = await file.read()
    raw_email = content.decode("utf-8", errors="replace")

    header_results = analyze_headers(raw_email)
    url_results = await check_urls(raw_email)
    attachment_results = await scan_attachment(raw_email)
    verdict = generate_verdict(header_results, url_results, attachment_results)

    return PhishingResult(
        verdict=verdict["verdict"],
        confidence=verdict["confidence"],
        risk_score=verdict["risk_score"],
        headers=header_results,
        urls=url_results,
        attachments=attachment_results,
        indicators=verdict["indicators"],
        recommendations=verdict["recommendations"],
    )


class InboxQuery(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    username: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=512)
    port: int = 993
    folder: str = "INBOX"
    limit: int = 10


@router.post("/inbox")
async def triage_inbox_route(query: InboxQuery) -> dict:
    """Pull recent messages from a mailbox over IMAPS and analyze each."""
    try:
        messages = await triage_inbox(
            host=query.host,
            username=query.username,
            password=query.password,
            port=query.port,
            folder=query.folder,
            limit=query.limit,
        )
    except InboxError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"messages": messages}


@router.post("/check-url")
async def check_single_url(url: str = Body(..., embed=True)) -> dict:
    """Check a single URL against threat intelligence sources."""
    results = await check_urls(url, single=True)
    return {"url": url, "results": results}
