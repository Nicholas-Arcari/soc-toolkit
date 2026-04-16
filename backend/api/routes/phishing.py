from fastapi import APIRouter, Body, File, UploadFile
from pydantic import BaseModel

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


@router.post("/check-url")
async def check_single_url(url: str = Body(..., embed=True)) -> dict:
    """Check a single URL against threat intelligence sources."""
    results = await check_urls(url, single=True)
    return {"url": url, "results": results}
