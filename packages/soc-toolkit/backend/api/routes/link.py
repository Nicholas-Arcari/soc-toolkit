from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sec_common.ratelimit import SlidingWindowLimiter

from config import settings
from core.linktrace.tracer import trace_redirects

router = APIRouter()

# Per-IP cap so the redirect tracer can't be driven as a scanning proxy.
_limiter = SlidingWindowLimiter(settings.outbound_fetch_per_minute, 60.0)


async def _ratelimit(request: Request) -> None:
    client = request.client.host if request.client else "unknown"
    if not _limiter.allow(client):
        raise HTTPException(status_code=429, detail="too many link traces; slow down")


@router.post("/trace", dependencies=[Depends(_ratelimit)])
async def trace_link(url: str = Body(..., embed=True)) -> dict:
    """Follow a URL's redirect chain to reveal where a shortened link lands."""
    return await trace_redirects(url)
