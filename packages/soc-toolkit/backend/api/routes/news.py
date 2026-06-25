from fastapi import APIRouter, Query
from pydantic import BaseModel

from core.news.feeds import NewsItem, fetch_news

router = APIRouter()


class NewsResponse(BaseModel):
    count: int
    items: list[NewsItem]


@router.get("", response_model=NewsResponse)
async def latest_news(
    limit: int = Query(default=40, ge=1, le=100),
) -> NewsResponse:
    """Aggregated, newest-first security news from curated free feeds."""
    items = await fetch_news(limit=limit)
    return NewsResponse(count=len(items), items=items)
