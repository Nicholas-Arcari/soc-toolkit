from typing import Any

from fastapi import APIRouter, Body
from pydantic import BaseModel

from core.sigma.engine import get_engine

router = APIRouter()


class SigmaMatchResponse(BaseModel):
    rule_id: str
    title: str
    level: str
    tags: list[str]
    description: str
    event: dict[str, Any]


class SigmaEvaluationResult(BaseModel):
    event_count: int
    match_count: int
    matches: list[SigmaMatchResponse]


@router.get("/rules")
async def list_rules() -> dict:
    """Return metadata for every loaded Sigma rule (id, title, level, tags)."""
    engine = get_engine()
    return {
        "rule_count": len(engine.rules),
        "rules": [
            {
                "id": r.id,
                "title": r.title,
                "level": r.level,
                "tags": r.tags,
                "description": r.description,
                "logsource": r.logsource,
            }
            for r in engine.rules
        ],
    }


@router.post("/evaluate", response_model=SigmaEvaluationResult)
async def evaluate_events(
    events: list[dict[str, Any]] = Body(..., embed=True),
) -> SigmaEvaluationResult:
    """Evaluate a batch of normalised log events against all Sigma rules.

    Expected event shape is the dict produced by our log analyzers (ssh,
    web, windows) - fields like ``event_id``, ``event_type``, ``source_ip``,
    ``request_uri``, etc.
    """
    engine = get_engine()
    matches = engine.evaluate_batch(events)

    return SigmaEvaluationResult(
        event_count=len(events),
        match_count=len(matches),
        matches=[SigmaMatchResponse(**m.__dict__) for m in matches],
    )
