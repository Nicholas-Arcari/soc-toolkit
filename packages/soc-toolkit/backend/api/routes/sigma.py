from typing import Any

import yaml
from fastapi import APIRouter, Body, HTTPException
from pydantic import BaseModel, Field

from core.sigma.compiler import SUPPORTED_BACKENDS, compile_rule
from core.sigma.engine import get_engine
from core.sigma.rule import SigmaRule, UnsupportedSigmaFeatureError

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


class SigmaCompileRequest(BaseModel):
    """Compile one rule - either a known ``rule_id`` or inline ``rule_yaml``."""

    rule_id: str | None = None
    rule_yaml: str | None = None
    backend: str = Field(default="splunk")


class SigmaCompileResponse(BaseModel):
    backend: str
    rule_id: str
    title: str
    level: str
    query: str


@router.get("/backends")
async def list_backends() -> dict[str, list[str]]:
    """Return the SIEM backends the compiler currently supports."""
    return {"backends": list(SUPPORTED_BACKENDS)}


@router.post("/compile", response_model=SigmaCompileResponse)
async def compile_rule_to_backend(
    body: SigmaCompileRequest = Body(...),
) -> SigmaCompileResponse:
    """Compile a Sigma rule to a SIEM query string.

    Exactly one of ``rule_id`` or ``rule_yaml`` must be provided. The
    ``rule_id`` path compiles a rule already loaded by the engine; the
    ``rule_yaml`` path lets analysts iterate on a draft without writing
    a file.
    """
    if bool(body.rule_id) == bool(body.rule_yaml):
        raise HTTPException(
            status_code=400,
            detail="provide exactly one of 'rule_id' or 'rule_yaml'",
        )
    if body.backend not in SUPPORTED_BACKENDS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"unsupported backend {body.backend!r}; "
                f"expected one of {list(SUPPORTED_BACKENDS)}"
            ),
        )

    if body.rule_id:
        engine = get_engine()
        rule = next((r for r in engine.rules if r.id == body.rule_id), None)
        if rule is None:
            raise HTTPException(status_code=404, detail=f"rule {body.rule_id!r} not found")
    else:
        try:
            data = yaml.safe_load(body.rule_yaml or "")
        except yaml.YAMLError as exc:
            raise HTTPException(status_code=400, detail=f"invalid YAML: {exc}") from exc
        if not isinstance(data, dict):
            raise HTTPException(status_code=400, detail="rule_yaml must be a YAML mapping")
        try:
            rule = SigmaRule.from_dict(data)
        except UnsupportedSigmaFeatureError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        query = compile_rule(rule, body.backend)
    except UnsupportedSigmaFeatureError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return SigmaCompileResponse(
        backend=body.backend,
        rule_id=rule.id,
        title=rule.title,
        level=rule.level,
        query=query,
    )
