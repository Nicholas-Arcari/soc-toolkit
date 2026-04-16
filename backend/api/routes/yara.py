from fastapi import APIRouter, File, UploadFile
from pydantic import BaseModel

from core.yara.scanner import get_scanner

router = APIRouter()


class YaraMatch(BaseModel):
    rule: str
    namespace: str
    tags: list[str]
    metadata: dict


class YaraScanResult(BaseModel):
    filename: str
    size: int
    match_count: int
    matches: list[YaraMatch]


@router.post("/scan", response_model=YaraScanResult)
async def scan_file(file: UploadFile = File(...)) -> YaraScanResult:
    """Scan an uploaded file against all compiled YARA rules.

    Rules live under backend/rules/yara/. Each match includes the rule name,
    namespace, tags, and metadata (severity, MITRE technique, reference).
    """
    content = await file.read()
    matches = get_scanner().scan(content)

    return YaraScanResult(
        filename=file.filename or "unknown",
        size=len(content),
        match_count=len(matches),
        matches=[YaraMatch(**m) for m in matches],
    )
