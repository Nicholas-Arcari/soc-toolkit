from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from export.report_export import export_json, export_pdf

router = APIRouter()


class ExportRequest(BaseModel):
    data: dict
    report_type: str = Field(min_length=1, max_length=64)
    format: str = "json"


@router.post("/export")
async def export_report(request: ExportRequest) -> StreamingResponse:
    """Export an investigative result as JSON or PDF (data-driven)."""
    exporters = {"json": export_json, "pdf": export_pdf}
    fmt = request.format if request.format in exporters else "json"
    result = await exporters[fmt](request.data, request.report_type)
    media = {"json": "application/json", "pdf": "application/pdf"}
    filename = f"osint_{request.report_type}.{fmt}"
    return StreamingResponse(
        result,
        media_type=media[fmt],
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
