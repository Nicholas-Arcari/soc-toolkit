from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from export.json_export import export_json
from export.csv_export import export_csv
from export.pdf_export import export_pdf

router = APIRouter()


class ExportRequest(BaseModel):
    data: dict
    report_type: str
    format: str = "json"


@router.post("/export")
async def export_report(request: ExportRequest):
    """
    Export analysis results in JSON, CSV, or PDF format.

    report_type: phishing, logs, ioc
    format: json, csv, pdf
    """
    exporters = {
        "json": export_json,
        "csv": export_csv,
        "pdf": export_pdf,
    }

    exporter = exporters.get(request.format, export_json)
    result = await exporter(request.data, request.report_type)

    media_types = {
        "json": "application/json",
        "csv": "text/csv",
        "pdf": "application/pdf",
    }

    filename = f"soc_report_{request.report_type}.{request.format}"

    return StreamingResponse(
        result,
        media_type=media_types[request.format],
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
