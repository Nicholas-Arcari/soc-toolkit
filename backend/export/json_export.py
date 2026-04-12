import io
import json


async def export_json(data: dict, report_type: str) -> io.BytesIO:
    """Export analysis results as formatted JSON."""
    output = {
        "report_type": report_type,
        "data": data,
    }
    content = json.dumps(output, indent=2, default=str)
    return io.BytesIO(content.encode("utf-8"))
