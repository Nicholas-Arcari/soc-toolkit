"""Generic investigative-result export (JSON + PDF)."""

import pytest

from export.report_export import export_json, export_pdf


@pytest.mark.asyncio
async def test_export_json_envelope() -> None:
    out = await export_json({"email": "a@b.com"}, "person")
    body = out.getvalue()
    assert b'"report_type": "person"' in body
    assert b"a@b.com" in body


@pytest.mark.asyncio
async def test_export_pdf_is_valid_pdf() -> None:
    out = await export_pdf(
        {"email": "a@b.com", "breaches": [{"name": "X", "date": "2021"}]},
        "person",
    )
    assert out.getvalue()[:4] == b"%PDF"
