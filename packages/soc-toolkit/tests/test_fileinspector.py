"""Static file-inspector checks (network reputation calls mocked)."""

import io
import zipfile
from collections.abc import Iterator
from unittest.mock import AsyncMock, patch

import pytest

from core.fileinspector.inspector import detect_type, inspect_file


@pytest.fixture(autouse=True)
def _no_reputation_network() -> Iterator[None]:
    """Stub the VirusTotal/MalwareBazaar lookups so tests never hit the net."""
    with (
        patch(
            "core.fileinspector.inspector._check_virustotal",
            AsyncMock(return_value=None),
        ),
        patch(
            "core.fileinspector.inspector._check_malwarebazaar",
            AsyncMock(return_value=None),
        ),
    ):
        yield


def test_detect_type_from_magic_bytes() -> None:
    assert detect_type(b"MZ\x90\x00") == "windows-pe"
    assert detect_type(b"%PDF-1.7") == "pdf"
    assert detect_type(b"\x89PNG\r\n\x1a\n") == "png"
    assert detect_type(b"PK\x03\x04") == "zip"
    assert detect_type(b"just plain text") == "text"


@pytest.mark.asyncio
async def test_extension_content_mismatch_flagged() -> None:
    report = await inspect_file("invoice.pdf", b"MZ\x90\x00" + b"\x00" * 64)
    assert report["detected_type"] == "windows-pe"
    assert report["type_mismatch"] is True
    assert report["verdict"] in ("suspicious", "malicious")
    assert any("Content is" in reason for reason in report["reasons"])


@pytest.mark.asyncio
async def test_trailing_data_after_png_is_polyglot() -> None:
    png = (
        b"\x89PNG\r\n\x1a\n" + b"\x00" * 8 + b"IEND" + b"\xae\x42\x60\x82"
        + b"APPENDED_PAYLOAD"
    )
    report = await inspect_file("pic.png", png)
    assert report["detected_type"] == "png"
    assert report["trailing_bytes"] == len(b"APPENDED_PAYLOAD")
    assert report["verdict"] in ("suspicious", "malicious")


@pytest.mark.asyncio
async def test_ooxml_macro_detected() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<xml/>")
        zf.writestr("word/vbaProject.bin", b"\x00\x01")
    report = await inspect_file("doc.docm", buf.getvalue())
    assert report["detected_type"] == "zip"
    assert report["macros"] is True


@pytest.mark.asyncio
async def test_embedded_indicators_extracted() -> None:
    blob = b"see http://evil.example/p then powershell -enc AAAA from 8.8.8.8"
    report = await inspect_file("notes.txt", blob)
    assert "http://evil.example/p" in report["embedded"]["urls"]
    assert "8.8.8.8" in report["embedded"]["ips"]
    assert "powershell" in report["embedded"]["script_markers"]


@pytest.mark.asyncio
async def test_clean_file_is_clean() -> None:
    report = await inspect_file("readme.txt", b"just some harmless notes\n")
    assert report["verdict"] == "clean"
    assert report["risk_score"] == 0
    assert report["reasons"] == []
