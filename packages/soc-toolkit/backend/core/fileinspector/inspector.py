"""Static file inspector.

Answers "is this download/setup actually a trojan?" with pure static
analysis - the file is never executed. Combines:

- magic-byte type detection + extension/content mismatch
- polyglot / appended-data detection (payload after a container's end)
- dangerous + double extensions (reused from the phishing scanner)
- embedded IOCs and script/command markers
- a local YARA scan (reused engine)
- an OOXML VBA-macro heuristic
- hash reputation (VirusTotal + MalwareBazaar, both degrade without a key)

…aggregated into a verdict (clean / suspicious / malicious) with reasons.
"""
from __future__ import annotations

import hashlib
import io
import re
import zipfile
from typing import Any

from core.phishing.attachment_scanner import (
    _check_malwarebazaar,
    _check_virustotal,
    _has_double_extension,
    _is_suspicious_extension,
)
from core.yara.scanner import get_scanner

# Magic-byte signatures → label. Dependency-free (no libmagic); covers the
# types that matter for "is this executable / a container hiding something".
_SIGNATURES: list[tuple[bytes, str]] = [
    (b"MZ", "windows-pe"),
    (b"\x7fELF", "elf"),
    (b"\xca\xfe\xba\xbe", "macho"),
    (b"\xfe\xed\xfa", "macho"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip"),  # also ooxml / jar / apk / odf
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"\xd0\xcf\x11\xe0", "ole-compound"),  # legacy office / msi
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF8", "gif"),
    (b"BM", "bmp"),
    (b"II*\x00", "tiff"),
    (b"MM\x00*", "tiff"),
    (b"RIFF", "riff"),  # webp / wav / avi
]

# Extension → magic type(s) we'd expect. Mismatch is a strong signal
# (e.g. invoice.pdf whose bytes are a Windows PE).
_EXT_EXPECTED: dict[str, set[str]] = {
    "exe": {"windows-pe"}, "dll": {"windows-pe"}, "scr": {"windows-pe"},
    "msi": {"ole-compound"},
    "pdf": {"pdf"},
    "png": {"png"}, "jpg": {"jpeg"}, "jpeg": {"jpeg"}, "gif": {"gif"},
    "bmp": {"bmp"}, "webp": {"riff"}, "tif": {"tiff"}, "tiff": {"tiff"},
    "zip": {"zip"}, "jar": {"zip"}, "apk": {"zip"},
    "docx": {"zip"}, "xlsx": {"zip"}, "pptx": {"zip"},
    "docm": {"zip"}, "xlsm": {"zip"}, "pptm": {"zip"},
    "doc": {"ole-compound"}, "xls": {"ole-compound"}, "ppt": {"ole-compound"},
    "rar": {"rar"}, "7z": {"7z"}, "gz": {"gzip"},
}

# Embedded-indicator extraction is capped to this window to bound cost on
# very large installers (markers/strings are typically near the start/tail).
_SCAN_WINDOW = 8 * 1024 * 1024

_URL_RE = re.compile(rb"https?://[^\s\"'<>)}\]]{4,}", re.IGNORECASE)
_IPV4_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SCRIPT_MARKERS = [
    b"powershell", b"cmd.exe", b"-enc", b"frombase64string",
    b"invoke-expression", b"iex(", b"createobject", b"wscript.shell",
    b"eval(", b"<script", b"document.write", b"shellexecute", b"rundll32",
]


def detect_type(content: bytes) -> str:
    """Best-effort file type from magic bytes, with a text fallback."""
    for signature, label in _SIGNATURES:
        if content.startswith(signature):
            return label
    head = content[:512]
    if head.startswith(b"#!"):
        return "script-shebang"
    if _looks_text(head):
        return "text"
    return "unknown"


def _looks_text(data: bytes) -> bool:
    if not data:
        return True
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data) > 0.9


def _trailing_bytes(content: bytes, file_type: str) -> int:
    """Bytes after a container's logical end - classic polyglot/appended payload."""
    if file_type == "png":
        idx = content.rfind(b"IEND")
        return len(content) - (idx + 8) if idx != -1 else 0  # IEND + 4-byte CRC
    if file_type == "jpeg":
        idx = content.rfind(b"\xff\xd9")
        return len(content) - (idx + 2) if idx != -1 else 0
    if file_type == "gif":
        idx = content.rfind(b"\x3b")
        return len(content) - (idx + 1) if idx != -1 else 0
    if file_type == "pdf":
        idx = content.rfind(b"%%EOF")
        if idx == -1:
            return 0
        return len(content[idx + 5:].strip(b"\r\n \t"))
    return 0


def _zip_has_macros(content: bytes) -> bool:
    """OOXML VBA-macro heuristic: a vbaProject.bin member inside the zip."""
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            return any(name.endswith("vbaProject.bin") for name in zf.namelist())
    except (zipfile.BadZipFile, OSError):
        return False


def _embedded_indicators(content: bytes) -> dict[str, list[str]]:
    region = content if len(content) <= _SCAN_WINDOW else content[:_SCAN_WINDOW]
    urls = sorted({m.decode("latin-1", "ignore") for m in _URL_RE.findall(region)})[:50]
    ips = sorted(
        ip
        for ip in {m.decode() for m in _IPV4_RE.findall(region)}
        if all(o.isdigit() and int(o) <= 255 for o in ip.split("."))
    )[:50]
    lowered = region.lower()
    markers = sorted({m.decode() for m in _SCRIPT_MARKERS if m in lowered})
    return {"urls": urls, "ips": ips, "script_markers": markers}


_IMAGE_TYPES = frozenset({"png", "jpeg", "gif", "bmp", "webp"})


def _ascii_strings(data: bytes, min_len: int) -> list[str]:
    result: list[str] = []
    current: list[str] = []
    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
            continue
        if len(current) >= min_len:
            result.append("".join(current))
        current = []
    if len(current) >= min_len:
        result.append("".join(current))
    return result


def _lsb_stego(content: bytes, file_type: str) -> dict[str, Any]:
    """Heuristic LSB-steganography check: pull the LSB plane of an image and
    look for hidden ASCII text. Catches naive (unencrypted) LSB embedders;
    an encrypted payload looks random and won't trip it.
    """
    if file_type not in _IMAGE_TYPES:
        return {"checked": False, "suspected": False, "strings": []}
    try:
        from PIL import Image

        img = Image.open(io.BytesIO(content)).convert("RGB")
    except Exception:
        return {"checked": False, "suspected": False, "strings": []}

    raw = img.tobytes()  # flat R,G,B,R,G,B,... bytes
    limit = 4096 * 8  # inspect ~the first 4 KB of any hidden payload
    bits = bytes(channel & 1 for channel in raw[:limit])

    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        out.append(byte)

    strings = _ascii_strings(bytes(out), min_len=12)[:5]
    return {"checked": True, "suspected": bool(strings), "strings": strings}


def _ole_macros(content: bytes) -> dict[str, Any]:
    """Real VBA-macro extraction via oletools (OLE .doc/.xls + OOXML .docm)."""
    empty = {"available": True, "has_macros": False, "autoexec": [], "suspicious": []}
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        return {**empty, "available": False}
    parser = None
    try:
        parser = VBA_Parser("upload", data=content)
        # Only trust real office containers; olevba's text mode treats any
        # text as VBA source and would false-positive.
        if getattr(parser, "type", None) not in (
            "OLE",
            "OpenXML",
            "Word2003_XML",
            "MHTML",
        ):
            return empty
        if not parser.detect_vba_macros():
            return empty
        autoexec: list[str] = []
        suspicious: list[str] = []
        for kw_type, keyword, _desc in parser.analyze_macros():
            if kw_type == "AutoExec":
                autoexec.append(keyword)
            elif kw_type == "Suspicious":
                suspicious.append(keyword)
        return {
            "available": True,
            "has_macros": True,
            "autoexec": sorted(set(autoexec))[:10],
            "suspicious": sorted(set(suspicious))[:10],
        }
    except Exception:
        return empty
    finally:
        if parser is not None:
            try:
                parser.close()
            except Exception:
                pass


def _verdict(report: dict[str, Any]) -> tuple[str, int, list[str]]:
    reasons: list[str] = []
    score = 0

    for match in report["yara_matches"]:
        severity = str(match.get("metadata", {}).get("severity", "")).lower()
        if severity in ("critical", "high"):
            reasons.append(f"YARA match: {match.get('rule')} ({severity})")
            score += 50

    vt = report["virustotal"]
    if isinstance(vt, dict) and vt.get("positives", 0) > 2:
        reasons.append(f"VirusTotal: {vt['positives']} engines flagged it")
        score += 50

    mb = report["malwarebazaar"]
    if isinstance(mb, dict) and mb.get("found"):
        reasons.append("Known malware sample on MalwareBazaar")
        score += 50

    if report["type_mismatch"]:
        reasons.append(
            f"Content is {report['detected_type']} but the extension is "
            f".{report['extension'] or '(none)'}"
        )
        score += 25

    if report["double_extension"]:
        reasons.append("Double extension (e.g. invoice.pdf.exe)")
        score += 25

    if report["suspicious_extension"]:
        reasons.append(f"Executable/dangerous extension: .{report['extension']}")
        score += 15

    macro = report["macro_analysis"]
    if macro["has_macros"]:
        if macro["autoexec"]:
            reasons.append(
                "VBA macros with auto-execution: "
                + ", ".join(macro["autoexec"][:5])
            )
            score += 35
        else:
            reasons.append("Embedded VBA macros")
            score += 20
        if macro["suspicious"]:
            reasons.append(
                "Suspicious macro calls: " + ", ".join(macro["suspicious"][:5])
            )
            score += 20
    elif report["macros"]:
        reasons.append("Embedded Office VBA macros")
        score += 20

    if report["stego"]["suspected"]:
        sample = ", ".join(s[:40] for s in report["stego"]["strings"][:2])
        reasons.append(f"Possible LSB-hidden text in the image: {sample}")
        score += 20

    if report["trailing_bytes"] > 0:
        reasons.append(
            f"{report['trailing_bytes']} bytes appended after the "
            f"{report['detected_type']} end (possible polyglot/hidden payload)"
        )
        score += 20

    markers = report["embedded"]["script_markers"]
    if markers:
        reasons.append("Script/command markers in content: " + ", ".join(markers[:5]))
        score += 10

    score = min(score, 100)
    if score >= 50:
        verdict = "malicious"
    elif score >= 20:
        verdict = "suspicious"
    else:
        verdict = "clean"
    return verdict, score, reasons


async def inspect_file(filename: str, content: bytes) -> dict[str, Any]:
    """Run all static checks on ``content`` and return a verdict report."""
    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    detected_type = detect_type(content)
    expected = _EXT_EXPECTED.get(extension)
    type_mismatch = (
        expected is not None
        and detected_type not in expected
        and detected_type != "unknown"
    )
    sha256 = hashlib.sha256(content).hexdigest()

    report: dict[str, Any] = {
        "filename": filename,
        "size": len(content),
        "extension": extension,
        "detected_type": detected_type,
        "type_mismatch": type_mismatch,
        "suspicious_extension": _is_suspicious_extension(filename),
        "double_extension": _has_double_extension(filename),
        "macros": _zip_has_macros(content) if detected_type == "zip" else False,
        "macro_analysis": (
            _ole_macros(content)
            if detected_type == "zip"
            or content[:8].startswith(b"\xd0\xcf\x11\xe0")
            else {
                "available": True,
                "has_macros": False,
                "autoexec": [],
                "suspicious": [],
            }
        ),
        "stego": _lsb_stego(content, detected_type),
        "trailing_bytes": _trailing_bytes(content, detected_type),
        "hashes": {
            "md5": hashlib.md5(content, usedforsecurity=False).hexdigest(),
            "sha1": hashlib.sha1(content, usedforsecurity=False).hexdigest(),
            "sha256": sha256,
        },
        "embedded": _embedded_indicators(content),
        "yara_matches": get_scanner().scan(content),
        "virustotal": await _check_virustotal(sha256),
        "malwarebazaar": await _check_malwarebazaar(sha256),
    }

    verdict, risk_score, reasons = _verdict(report)
    report["verdict"] = verdict
    report["risk_score"] = risk_score
    report["reasons"] = reasons
    return report
