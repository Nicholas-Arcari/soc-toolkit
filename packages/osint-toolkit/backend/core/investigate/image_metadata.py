"""EXIF / image metadata extraction.

Pillow (PIL) handles JPEG, TIFF, PNG, HEIF-via-plugin. For a public
release we accept the narrower set (JPEG + TIFF + PNG + WebP) because
those cover the vast majority of OSINT source material and don't pull
in extra binary dependencies.

Only metadata the analyst *asked for* is returned. The raw PIL EXIF
blob contains vendor-specific maker notes that are rarely useful and
often huge - we pull the fields that map to documented EXIF tags and
drop the rest.

GPS coordinates are the headline feature for OSINT: many consumer
cameras embed lat/lon, and stripping these before publishing images is
a common OPSEC failure. We convert the raw DMS rationals into decimal
degrees with the hemisphere applied so the UI can plot a point
directly.
"""
from __future__ import annotations

import io
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Any

from PIL import ExifTags, Image, UnidentifiedImageError


@dataclass
class GPSCoords:
    latitude: float
    longitude: float
    altitude: float | None = None


@dataclass
class ImageMetadataResult:
    filename: str
    format: str  # e.g. "JPEG", "PNG"
    size_px: tuple[int, int]
    size_bytes: int
    # Subset of EXIF fields that are OSINT-relevant. Anything unset is
    # left out of the dict; the UI renders only present keys.
    exif: dict[str, str] = field(default_factory=dict)
    gps: GPSCoords | None = None
    note: str = ""


# Tags we surface. IFD numbers match PIL's ``ExifTags.TAGS`` mapping.
# Keeping this allowlist explicit means vendor maker-notes, thumbnails,
# and anything PIL doesn't understand is silently dropped.
_OSINT_TAGS: dict[str, str] = {
    "Make": "camera_make",
    "Model": "camera_model",
    "DateTime": "timestamp",
    "DateTimeOriginal": "timestamp_original",
    "DateTimeDigitized": "timestamp_digitized",
    "Software": "software",
    "Artist": "artist",
    "Copyright": "copyright",
    "ImageDescription": "description",
    "LensModel": "lens_model",
    "GPSDateStamp": "gps_date",
}

_MAX_BYTES = 25 * 1024 * 1024  # 25 MB cap - EXIF is small, but the file isn't


class ImageValidationError(ValueError):
    """Raised when the input is too large, missing, or not a real image."""


def _rational_to_float(value: Any) -> float:
    """PIL returns GPS values as IFDRational / tuple-of-rationals.

    Normalize to float; fall back to ``0.0`` on malformed input rather
    than raising - a corrupt GPS tag shouldn't kill the whole extract.
    """
    try:
        if isinstance(value, Fraction):
            return float(value)
        if isinstance(value, tuple) and len(value) == 2:
            num, denom = value
            return float(num) / float(denom) if denom else 0.0
        return float(value)
    except (TypeError, ValueError, ZeroDivisionError):
        return 0.0


def _dms_to_decimal(dms: Any, ref: str | None) -> float | None:
    """Convert (degrees, minutes, seconds) + hemisphere → signed decimal.

    ``dms`` arrives as a 3-tuple of IFDRational from PIL. Returns
    ``None`` when the structure isn't what we expect - GPS tags from
    stripped images or non-conforming writers can be partial.
    """
    try:
        degrees, minutes, seconds = dms
    except (TypeError, ValueError):
        return None

    decimal = (
        _rational_to_float(degrees)
        + _rational_to_float(minutes) / 60.0
        + _rational_to_float(seconds) / 3600.0
    )
    if ref in ("S", "W"):
        decimal = -decimal
    return decimal


def _extract_gps(gps_ifd: dict[int, Any]) -> GPSCoords | None:
    """Pull GPSLatitude/Longitude/Altitude into ``GPSCoords`` or None."""
    inv = {v: k for k, v in ExifTags.GPSTAGS.items()}
    lat_key, lat_ref_key = inv.get("GPSLatitude"), inv.get("GPSLatitudeRef")
    lon_key, lon_ref_key = inv.get("GPSLongitude"), inv.get("GPSLongitudeRef")
    alt_key, alt_ref_key = inv.get("GPSAltitude"), inv.get("GPSAltitudeRef")

    if lat_key is None or lon_key is None:
        return None

    lat = _dms_to_decimal(gps_ifd.get(lat_key), gps_ifd.get(lat_ref_key or -1))
    lon = _dms_to_decimal(gps_ifd.get(lon_key), gps_ifd.get(lon_ref_key or -1))
    if lat is None or lon is None:
        return None

    altitude: float | None = None
    if alt_key is not None and alt_key in gps_ifd:
        altitude = _rational_to_float(gps_ifd[alt_key])
        # GPSAltitudeRef=1 means below sea level. Readers vary in how
        # they return the ref: int 1, bytes b"\x01", or sometimes the
        # raw numeric. Treat any of those as "below sea level".
        raw_ref = gps_ifd.get(alt_ref_key) if alt_ref_key is not None else None
        if raw_ref in (1, b"\x01") or raw_ref == b"1":
            altitude = -altitude

    return GPSCoords(latitude=lat, longitude=lon, altitude=altitude)


def extract_metadata(*, filename: str, content: bytes) -> ImageMetadataResult:
    """Parse ``content`` and return structured EXIF metadata.

    Accepts raw bytes rather than a path so the API route can hand off
    the UploadFile payload directly. Raises :class:`ImageValidationError`
    for input that isn't a recognizable image or exceeds the size cap.
    """
    if not content:
        raise ImageValidationError("empty payload")
    if len(content) > _MAX_BYTES:
        raise ImageValidationError(f"image exceeds {_MAX_BYTES // (1024 * 1024)} MB cap")

    try:
        image = Image.open(io.BytesIO(content))
        image.load()
    except (UnidentifiedImageError, OSError) as exc:
        raise ImageValidationError(f"not a recognizable image: {exc}") from exc

    exif_fields: dict[str, str] = {}
    gps: GPSCoords | None = None
    note = ""

    # PIL's getexif() returns an ``Image.Exif`` object. For PNGs without
    # EXIF, this is an empty mapping - iterate safely.
    try:
        exif_obj = image.getexif()
    except Exception:  # pragma: no cover - PIL is permissive, defensive only
        exif_obj = None

    if exif_obj:
        inv = {v: k for k, v in ExifTags.TAGS.items()}
        # Tags like DateTimeOriginal / LensModel live in the Exif sub-IFD
        # (0x8769), not the top-level 0th IFD. Merge both maps so the
        # allowlist lookup finds either location.
        exif_sub = exif_obj.get_ifd(0x8769) or {}
        merged: dict[int, object] = {**dict(exif_obj), **exif_sub}
        for tag_name, out_key in _OSINT_TAGS.items():
            tag_id = inv.get(tag_name)
            if tag_id is None:
                continue
            raw = merged.get(tag_id)
            if raw is None:
                continue
            # Coerce bytes → str (some writers store ASCII fields as
            # null-terminated byte strings).
            if isinstance(raw, bytes):
                raw = raw.rstrip(b"\x00").decode("utf-8", errors="replace")
            exif_fields[out_key] = str(raw).strip()

        # GPS IFD lives under a separate tag. get_ifd() returns an empty
        # dict when no GPS data is embedded - safer than catching KeyError.
        gps_tag_id = inv.get("GPSInfo")
        if gps_tag_id is not None:
            gps_ifd = exif_obj.get_ifd(gps_tag_id)
            if gps_ifd:
                gps = _extract_gps(gps_ifd)

    if not exif_fields and gps is None:
        note = "no EXIF metadata present (may have been stripped)"

    return ImageMetadataResult(
        filename=filename,
        format=image.format or "unknown",
        size_px=image.size,
        size_bytes=len(content),
        exif=exif_fields,
        gps=gps,
        note=note,
    )
