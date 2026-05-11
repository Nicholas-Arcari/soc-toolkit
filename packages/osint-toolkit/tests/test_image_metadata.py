"""EXIF extraction tests.

Image payloads are synthesized in-test via Pillow so we don't need a
fixtures/ directory. This also means the tests document what EXIF shape
the extractor expects: if PIL's behavior changes across versions, the
test will fail loudly rather than silently accepting unexpected data.
"""
from __future__ import annotations

import io
from fractions import Fraction

import piexif
import pytest
from PIL import Image

from core.investigate.image_metadata import (
    ImageValidationError,
    extract_metadata,
)


def _png_bytes(size: tuple[int, int] = (4, 4)) -> bytes:
    """Plain PNG, no metadata - default exit path for stripped images."""
    buf = io.BytesIO()
    Image.new("RGB", size, (128, 128, 128)).save(buf, format="PNG")
    return buf.getvalue()


def _jpeg_with_exif(exif_dict: dict) -> bytes:
    """Build a JPEG whose EXIF IFD matches ``exif_dict``."""
    buf = io.BytesIO()
    img = Image.new("RGB", (8, 8), (0, 0, 0))
    img.save(buf, format="JPEG", exif=piexif.dump(exif_dict))
    return buf.getvalue()


def test_empty_payload_rejected() -> None:
    with pytest.raises(ImageValidationError):
        extract_metadata(filename="nothing.jpg", content=b"")


def test_bogus_bytes_rejected() -> None:
    with pytest.raises(ImageValidationError):
        extract_metadata(filename="junk.jpg", content=b"not an image at all")


def test_png_without_exif_returns_note() -> None:
    """Stripped images are the common case - must not error, just explain."""
    result = extract_metadata(filename="stripped.png", content=_png_bytes())

    assert result.format == "PNG"
    assert result.size_px == (4, 4)
    assert result.exif == {}
    assert result.gps is None
    assert "no EXIF" in result.note


def test_jpeg_with_camera_fields_extracted() -> None:
    exif_dict = {
        "0th": {
            piexif.ImageIFD.Make: b"TestCorp",
            piexif.ImageIFD.Model: b"TC-9000",
            piexif.ImageIFD.Software: b"exif-writer/1.0",
            piexif.ImageIFD.DateTime: b"2024:01:15 10:30:00",
        },
        "Exif": {
            piexif.ExifIFD.DateTimeOriginal: b"2024:01:15 10:29:45",
        },
        "GPS": {},
        "1st": {},
        "thumbnail": None,
    }
    payload = _jpeg_with_exif(exif_dict)
    result = extract_metadata(filename="sample.jpg", content=payload)

    assert result.format == "JPEG"
    assert result.exif["camera_make"] == "TestCorp"
    assert result.exif["camera_model"] == "TC-9000"
    assert result.exif["software"] == "exif-writer/1.0"
    assert result.exif["timestamp"] == "2024:01:15 10:30:00"
    assert result.exif["timestamp_original"] == "2024:01:15 10:29:45"
    assert result.gps is None


def test_jpeg_with_gps_converts_to_decimal_degrees() -> None:
    """Leuven, Belgium: 50°52'48"N, 4°42'00"E → (50.88, 4.70) decimal."""
    exif_dict = {
        "0th": {},
        "Exif": {},
        "GPS": {
            piexif.GPSIFD.GPSLatitudeRef: b"N",
            piexif.GPSIFD.GPSLatitude: (
                (50, 1),
                (52, 1),
                (48, 1),
            ),
            piexif.GPSIFD.GPSLongitudeRef: b"E",
            piexif.GPSIFD.GPSLongitude: (
                (4, 1),
                (42, 1),
                (0, 1),
            ),
            piexif.GPSIFD.GPSAltitudeRef: 0,
            piexif.GPSIFD.GPSAltitude: (100, 1),
        },
        "1st": {},
        "thumbnail": None,
    }
    payload = _jpeg_with_exif(exif_dict)
    result = extract_metadata(filename="leuven.jpg", content=payload)

    assert result.gps is not None
    assert result.gps.latitude == pytest.approx(50.88, abs=0.001)
    assert result.gps.longitude == pytest.approx(4.70, abs=0.001)
    assert result.gps.altitude == pytest.approx(100.0)


def test_jpeg_gps_south_hemisphere_is_negative() -> None:
    """Sydney: 33°52'S, 151°12'E - latitude must come out negative."""
    exif_dict = {
        "0th": {},
        "Exif": {},
        "GPS": {
            piexif.GPSIFD.GPSLatitudeRef: b"S",
            piexif.GPSIFD.GPSLatitude: ((33, 1), (52, 1), (0, 1)),
            piexif.GPSIFD.GPSLongitudeRef: b"E",
            piexif.GPSIFD.GPSLongitude: ((151, 1), (12, 1), (0, 1)),
        },
        "1st": {},
        "thumbnail": None,
    }
    result = extract_metadata(filename="sydney.jpg", content=_jpeg_with_exif(exif_dict))

    assert result.gps is not None
    assert result.gps.latitude < 0
    assert result.gps.longitude > 0


def test_jpeg_gps_altitude_below_sea_level() -> None:
    """GPSAltitudeRef=1 → altitude is negative."""
    exif_dict = {
        "0th": {},
        "Exif": {},
        "GPS": {
            piexif.GPSIFD.GPSLatitudeRef: b"N",
            piexif.GPSIFD.GPSLatitude: ((1, 1), (0, 1), (0, 1)),
            piexif.GPSIFD.GPSLongitudeRef: b"E",
            piexif.GPSIFD.GPSLongitude: ((1, 1), (0, 1), (0, 1)),
            piexif.GPSIFD.GPSAltitudeRef: 1,
            piexif.GPSIFD.GPSAltitude: (50, 1),
        },
        "1st": {},
        "thumbnail": None,
    }
    result = extract_metadata(filename="deadsea.jpg", content=_jpeg_with_exif(exif_dict))

    assert result.gps is not None
    assert result.gps.altitude == pytest.approx(-50.0)


def test_oversize_payload_rejected() -> None:
    """Size cap defends the server from huge uploads."""
    with pytest.raises(ImageValidationError):
        extract_metadata(filename="huge.jpg", content=b"\x00" * (26 * 1024 * 1024))


def test_rational_fraction_type_handled() -> None:
    """PIL sometimes emits IFDRational which is a Fraction subclass."""
    # Drive internal helper via a direct GPS tuple containing Fraction values.
    from core.investigate.image_metadata import _dms_to_decimal

    assert _dms_to_decimal((Fraction(50), Fraction(30), Fraction(0)), "N") == pytest.approx(50.5)
    assert _dms_to_decimal((Fraction(50), Fraction(30), Fraction(0)), "S") == pytest.approx(-50.5)
    assert _dms_to_decimal(None, "N") is None
