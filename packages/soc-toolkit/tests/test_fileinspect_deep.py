"""Deep file analysis: LSB steganography + OLE-macro extraction."""

import io

from PIL import Image

from core.fileinspector.inspector import _lsb_stego, _ole_macros


def _png_with_lsb(secret: bytes) -> bytes:
    bits: list[int] = []
    for byte in secret:
        for k in range(8):
            bits.append((byte >> (7 - k)) & 1)
    n_pixels = (len(bits) + 2) // 3
    img = Image.new("RGB", (n_pixels, 1), (120, 120, 120))
    px = img.load()
    assert px is not None
    bi = 0
    for x in range(n_pixels):
        chans = [120, 120, 120]
        for c in range(3):
            if bi < len(bits):
                chans[c] = (chans[c] & ~1) | bits[bi]
                bi += 1
        px[x, 0] = (chans[0], chans[1], chans[2])
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_lsb_stego_detects_hidden_text() -> None:
    result = _lsb_stego(_png_with_lsb(b"SECRETFLAG{hidden_message_here}"), "png")
    assert result["suspected"] is True
    assert any("SECRETFLAG" in s for s in result["strings"])


def test_lsb_stego_clean_image() -> None:
    buf = io.BytesIO()
    Image.new("RGB", (40, 40), (10, 20, 30)).save(buf, format="PNG")
    result = _lsb_stego(buf.getvalue(), "png")
    assert result["suspected"] is False


def test_lsb_stego_skips_non_images() -> None:
    result = _lsb_stego(b"%PDF-1.4 fake", "pdf")
    assert result["checked"] is False


def test_ole_macros_graceful_on_non_office() -> None:
    result = _ole_macros(b"just some plain bytes, not an office document")
    assert result["available"] is True
    assert result["has_macros"] is False
