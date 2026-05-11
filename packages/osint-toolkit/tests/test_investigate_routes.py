"""End-to-end API tests for /api/investigate.

The individual modules have unit tests; these assert the route wiring,
response shape, and validation status codes so the frontend contract is
stable.
"""
from __future__ import annotations

import io

import piexif
import respx
from httpx import AsyncClient, Response
from PIL import Image


async def test_username_route_returns_graph_and_hits(client: AsyncClient) -> None:
    # Monkeypatch the module-level platform list is fragile; instead we
    # rely on the fact that all unmocked requests are passed through
    # to respx, and mock every URL in _PLATFORMS. Keeping this narrow
    # keeps the test focused.
    async with respx.mock(assert_all_called=False) as mock:
        # Only GitHub returns 200; all other calls in _PLATFORMS resolve
        # to 404 via a catch-all pattern.
        mock.get("https://github.com/testuser").mock(
            return_value=Response(200, text="profile")
        )
        mock.route().mock(return_value=Response(404))

        resp = await client.post(
            "/api/investigate/username", json={"username": "testuser"}
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == "testuser"
    assert body["present_count"] >= 1
    assert "graph" in body
    assert any(n["type"] == "platform" for n in body["graph"]["nodes"])


async def test_username_route_422_for_invalid_input(client: AsyncClient) -> None:
    resp = await client.post("/api/investigate/username", json={"username": "bad/name"})
    assert resp.status_code == 422


async def test_breaches_route_degraded_without_key(client: AsyncClient) -> None:
    """Without HIBP_API_KEY in the environment the route must not error.

    The fixture env has no HIBP key, so this exercises the real
    degraded path - no monkeypatching needed.
    """
    resp = await client.post(
        "/api/investigate/breaches", json={"query": "user@example.com"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["available"] is False
    assert body["kind"] == "email"
    assert body["breaches"] == []
    assert "HIBP" in body["note"]


async def test_breaches_route_422_for_garbage_input(client: AsyncClient) -> None:
    resp = await client.post("/api/investigate/breaches", json={"query": "nonsense"})
    assert resp.status_code == 422


async def test_image_route_accepts_png(client: AsyncClient) -> None:
    buf = io.BytesIO()
    Image.new("RGB", (8, 8), (255, 0, 0)).save(buf, format="PNG")

    resp = await client.post(
        "/api/investigate/image",
        files={"file": ("red.png", buf.getvalue(), "image/png")},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["format"] == "PNG"
    assert body["size_px"] == [8, 8]
    assert body["gps"] is None
    assert "graph" in body


async def test_image_route_extracts_gps_from_jpeg(client: AsyncClient) -> None:
    exif_dict = {
        "0th": {},
        "Exif": {},
        "GPS": {
            piexif.GPSIFD.GPSLatitudeRef: b"N",
            piexif.GPSIFD.GPSLatitude: ((40, 1), (45, 1), (0, 1)),
            piexif.GPSIFD.GPSLongitudeRef: b"W",
            piexif.GPSIFD.GPSLongitude: ((73, 1), (59, 1), (0, 1)),
        },
        "1st": {},
        "thumbnail": None,
    }
    buf = io.BytesIO()
    Image.new("RGB", (8, 8), (0, 255, 0)).save(buf, format="JPEG", exif=piexif.dump(exif_dict))

    resp = await client.post(
        "/api/investigate/image",
        files={"file": ("nyc.jpg", buf.getvalue(), "image/jpeg")},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["gps"] is not None
    assert body["gps"]["latitude"] > 40
    assert body["gps"]["longitude"] < 0  # West hemisphere


async def test_image_route_422_for_non_image(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/investigate/image",
        files={"file": ("junk.bin", b"not an image", "application/octet-stream")},
    )
    assert resp.status_code == 422
