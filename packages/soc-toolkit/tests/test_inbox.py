"""IMAP inbox triage: header decode, SSRF guard, route wiring."""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from api.app import app
from core.inbox.imap_triage import InboxError, _decode, triage_inbox


def test_decode_handles_encoded_words() -> None:
    assert _decode("Hello") == "Hello"
    assert _decode(None) == ""
    assert _decode("=?utf-8?B?SGVsbG8=?=") == "Hello"


@pytest.mark.asyncio
async def test_triage_blocks_private_host() -> None:
    with pytest.raises(InboxError):
        await triage_inbox(host="127.0.0.1", username="u", password="p")


def test_inbox_route_returns_messages() -> None:
    client = TestClient(app)
    fake = AsyncMock(return_value=[{"subject": "Hi", "verdict": "clean"}])
    with patch("api.routes.phishing.triage_inbox", fake):
        r = client.post(
            "/api/phishing/inbox",
            json={"host": "imap.example.com", "username": "u", "password": "p"},
        )
    assert r.status_code == 200
    assert r.json()["messages"][0]["subject"] == "Hi"


def test_inbox_route_maps_error_to_400() -> None:
    client = TestClient(app)
    fake = AsyncMock(side_effect=InboxError("login failed"))
    with patch("api.routes.phishing.triage_inbox", fake):
        r = client.post(
            "/api/phishing/inbox",
            json={"host": "imap.example.com", "username": "u", "password": "x"},
        )
    assert r.status_code == 400
