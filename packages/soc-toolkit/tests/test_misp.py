"""MISP client and enricher tests.

All network I/O is mocked - we only test the translation layer between our
canonical IOC types and MISP's attribute types, plus the enricher's
deduplication and aggregation behaviour.
"""

from unittest.mock import AsyncMock, patch

import pytest

from core.misp.enricher import enrich_iocs
from integrations.misp import MISPClient


@pytest.fixture
def misp_client():
    return MISPClient()


# A representative MISP /attributes/restSearch response for a found IOC.
# Values are illustrative - real MISP responses contain far more fields but
# our client only surfaces the ones an analyst needs during triage
MISP_FOUND_RESPONSE = {
    "response": {
        "Attribute": [
            {
                "id": "1001",
                "type": "sha256",
                "category": "Payload delivery",
                "to_ids": True,
                "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "Event": {
                    "id": "42",
                    "uuid": "5f3e0a12-1234-4abc-9def-1234567890ab",
                    "info": "APT29 campaign - credential harvesting",
                    "threat_level_id": "2",
                    "date": "2026-03-01",
                    "Orgc": {"name": "CERT-EU"},
                },
            }
        ]
    }
}

MISP_NOT_FOUND_RESPONSE = {"response": {"Attribute": []}}


@pytest.mark.asyncio
async def test_check_attribute_found(misp_client):
    with patch.object(
        misp_client, "_post_search", new_callable=AsyncMock, return_value=MISP_FOUND_RESPONSE
    ):
        with patch("integrations.misp.settings") as mock_settings:
            mock_settings.misp_url = "https://misp.example.org"
            mock_settings.misp_api_key = "test-key"
            mock_settings.has_api_key.return_value = True

            result = await misp_client.check_attribute(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "sha256",
            )

    assert result["found"] is True
    assert result["event_count"] == 1
    assert result["to_ids"] is True
    event = result["events"][0]
    assert event["uuid"] == "5f3e0a12-1234-4abc-9def-1234567890ab"
    assert event["info"] == "APT29 campaign - credential harvesting"
    assert event["org"] == "CERT-EU"
    assert event["attribute_type"] == "sha256"


@pytest.mark.asyncio
async def test_check_attribute_not_found(misp_client):
    with patch.object(
        misp_client,
        "_post_search",
        new_callable=AsyncMock,
        return_value=MISP_NOT_FOUND_RESPONSE,
    ):
        with patch("integrations.misp.settings") as mock_settings:
            mock_settings.misp_url = "https://misp.example.org"
            mock_settings.misp_api_key = "test-key"
            mock_settings.has_api_key.return_value = True

            result = await misp_client.check_attribute("1.2.3.4", "ip")

    assert result["found"] is False


@pytest.mark.asyncio
async def test_check_attribute_not_configured(misp_client):
    with patch("integrations.misp.settings") as mock_settings:
        mock_settings.misp_url = ""
        mock_settings.has_api_key.return_value = False

        result = await misp_client.check_attribute("1.2.3.4", "ip")

    assert result.get("error") == "MISP not configured"


@pytest.mark.asyncio
async def test_check_attribute_unsupported_kind(misp_client):
    with patch("integrations.misp.settings") as mock_settings:
        mock_settings.misp_url = "https://misp.example.org"
        mock_settings.misp_api_key = "test-key"
        mock_settings.has_api_key.return_value = True

        # "bitcoin" isn't in the type map - should fail closed, not crash
        result = await misp_client.check_attribute("1abc", "bitcoin")

    assert result["found"] is False
    assert "unsupported IOC kind" in result["error"]


@pytest.mark.asyncio
async def test_check_attribute_translates_ip_to_ip_src_ip_dst(misp_client):
    """The MISP search payload must ask for BOTH ip-src and ip-dst when we
    look up a generic IP - otherwise half of the matches would be missed."""
    captured_payload = {}

    async def fake_search(payload):
        captured_payload.update(payload)
        return MISP_NOT_FOUND_RESPONSE

    with patch.object(misp_client, "_post_search", side_effect=fake_search):
        with patch("integrations.misp.settings") as mock_settings:
            mock_settings.misp_url = "https://misp.example.org"
            mock_settings.misp_api_key = "test-key"
            mock_settings.has_api_key.return_value = True

            await misp_client.check_attribute("8.8.8.8", "ip")

    assert set(captured_payload["type"]) == {"ip-src", "ip-dst"}
    assert captured_payload["value"] == "8.8.8.8"


# --- Enricher -------------------------------------------------------------


@pytest.mark.asyncio
async def test_enrich_iocs_deduplicates():
    """The extractor can emit the same (type, value) multiple times; the
    enricher must call MISP once per unique pair, not once per occurrence."""
    iocs = [
        {"type": "ipv4", "value": "8.8.8.8", "context": "..."},
        {"type": "ipv4", "value": "8.8.8.8", "context": "... duplicate ..."},
        {"type": "domain", "value": "evil.example", "context": "..."},
    ]

    call_count = {"n": 0}

    async def fake_check(value, kind):
        call_count["n"] += 1
        return {"found": False}

    with patch("core.misp.enricher.MISPClient") as mock_client_cls:
        mock_client_cls.return_value.check_attribute = fake_check
        result = await enrich_iocs(iocs)

    assert call_count["n"] == 2  # 8.8.8.8 and evil.example
    assert result["known_count"] == 0
    assert result["summary"]["ip"]["checked"] == 1
    assert result["summary"]["domain"]["checked"] == 1


@pytest.mark.asyncio
async def test_enrich_iocs_counts_known():
    iocs = [
        {"type": "sha256", "value": "abc" * 21 + "a", "context": "..."},
        {"type": "domain", "value": "clean.example", "context": "..."},
    ]

    async def fake_check(value, kind):
        if kind == "sha256":
            return {"found": True, "event_count": 1, "to_ids": True, "events": []}
        return {"found": False}

    with patch("core.misp.enricher.MISPClient") as mock_client_cls:
        mock_client_cls.return_value.check_attribute = fake_check
        result = await enrich_iocs(iocs)

    assert result["known_count"] == 1
    assert result["summary"]["sha256"]["known"] == 1
    assert result["summary"]["domain"]["known"] == 0


@pytest.mark.asyncio
async def test_enrich_iocs_survives_per_lookup_errors():
    """A transient failure on one IOC must not abort the whole enrichment."""
    iocs = [
        {"type": "ipv4", "value": "1.1.1.1", "context": "..."},
        {"type": "ipv4", "value": "2.2.2.2", "context": "..."},
    ]

    async def fake_check(value, kind):
        if value == "1.1.1.1":
            raise RuntimeError("timeout")
        return {"found": True, "event_count": 1, "to_ids": False, "events": []}

    with patch("core.misp.enricher.MISPClient") as mock_client_cls:
        mock_client_cls.return_value.check_attribute = fake_check
        result = await enrich_iocs(iocs)

    assert "error" in result["results"]["1.1.1.1"]
    assert result["results"]["2.2.2.2"]["found"] is True
    assert result["known_count"] == 1


@pytest.mark.asyncio
async def test_enrich_iocs_empty_input():
    result = await enrich_iocs([])
    assert result == {"known_count": 0, "results": {}, "summary": {}}


@pytest.mark.asyncio
async def test_enrich_iocs_skips_cves():
    """CVEs are catalogued in MISP but aren't triage IOCs - skip them."""
    iocs = [{"type": "cve", "value": "CVE-2024-1234", "context": "..."}]

    call_count = {"n": 0}

    async def fake_check(value, kind):
        call_count["n"] += 1
        return {"found": False}

    with patch("core.misp.enricher.MISPClient") as mock_client_cls:
        mock_client_cls.return_value.check_attribute = fake_check
        result = await enrich_iocs(iocs)

    assert call_count["n"] == 0
    assert result["known_count"] == 0
