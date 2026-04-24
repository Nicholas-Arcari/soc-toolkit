"""Tests for integration clients (mocked - no real API calls)."""

from unittest.mock import AsyncMock, patch

import pytest

from integrations.virustotal import VirusTotalClient
from integrations.abuseipdb import AbuseIPDBClient


@pytest.fixture
def vt_client():
    return VirusTotalClient()


@pytest.fixture
def abuse_client():
    return AbuseIPDBClient()


@pytest.mark.asyncio
async def test_virustotal_check_hash_found(vt_client):
    mock_response = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 15,
                    "undetected": 55,
                    "harmless": 0,
                    "suspicious": 2,
                },
                "popular_threat_classification": {
                    "suggested_threat_label": "trojan.generic"
                },
                "reputation": -50,
            }
        }
    }

    with patch.object(vt_client, "get", new_callable=AsyncMock, return_value=mock_response):
        with patch("integrations.virustotal.settings") as mock_settings:
            mock_settings.has_api_key.return_value = True
            mock_settings.virustotal_api_key = "test_key"

            result = await vt_client.check_hash("abc123def456")

            assert result["found"] is True
            assert result["positives"] == 15
            assert result["threat_label"] == "trojan.generic"


@pytest.mark.asyncio
async def test_virustotal_no_api_key(vt_client):
    with patch("integrations.virustotal.settings") as mock_settings:
        mock_settings.has_api_key.return_value = False

        result = await vt_client.check_hash("abc123")

        assert result.get("error") == "API key not configured"


@pytest.mark.asyncio
async def test_abuseipdb_check_ip(abuse_client):
    mock_response = {
        "data": {
            "ipAddress": "45.33.32.156",
            "abuseConfidenceScore": 85,
            "countryCode": "US",
            "isp": "Linode",
            "domain": "linode.com",
            "totalReports": 142,
            "lastReportedAt": "2026-04-10T08:00:00Z",
            "isPublic": True,
            "isTor": False,
            "reports": [{"categories": [18, 22]}],
        }
    }

    with patch.object(abuse_client, "get", new_callable=AsyncMock, return_value=mock_response):
        with patch("integrations.abuseipdb.settings") as mock_settings:
            mock_settings.has_api_key.return_value = True
            mock_settings.abuseipdb_api_key = "test_key"

            result = await abuse_client.check_ip("45.33.32.156")

            assert result["ip"] == "45.33.32.156"
            assert result["abuse_score"] == 85
            assert result["country"] == "US"
            assert result["total_reports"] == 142
            assert result["is_tor"] is False


@pytest.mark.asyncio
async def test_abuseipdb_no_api_key(abuse_client):
    with patch("integrations.abuseipdb.settings") as mock_settings:
        mock_settings.has_api_key.return_value = False

        result = await abuse_client.check_ip("1.2.3.4")

        assert result.get("error") == "API key not configured"
