"""End-to-end IOC validation path with all 3 clients injected as mocks."""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from sec_common.ioc.validator import validate_and_enrich


def _mock_clients(
    *, vt_resp: dict | None = None, abuse_resp: dict | None = None,
    otx_resp: dict | None = None,
) -> tuple[AsyncMock, AsyncMock, AsyncMock]:
    vt = AsyncMock()
    vt.check_ip = AsyncMock(return_value=vt_resp or {"positives": 0, "total": 80})
    vt.check_domain = AsyncMock(return_value=vt_resp or {"positives": 0, "total": 80})
    vt.check_url = AsyncMock(return_value=vt_resp or {"positives": 0, "total": 80})
    vt.check_hash = AsyncMock(return_value=vt_resp or {"found": False})

    abuse = AsyncMock()
    abuse.check_ip = AsyncMock(return_value=abuse_resp or {"abuse_score": 0})

    otx = AsyncMock()
    otx.check_ip = AsyncMock(return_value=otx_resp or {"pulse_count": 0})
    otx.check_domain = AsyncMock(return_value=otx_resp or {"pulse_count": 0})
    otx.check_hash = AsyncMock(return_value=otx_resp or {"pulse_count": 0})
    return vt, abuse, otx


@pytest.mark.asyncio
async def test_ipv4_enrichment_calls_all_three_sources() -> None:
    vt, abuse, otx = _mock_clients()
    result = await validate_and_enrich(
        [{"type": "ipv4", "value": "1.2.3.4", "context": "beacon"}],
        vt=vt, abuseipdb=abuse, otx=otx,
    )
    assert len(result) == 1
    enr = result[0]["enrichment"]
    assert "virustotal" in enr
    assert "abuseipdb" in enr
    assert "otx" in enr
    vt.check_ip.assert_awaited_once_with("1.2.3.4")
    abuse.check_ip.assert_awaited_once_with("1.2.3.4")
    otx.check_ip.assert_awaited_once_with("1.2.3.4")


@pytest.mark.asyncio
async def test_ip_marked_malicious_when_vt_positive() -> None:
    vt, abuse, otx = _mock_clients(vt_resp={"positives": 15, "total": 80})
    result = await validate_and_enrich(
        [{"type": "ipv4", "value": "1.2.3.4", "context": ""}],
        vt=vt, abuseipdb=abuse, otx=otx,
    )
    assert result[0]["malicious"] is True


@pytest.mark.asyncio
async def test_domain_enrichment_skips_abuseipdb() -> None:
    vt, abuse, otx = _mock_clients()
    result = await validate_and_enrich(
        [{"type": "domain", "value": "evil.test", "context": ""}],
        vt=vt, abuseipdb=abuse, otx=otx,
    )
    vt.check_domain.assert_awaited_once_with("evil.test")
    otx.check_domain.assert_awaited_once_with("evil.test")
    abuse.check_ip.assert_not_awaited()
    assert "abuseipdb" not in result[0]["enrichment"]


@pytest.mark.asyncio
async def test_hash_enrichment_uses_hash_methods() -> None:
    vt, abuse, otx = _mock_clients(vt_resp={"found": True, "positives": 20, "total": 72})
    result = await validate_and_enrich(
        [{"type": "sha256", "value": "a" * 64, "context": ""}],
        vt=vt, abuseipdb=abuse, otx=otx,
    )
    vt.check_hash.assert_awaited()
    otx.check_hash.assert_awaited()
    assert result[0]["malicious"] is True


@pytest.mark.asyncio
async def test_email_and_cve_short_circuit_without_network() -> None:
    vt, abuse, otx = _mock_clients()
    result = await validate_and_enrich(
        [
            {"type": "email", "value": "x@y.test", "context": ""},
            {"type": "cve", "value": "CVE-2024-1", "context": ""},
        ],
        vt=vt, abuseipdb=abuse, otx=otx,
    )
    # Neither should have triggered any client call.
    vt.check_ip.assert_not_awaited()
    vt.check_domain.assert_not_awaited()
    vt.check_hash.assert_not_awaited()
    assert "note" in result[0]["enrichment"]
    assert "CVE-2024-1" in result[1]["enrichment"]["note"]


@pytest.mark.asyncio
async def test_enricher_isolates_per_source_failures() -> None:
    """If one of the 3 sources raises, the others should still be captured."""
    vt = AsyncMock()
    vt.check_ip = AsyncMock(side_effect=RuntimeError("boom"))
    abuse = AsyncMock()
    abuse.check_ip = AsyncMock(return_value={"abuse_score": 0})
    otx = AsyncMock()
    otx.check_ip = AsyncMock(return_value={"pulse_count": 1})

    result = await validate_and_enrich(
        [{"type": "ipv4", "value": "1.2.3.4", "context": ""}],
        vt=vt, abuseipdb=abuse, otx=otx,
    )
    enr = result[0]["enrichment"]
    assert enr["virustotal"] == {"error": "unavailable"}
    assert enr["abuseipdb"]["abuse_score"] == 0
    assert enr["otx"]["pulse_count"] == 1
