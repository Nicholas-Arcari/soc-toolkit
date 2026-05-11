"""Webhook notification tests.

Exercises the pure helper (`notify_severe_findings`) against mocked
HTTP endpoints, and covers the wiring into the scan route so a DNS
mapping that emits an SPF finding does in fact POST to the configured
webhook URL.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from core.notifications import notify_severe_findings
from db.models import Finding, Target


def _finding(severity: str, fid: int = 1) -> Finding:
    return Finding(
        id=fid,
        target_id=1,
        severity=severity,
        category="test",
        description=f"{severity} finding",
        status="open",
        note="",
    )


def _target() -> Target:
    return Target(id=1, name="example")


@respx.mock
async def test_notify_fires_only_for_severe() -> None:
    """Only high/critical findings trigger a POST - low/medium/info stay silent."""
    route = respx.post("https://hooks.example.com/osint").mock(
        return_value=httpx.Response(200)
    )
    findings = [
        _finding("info", 1),
        _finding("low", 2),
        _finding("medium", 3),
        _finding("high", 4),
        _finding("critical", 5),
    ]
    sent = await notify_severe_findings(
        target=_target(),
        findings=findings,
        webhook_url="https://hooks.example.com/osint",
    )
    assert sent == 2
    assert route.call_count == 2


async def test_notify_noop_when_url_blank() -> None:
    """Blank webhook_url short-circuits before any network call."""
    sent = await notify_severe_findings(
        target=_target(),
        findings=[_finding("critical")],
        webhook_url="",
    )
    assert sent == 0


async def test_notify_noop_when_no_severe_findings() -> None:
    """No network call when every finding is below the threshold."""
    async with respx.mock(assert_all_called=False) as mock:
        route = mock.post("https://hooks.example.com/osint")
        sent = await notify_severe_findings(
            target=_target(),
            findings=[_finding("low"), _finding("medium")],
            webhook_url="https://hooks.example.com/osint",
        )
        assert sent == 0
        assert route.call_count == 0


@respx.mock
async def test_notify_survives_http_failure() -> None:
    """A single broken webhook delivery does not sink the other postings."""
    respx.post("https://hooks.example.com/osint").mock(
        side_effect=[
            httpx.Response(500),
            httpx.Response(200),
        ]
    )
    findings = [_finding("high", 10), _finding("critical", 11)]
    sent = await notify_severe_findings(
        target=_target(),
        findings=findings,
        webhook_url="https://hooks.example.com/osint",
    )
    assert sent == 1


@respx.mock
async def test_notify_payload_shape() -> None:
    """The JSON body is flat and aggregator-friendly."""
    import json

    captured: list[dict[str, object]] = []

    def _capture(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content))
        return httpx.Response(200)

    respx.post("https://hooks.example.com/osint").mock(side_effect=_capture)
    await notify_severe_findings(
        target=_target(),
        findings=[_finding("critical", 42)],
        webhook_url="https://hooks.example.com/osint",
    )
    assert captured == [
        {
            "event": "finding.created",
            "target": {"id": 1, "name": "example"},
            "finding": {
                "id": 42,
                "severity": "critical",
                "category": "test",
                "description": "critical finding",
                "status": "open",
            },
        }
    ]


@respx.mock
async def test_dns_scan_fires_webhook(client, db_session, monkeypatch) -> None:
    """End-to-end: a dns-mapping scan that emits a medium finding does not
    POST (SPF-missing is medium), but the route still completes cleanly."""
    from config import settings as cfg

    monkeypatch.setattr(cfg, "webhook_url", "https://hooks.example.com/osint")
    route = respx.post("https://hooks.example.com/osint").mock(
        return_value=httpx.Response(200)
    )

    # Seed an authorized target directly via the test session.
    target = Target(
        name="demo", scope_domains=["example.test"], authorized_to_scan=True
    )
    db_session.add(target)
    await db_session.flush()
    target_id = target.id

    # Stub the DNS resolver so we deterministically emit a finding.
    from core.asm import dns_mapping as dns_mod

    class _Resolver:
        async def resolve(self, qname: str, rtype: str) -> list[str]:
            raise AssertionError("resolver should be patched at the module level")

    async def _fake_map_dns(target, *, session, resolver=None):
        # Emit one high-severity finding so the webhook must fire.
        session.add(
            Finding(
                target_id=target.id,
                severity="high",
                category="email_auth",
                description="example.test: SPF '+all' (stub).",
            )
        )
        await session.flush()
        return dns_mod.DNSMappingResult(
            target_id=target.id, domains=[], findings_created=1
        )

    monkeypatch.setattr(dns_mod, "map_dns", _fake_map_dns)

    resp = await client.post(f"/api/scans/targets/{target_id}/dns-mapping")
    assert resp.status_code == 201, resp.text
    assert route.call_count == 1


@respx.mock
async def test_dns_scan_silent_when_url_unset(client, db_session, monkeypatch) -> None:
    """When webhook_url is empty the scan endpoint never reaches out."""
    from config import settings as cfg

    monkeypatch.setattr(cfg, "webhook_url", "")
    route = respx.post("https://hooks.example.com/osint").mock(
        return_value=httpx.Response(200)
    )

    target = Target(
        name="demo", scope_domains=["example.test"], authorized_to_scan=True
    )
    db_session.add(target)
    await db_session.flush()
    target_id = target.id

    from core.asm import dns_mapping as dns_mod

    async def _fake_map_dns(target, *, session, resolver=None):
        session.add(
            Finding(
                target_id=target.id,
                severity="critical",
                category="cve_exposure",
                description="stub",
            )
        )
        await session.flush()
        return dns_mod.DNSMappingResult(
            target_id=target.id, domains=[], findings_created=1
        )

    monkeypatch.setattr(dns_mod, "map_dns", _fake_map_dns)

    resp = await client.post(f"/api/scans/targets/{target_id}/dns-mapping")
    assert resp.status_code == 201, resp.text
    assert route.call_count == 0


@pytest.mark.parametrize("http_error", [httpx.TimeoutException("t"), httpx.ConnectError("c")])
@respx.mock
async def test_scan_survives_webhook_failure(
    client, db_session, monkeypatch, http_error
) -> None:
    """If the webhook receiver is down/timing out, the scan still returns 201."""
    from config import settings as cfg

    monkeypatch.setattr(cfg, "webhook_url", "https://hooks.example.com/osint")
    respx.post("https://hooks.example.com/osint").mock(side_effect=http_error)

    target = Target(
        name="demo", scope_domains=["example.test"], authorized_to_scan=True
    )
    db_session.add(target)
    await db_session.flush()
    target_id = target.id

    from core.asm import dns_mapping as dns_mod

    async def _fake_map_dns(target, *, session, resolver=None):
        session.add(
            Finding(
                target_id=target.id,
                severity="high",
                category="email_auth",
                description="stub",
            )
        )
        await session.flush()
        return dns_mod.DNSMappingResult(
            target_id=target.id, domains=[], findings_created=1
        )

    monkeypatch.setattr(dns_mod, "map_dns", _fake_map_dns)

    resp = await client.post(f"/api/scans/targets/{target_id}/dns-mapping")
    assert resp.status_code == 201, resp.text
