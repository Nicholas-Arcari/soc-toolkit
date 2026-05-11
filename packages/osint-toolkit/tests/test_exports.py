"""CSV + JSON export endpoints.

These cover the happy path (round-trip the rows we just seeded) and
the ownership/404 path. Pure CSV-shape assertions are cheap - they
pin the header order so downstream consumers don't silently break.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from typing import Any

from httpx import AsyncClient

from db.models import Finding, Scan, Service, Subdomain, Target


async def _seed_full_engagement(db_session: Any) -> int:
    """Populate one target with a scan, two subdomains, a service, a finding."""
    target = Target(
        name="acme",
        scope_domains=["acme.example"],
        authorized_to_scan=True,
        active=True,
    )
    db_session.add(target)
    await db_session.flush()

    scan = Scan(
        target_id=target.id,
        kind="subdomain_enum",
        status="completed",
        finished_at=datetime.now(UTC),
        summary={"discovered": 2},
    )
    db_session.add(scan)
    await db_session.flush()

    sub1 = Subdomain(target_id=target.id, fqdn="www.acme.example", source="crtsh")
    sub2 = Subdomain(target_id=target.id, fqdn="api.acme.example", source="pdns")
    db_session.add_all([sub1, sub2])
    await db_session.flush()

    service = Service(
        subdomain_id=sub1.id,
        ip="192.0.2.10",
        port=443,
        banner="nginx/1.25",
        cves=["CVE-2024-0001", "CVE-2024-0002"],
    )
    db_session.add(service)

    finding = Finding(
        target_id=target.id,
        severity="high",
        category="cve",
        description="nginx vulnerable to CVE-2024-0001",
        status="acknowledged",
        note="tracking in Jira",
    )
    db_session.add(finding)
    await db_session.flush()
    return int(target.id)


async def test_export_subdomains_csv_header_and_rows(
    client: AsyncClient, db_session: Any
) -> None:
    target_id = await _seed_full_engagement(db_session)
    resp = await client.get(f"/api/scans/targets/{target_id}/export/subdomains.csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert "attachment" in resp.headers["content-disposition"]

    text = resp.content.decode("utf-8-sig")
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0] == ["fqdn", "source", "first_seen", "last_seen"]
    fqdns = {r[0] for r in rows[1:]}
    assert fqdns == {"www.acme.example", "api.acme.example"}


async def test_export_services_csv_serializes_cves_as_semicolon(
    client: AsyncClient, db_session: Any
) -> None:
    target_id = await _seed_full_engagement(db_session)
    resp = await client.get(f"/api/scans/targets/{target_id}/export/services.csv")
    assert resp.status_code == 200
    text = resp.content.decode("utf-8-sig")
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0] == ["ip", "port", "banner", "cves", "first_seen", "last_seen"]
    # The one service we seeded had two CVEs joined by ";".
    assert rows[1][3] == "CVE-2024-0001;CVE-2024-0002"


async def test_export_findings_csv_includes_triage_state(
    client: AsyncClient, db_session: Any
) -> None:
    target_id = await _seed_full_engagement(db_session)
    resp = await client.get(f"/api/scans/targets/{target_id}/export/findings.csv")
    assert resp.status_code == 200
    text = resp.content.decode("utf-8-sig")
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0] == [
        "id",
        "severity",
        "category",
        "status",
        "description",
        "note",
        "created_at",
        "resolved_at",
    ]
    assert rows[1][1] == "high"
    assert rows[1][3] == "acknowledged"
    assert rows[1][5] == "tracking in Jira"
    # No resolved_at yet (finding is still active).
    assert rows[1][7] == ""


async def test_export_engagement_report_bundles_all_state(
    client: AsyncClient, db_session: Any
) -> None:
    target_id = await _seed_full_engagement(db_session)
    resp = await client.get(f"/api/scans/targets/{target_id}/export/report.json")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    payload = json.loads(resp.content.decode("utf-8"))

    assert payload["target"]["name"] == "acme"
    assert payload["target"]["scope_domains"] == ["acme.example"]
    assert len(payload["scans"]) == 1
    assert payload["scans"][0]["kind"] == "subdomain_enum"
    assert len(payload["subdomains"]) == 2
    assert len(payload["services"]) == 1
    assert payload["services"][0]["cves"] == ["CVE-2024-0001", "CVE-2024-0002"]
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["status"] == "acknowledged"


async def test_export_missing_target_returns_404(client: AsyncClient) -> None:
    resp = await client.get("/api/scans/targets/99999/export/subdomains.csv")
    assert resp.status_code == 404
