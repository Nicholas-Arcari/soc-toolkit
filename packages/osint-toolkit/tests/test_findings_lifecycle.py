"""Findings triage: PATCH endpoint covering status + note transitions.

The PATCH handler stamps ``resolved_at`` on transitions into terminal
states and clears it on transitions back to active - these tests pin
that behavior so future refactors can't silently regress it.
"""
from __future__ import annotations

from typing import Any

from httpx import AsyncClient

from db.models import Finding, Target


async def _seed(db_session: Any, *, severity: str = "medium") -> tuple[int, int]:
    target = Target(
        name="acme",
        scope_domains=["acme.example"],
        authorized_to_scan=True,
        active=True,
    )
    db_session.add(target)
    await db_session.flush()
    finding = Finding(
        target_id=target.id,
        severity=severity,
        category="dns",
        description="SPF missing",
    )
    db_session.add(finding)
    await db_session.flush()
    # Don't commit inside the seed - the client fixture's override
    # shares this session and will commit for us on the next request.
    # Committing here closes the transaction, and under StaticPool +
    # :memory: SQLite that can surface as an empty identity map on the
    # subsequent ORM fetch inside the handler.
    return target.id, finding.id


async def test_patch_rejects_unknown_status(client: AsyncClient, db_session: Any) -> None:
    target_id, finding_id = await _seed(db_session)
    resp = await client.patch(
        f"/api/scans/targets/{target_id}/findings/{finding_id}",
        json={"status": "wontfix"},
    )
    assert resp.status_code == 400
    assert "invalid status" in resp.json()["detail"]


async def test_patch_returns_404_when_finding_owned_by_other_target(
    client: AsyncClient, db_session: Any
) -> None:
    target_id, finding_id = await _seed(db_session)
    # Create a second target and try to update the first target's finding
    # through its URL - the ownership check must reject it.
    other = Target(
        name="other",
        scope_domains=["other.example"],
        authorized_to_scan=True,
        active=True,
    )
    db_session.add(other)
    await db_session.flush()

    resp = await client.patch(
        f"/api/scans/targets/{other.id}/findings/{finding_id}",
        json={"status": "acknowledged"},
    )
    assert resp.status_code == 404


async def test_patch_stamps_resolved_at_on_terminal_transition(
    client: AsyncClient, db_session: Any
) -> None:
    target_id, finding_id = await _seed(db_session)
    resp = await client.patch(
        f"/api/scans/targets/{target_id}/findings/{finding_id}",
        json={"status": "resolved", "note": "patched upstream"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "resolved"
    assert body["note"] == "patched upstream"
    assert body["resolved_at"] is not None


async def test_patch_clears_resolved_at_on_reopen(
    client: AsyncClient, db_session: Any
) -> None:
    target_id, finding_id = await _seed(db_session)
    # Transition into terminal to stamp resolved_at.
    first = await client.patch(
        f"/api/scans/targets/{target_id}/findings/{finding_id}",
        json={"status": "false_positive"},
    )
    assert first.json()["resolved_at"] is not None

    # Now flip back to acknowledged - resolved_at must clear.
    second = await client.patch(
        f"/api/scans/targets/{target_id}/findings/{finding_id}",
        json={"status": "acknowledged"},
    )
    assert second.status_code == 200
    assert second.json()["status"] == "acknowledged"
    assert second.json()["resolved_at"] is None


async def test_patch_note_only_preserves_status(
    client: AsyncClient, db_session: Any
) -> None:
    target_id, finding_id = await _seed(db_session)
    resp = await client.patch(
        f"/api/scans/targets/{target_id}/findings/{finding_id}",
        json={"note": "investigating"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "open"  # default, unchanged
    assert body["note"] == "investigating"
    assert body["resolved_at"] is None


async def test_patch_preserves_resolved_at_on_terminal_to_terminal(
    client: AsyncClient, db_session: Any
) -> None:
    """resolved → false_positive must not re-stamp resolved_at.

    The timestamp records when the finding first left the active set.
    Flipping between terminal states is a reclassification, not a fresh
    remediation event.
    """
    target_id, finding_id = await _seed(db_session)
    first = await client.patch(
        f"/api/scans/targets/{target_id}/findings/{finding_id}",
        json={"status": "resolved"},
    )
    stamped = first.json()["resolved_at"]
    assert stamped is not None

    second = await client.patch(
        f"/api/scans/targets/{target_id}/findings/{finding_id}",
        json={"status": "false_positive"},
    )
    assert second.status_code == 200
    assert second.json()["resolved_at"] == stamped
