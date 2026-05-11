"""Active-scan route + wrapper tests.

Covers the two-axis gate (operator flag + per-request confirmation
token), the subprocess wrapper's detect-and-use behaviour, and the
persistence side effects of a successful scan.
"""
from __future__ import annotations

import pytest

from core.asm import active_enum
from core.asm.active_enum import (
    ActiveEnumResult,
    ActiveScannerUnavailableError,
)
from db.models import Subdomain, Target


# --- Wrapper --------------------------------------------------------------


async def test_wrapper_raises_when_no_binary(monkeypatch) -> None:
    """No PATH hit for subfinder/amass -> clear error, no subprocess call."""
    monkeypatch.setattr(active_enum.shutil, "which", lambda _: None)
    with pytest.raises(ActiveScannerUnavailableError):
        await active_enum.active_enumerate("example.com")


async def test_wrapper_parses_subfinder_stdout(monkeypatch) -> None:
    """Subfinder default output is one FQDN per line - collapse to sorted set."""
    monkeypatch.setattr(active_enum.shutil, "which", lambda cand: "/usr/bin/subfinder")

    class _FakeProc:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return (b"api.example.com\nwww.example.com\nwww.example.com\n", b"")

        def kill(self) -> None:
            pass

        async def wait(self) -> int:
            return 0

    async def _fake_exec(*args: object, **kwargs: object) -> _FakeProc:
        return _FakeProc()

    monkeypatch.setattr(active_enum.asyncio, "create_subprocess_exec", _fake_exec)

    result = await active_enum.active_enumerate("example.com")
    assert result.tool == "subfinder"
    assert result.discovered == ["api.example.com", "www.example.com"]
    assert result.returncode == 0


async def test_wrapper_prefers_subfinder_over_amass(monkeypatch) -> None:
    """When both binaries exist, Subfinder wins (MIT, faster output)."""
    monkeypatch.setattr(
        active_enum.shutil,
        "which",
        lambda cand: "/usr/bin/" + cand,
    )
    assert active_enum._detect_tool() == "subfinder"


# --- Route gates ----------------------------------------------------------


async def _seed_target(db_session, **kwargs) -> int:
    target = Target(
        name=kwargs.get("name", "demo"),
        scope_domains=kwargs.get("scope_domains", ["example.com"]),
        authorized_to_scan=kwargs.get("authorized_to_scan", True),
    )
    db_session.add(target)
    await db_session.flush()
    return target.id


async def test_route_403_when_active_scan_disabled(client, db_session, monkeypatch) -> None:
    from config import settings as cfg

    monkeypatch.setattr(cfg, "enable_active_scanning", False)
    target_id = await _seed_target(db_session)

    resp = await client.post(
        f"/api/scans/targets/{target_id}/active-scan",
        json={"confirmation": "demo"},
    )
    assert resp.status_code == 403
    assert "OSINT_ENABLE_ACTIVE_SCANNING" in resp.json()["detail"]


async def test_route_404_on_missing_target(client, monkeypatch) -> None:
    from config import settings as cfg

    monkeypatch.setattr(cfg, "enable_active_scanning", True)
    resp = await client.post(
        "/api/scans/targets/9999/active-scan",
        json={"confirmation": "anything"},
    )
    assert resp.status_code == 404


async def test_route_400_when_not_authorized(client, db_session, monkeypatch) -> None:
    from config import settings as cfg

    monkeypatch.setattr(cfg, "enable_active_scanning", True)
    target_id = await _seed_target(db_session, authorized_to_scan=False)

    resp = await client.post(
        f"/api/scans/targets/{target_id}/active-scan",
        json={"confirmation": "demo"},
    )
    assert resp.status_code == 400
    assert "authorized" in resp.json()["detail"]


async def test_route_400_when_confirmation_mismatch(
    client, db_session, monkeypatch
) -> None:
    from config import settings as cfg

    monkeypatch.setattr(cfg, "enable_active_scanning", True)
    target_id = await _seed_target(db_session, name="prod-perimeter")

    resp = await client.post(
        f"/api/scans/targets/{target_id}/active-scan",
        json={"confirmation": "something-else"},
    )
    assert resp.status_code == 400
    assert "confirmation" in resp.json()["detail"]


async def test_route_confirmation_is_case_insensitive(
    client, db_session, monkeypatch
) -> None:
    from config import settings as cfg

    monkeypatch.setattr(cfg, "enable_active_scanning", True)
    target_id = await _seed_target(db_session, name="Prod-Perimeter")

    async def _fake_enum(root: str, **kwargs) -> ActiveEnumResult:
        return ActiveEnumResult(tool="subfinder", discovered=[])

    monkeypatch.setattr(
        "api.routes.scans.active_enumerate", _fake_enum
    )

    resp = await client.post(
        f"/api/scans/targets/{target_id}/active-scan",
        json={"confirmation": "PROD-perimeter"},
    )
    assert resp.status_code == 201, resp.text


async def test_route_400_when_scope_empty(client, db_session, monkeypatch) -> None:
    from config import settings as cfg

    monkeypatch.setattr(cfg, "enable_active_scanning", True)
    target_id = await _seed_target(db_session, scope_domains=[])

    resp = await client.post(
        f"/api/scans/targets/{target_id}/active-scan",
        json={"confirmation": "demo"},
    )
    assert resp.status_code == 400
    assert "scope_domains" in resp.json()["detail"]


async def test_route_503_when_no_binary(client, db_session, monkeypatch) -> None:
    from config import settings as cfg

    monkeypatch.setattr(cfg, "enable_active_scanning", True)
    target_id = await _seed_target(db_session)

    async def _fake_enum(root: str, **kwargs) -> ActiveEnumResult:
        raise ActiveScannerUnavailableError("no active-scan binary found")

    monkeypatch.setattr("api.routes.scans.active_enumerate", _fake_enum)

    resp = await client.post(
        f"/api/scans/targets/{target_id}/active-scan",
        json={"confirmation": "demo"},
    )
    assert resp.status_code == 503


async def test_route_success_persists_subdomains(
    client, db_session, monkeypatch
) -> None:
    from config import settings as cfg
    from sqlalchemy import select

    monkeypatch.setattr(cfg, "enable_active_scanning", True)
    target_id = await _seed_target(db_session, name="acme")

    async def _fake_enum(root: str, **kwargs) -> ActiveEnumResult:
        return ActiveEnumResult(
            tool="subfinder",
            discovered=["api.example.com", "mail.example.com"],
        )

    monkeypatch.setattr("api.routes.scans.active_enumerate", _fake_enum)

    resp = await client.post(
        f"/api/scans/targets/{target_id}/active-scan",
        json={"confirmation": "acme"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["summary"]["tool"] == "subfinder"
    assert body["summary"]["discovered_total"] == 2
    assert body["summary"]["new"] == 2
    assert sorted(body["discovered"]) == ["api.example.com", "mail.example.com"]

    # Subdomain rows are persisted with the `active:subfinder` source label.
    rows = (
        await db_session.execute(
            select(Subdomain).where(Subdomain.target_id == target_id)
        )
    ).scalars().all()
    assert {r.fqdn for r in rows} == {"api.example.com", "mail.example.com"}
    assert all(r.source == "active:subfinder" for r in rows)
