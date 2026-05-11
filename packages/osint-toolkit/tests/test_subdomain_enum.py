"""Passive subdomain enumeration.

Mocks the integration clients so scan logic (scope filter, upsert,
source merging) is exercised without hitting crt.sh / SecurityTrails.
"""
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from core.asm.subdomain_enum import EnumClients, _in_scope, enumerate_subdomains
from db.models import Subdomain, Target


def test_in_scope_matches_root_and_subdomains() -> None:
    scope = ["example.com"]
    assert _in_scope("example.com", scope)
    assert _in_scope("www.example.com", scope)
    assert _in_scope("api.eu.example.com", scope)


def test_in_scope_rejects_neighbors() -> None:
    """Passive sources leak neighbor domains - scope filter stops that.

    Critical for public release: a scan for "example.com" must not end
    up persisting "examplecompany.com" just because they co-occurred in
    a CT log entry.
    """
    scope = ["example.com"]
    assert not _in_scope("notexample.com", scope)
    assert not _in_scope("example.com.evil.net", scope)
    assert not _in_scope("examplecompany.com", scope)


def test_in_scope_empty_scope_permits_all() -> None:
    """Empty scope is dev-convenience only - production targets always
    have a scope set on create.
    """
    assert _in_scope("anything.tld", [])


async def test_enumerate_dedupes_and_scope_filters(db_session) -> None:
    """crt.sh + SecurityTrails merge, out-of-scope entries are dropped."""
    target = Target(
        name="acme", scope_domains=["acme.example"], authorized_to_scan=True, active=True
    )
    db_session.add(target)
    await db_session.flush()

    crtsh = MagicMock()
    crtsh.search = AsyncMock(
        return_value=[
            {"subdomain": "www.acme.example", "issuer": "LE", "active": True},
            {"subdomain": "www.acme.example", "issuer": "LE", "active": True},  # dup
            {"subdomain": "*.acme.example", "issuer": "LE", "active": True},  # wildcard
            {"subdomain": "api.acme.example", "issuer": "LE", "active": True},
            {"subdomain": "leaked.other.tld", "issuer": "LE", "active": True},  # out of scope
        ]
    )

    securitytrails = MagicMock()
    securitytrails.api_key = "real-key"
    securitytrails.subdomains = AsyncMock(
        return_value=["api.acme.example", "staging.acme.example"]
    )

    result = await enumerate_subdomains(
        target,
        clients=EnumClients(crtsh=crtsh, securitytrails=securitytrails),
        session=db_session,
    )

    assert set(result.discovered) == {
        "www.acme.example",
        "api.acme.example",
        "staging.acme.example",
    }
    assert result.new_count == 3
    assert result.updated_count == 0
    assert result.sources == {"crtsh": 2, "securitytrails": 2}

    rows = (
        await db_session.execute(select(Subdomain).where(Subdomain.target_id == target.id))
    ).scalars().all()
    assert {r.fqdn for r in rows} == {
        "www.acme.example",
        "api.acme.example",
        "staging.acme.example",
    }


async def test_enumerate_skips_securitytrails_without_key(db_session) -> None:
    """No key → silent skip, not an error. Same pattern used everywhere
    in sec-common so a public install with no credentials still works.
    """
    target = Target(
        name="acme", scope_domains=["acme.example"], authorized_to_scan=True, active=True
    )
    db_session.add(target)
    await db_session.flush()

    crtsh = MagicMock()
    crtsh.search = AsyncMock(
        return_value=[{"subdomain": "www.acme.example", "active": True}]
    )

    securitytrails = MagicMock()
    securitytrails.api_key = ""  # degraded mode
    securitytrails.subdomains = AsyncMock(side_effect=AssertionError("must not be called"))

    result = await enumerate_subdomains(
        target,
        clients=EnumClients(crtsh=crtsh, securitytrails=securitytrails),
        session=db_session,
    )

    assert result.discovered == ["www.acme.example"]
    assert result.sources["securitytrails"] == 0
    securitytrails.subdomains.assert_not_called()


async def test_enumerate_rescan_updates_last_seen(db_session) -> None:
    """Second run on same FQDN → `last_seen` advances, no duplicate row.

    Backs the UI's "discovered N days ago, still present" story.
    """
    target = Target(
        name="acme", scope_domains=["acme.example"], authorized_to_scan=True, active=True
    )
    db_session.add(target)
    await db_session.flush()

    crtsh = MagicMock()
    crtsh.search = AsyncMock(
        return_value=[{"subdomain": "www.acme.example", "active": True}]
    )
    securitytrails = MagicMock()
    securitytrails.api_key = ""

    clients = EnumClients(crtsh=crtsh, securitytrails=securitytrails)

    first = await enumerate_subdomains(target, clients=clients, session=db_session)
    second = await enumerate_subdomains(target, clients=clients, session=db_session)

    assert first.new_count == 1
    assert second.new_count == 0
    assert second.updated_count == 1

    rows = (
        await db_session.execute(select(Subdomain).where(Subdomain.target_id == target.id))
    ).scalars().all()
    assert len(rows) == 1


async def test_scan_endpoint_rejects_unknown_target(client: AsyncClient) -> None:
    response = await client.post("/api/scans/targets/9999/subdomain-enum")
    assert response.status_code == 404


async def test_scan_failure_persists_scan_row(
    client: AsyncClient, db_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When enumeration raises, the `scans` row must still exist with
    status=failed. The bug was that `get_session`'s rollback-on-exception
    would undo the status update alongside the raised error - the route
    now commits the failure state explicitly before re-raising.
    """
    from db.models import Scan

    create = await client.post(
        "/api/targets",
        json={
            "name": "acme",
            "scope_domains": ["acme.example"],
            "authorized_to_scan": True,
        },
    )
    target_id = create.json()["id"]

    async def _boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("upstream exploded")

    monkeypatch.setattr("api.routes.scans.enumerate_subdomains", _boom)

    response = await client.post(f"/api/scans/targets/{target_id}/subdomain-enum")
    assert response.status_code == 502
    assert "upstream exploded" in response.json()["detail"]

    # The shared in-memory DB is reached via the same `db_session`; expire
    # the identity map so the SELECT goes to disk and we see the real state.
    db_session.expire_all()
    scans = (
        await db_session.execute(select(Scan).where(Scan.target_id == target_id))
    ).scalars().all()
    assert len(scans) == 1
    assert scans[0].status == "failed"
    assert "upstream exploded" in (scans[0].error or "")


async def test_subdomain_unique_constraint_prevents_duplicates(db_session) -> None:
    """DB-level guard against TOCTOU. Two direct inserts of the same
    (target_id, fqdn) must raise IntegrityError instead of silently
    producing two rows.
    """
    target = Target(
        name="acme", scope_domains=["acme.example"], authorized_to_scan=True, active=True
    )
    db_session.add(target)
    await db_session.flush()

    db_session.add(Subdomain(target_id=target.id, fqdn="www.acme.example", source="crtsh"))
    await db_session.flush()

    db_session.add(Subdomain(target_id=target.id, fqdn="www.acme.example", source="securitytrails"))
    with pytest.raises(IntegrityError):
        await db_session.flush()
    await db_session.rollback()
