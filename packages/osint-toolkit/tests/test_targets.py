"""Targets CRUD - especially the authorization gate."""
from httpx import AsyncClient


async def test_create_target_requires_authorization(client: AsyncClient) -> None:
    """The whole project presumes authorization - the API must refuse
    creation when `authorized_to_scan` is missing or False.
    """
    response = await client.post(
        "/api/targets",
        json={"name": "acme", "scope_domains": ["acme.example"], "authorized_to_scan": False},
    )
    assert response.status_code == 400
    assert "authorized_to_scan" in response.json()["detail"]


async def test_create_target_succeeds_with_authorization(client: AsyncClient) -> None:
    response = await client.post(
        "/api/targets",
        json={
            "name": "acme",
            "owner_email": "sec@acme.example",
            "scope_domains": ["acme.example", "Acme.Example"],
            "authorized_to_scan": True,
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "acme"
    assert body["authorized_to_scan"] is True
    assert body["active"] is True
    # Dedup + lowercase normalization happens in the validator
    assert body["scope_domains"] == ["acme.example"]


async def test_create_target_rejects_invalid_scope_domain(client: AsyncClient) -> None:
    response = await client.post(
        "/api/targets",
        json={
            "name": "acme",
            "scope_domains": ["https://acme.example/"],  # URL, not a domain
            "authorized_to_scan": True,
        },
    )
    assert response.status_code == 422


async def test_list_targets_excludes_inactive_by_default(client: AsyncClient) -> None:
    create = await client.post(
        "/api/targets",
        json={"name": "acme", "scope_domains": ["acme.example"], "authorized_to_scan": True},
    )
    target_id = create.json()["id"]
    await client.patch(f"/api/targets/{target_id}", json={"active": False})

    default = await client.get("/api/targets")
    assert default.json() == []

    include_all = await client.get("/api/targets", params={"include_inactive": True})
    assert len(include_all.json()) == 1


async def test_get_missing_target_returns_404(client: AsyncClient) -> None:
    response = await client.get("/api/targets/9999")
    assert response.status_code == 404


async def test_update_cannot_revoke_authorization_flag(client: AsyncClient) -> None:
    """`authorized_to_scan` is not in `TargetUpdate` on purpose - flipping
    it via a PATCH would let a client silently disarm the server-side gate
    after the fact.
    """
    create = await client.post(
        "/api/targets",
        json={"name": "acme", "scope_domains": ["acme.example"], "authorized_to_scan": True},
    )
    target_id = create.json()["id"]

    patched = await client.patch(
        f"/api/targets/{target_id}",
        json={"authorized_to_scan": False, "name": "renamed"},
    )
    assert patched.status_code == 200
    # `authorized_to_scan` in the payload is silently ignored (extra field)
    assert patched.json()["authorized_to_scan"] is True
    assert patched.json()["name"] == "renamed"


async def test_delete_target_removes_it(client: AsyncClient) -> None:
    create = await client.post(
        "/api/targets",
        json={"name": "acme", "scope_domains": ["acme.example"], "authorized_to_scan": True},
    )
    target_id = create.json()["id"]

    delete = await client.delete(f"/api/targets/{target_id}")
    assert delete.status_code == 204

    assert (await client.get(f"/api/targets/{target_id}")).status_code == 404
