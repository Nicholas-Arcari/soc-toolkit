"""JWT auth: token codec, password hashing, user store, middleware, routes.

Covers the full auth layer end-to-end: issuing a JWT, verifying it,
gating a protected route, first-run signup flow, and the "signup is
disabled after the first user exists" safeguard.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.responses import JSONResponse

from sec_common.auth import (
    JwtAuthMiddleware,
    LocalAvatarStorage,
    TokenError,
    UserStore,
    build_auth_router,
    decode_token,
    encode_token,
    hash_password,
    verify_password,
)
from sec_common.auth.gamification import (
    level_for_xp,
    level_progress,
    xp_for_event,
)


def test_encode_decode_roundtrip() -> None:
    tok = encode_token(
        subject="abc", username="alice", role="admin", secret="s3cret"
    )
    claims = decode_token(tok, secret="s3cret")
    assert claims.username == "alice"
    assert claims.role == "admin"
    assert claims.sub == "abc"


def test_wrong_secret_raises() -> None:
    tok = encode_token(subject="x", username="u", role="r", secret="right")
    with pytest.raises(TokenError):
        decode_token(tok, secret="wrong")


def test_expired_token_raises() -> None:
    past = dt.datetime.now(dt.UTC) - dt.timedelta(hours=1)
    tok = encode_token(
        subject="x", username="u", role="r", secret="s", ttl_minutes=1, now=past
    )
    with pytest.raises(TokenError):
        decode_token(tok, secret="s")


def test_password_hash_roundtrip() -> None:
    h = hash_password("correcthorsebatterystaple")
    assert verify_password("correcthorsebatterystaple", h)
    assert not verify_password("wrongpassword", h)


def test_password_hash_rejects_empty() -> None:
    with pytest.raises(ValueError):
        hash_password("")


def test_verify_returns_false_on_malformed_hash() -> None:
    # No timing-leak via exception type - wrong password and bad hash
    # both yield False so a caller can't distinguish the cases.
    assert not verify_password("anything", "not-a-bcrypt-hash")


def test_user_store_create_and_lookup(tmp_path: Path) -> None:
    store = UserStore(tmp_path / "users.json")
    assert store.is_empty()
    user = store.create(username="alice", password_hash="h", role="admin")
    assert not store.is_empty()
    assert store.get_by_username("alice") == user
    assert store.get_by_username("missing") is None


def test_user_store_rejects_duplicate(tmp_path: Path) -> None:
    store = UserStore(tmp_path / "users.json")
    store.create(username="alice", password_hash="h", role="admin")
    with pytest.raises(ValueError):
        store.create(username="alice", password_hash="h2", role="user")


def test_imports_legacy_json_users_on_first_start(tmp_path: Path) -> None:
    # A users.json left by the old JSON-backed store is migrated into the DB
    # once, then renamed aside so it is not re-imported.
    legacy = tmp_path / "users.json"
    legacy.write_text(
        '{"users": [{"id": "u1", "username": "legacy", '
        '"password_hash": "h", "role": "admin", '
        '"created_at": "2026-01-01T00:00:00+00:00"}]}'
    )
    store = UserStore(tmp_path / "users.db")
    migrated = store.get_by_username("legacy")
    assert migrated is not None
    assert migrated.role == "admin"
    assert migrated.plan == "unlimited"  # missing field falls back to default
    assert not legacy.exists()
    assert (tmp_path / "users.json.migrated").exists()


def _make_protected_app(secret: str | None) -> FastAPI:
    app = FastAPI()

    @app.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "healthy"}

    @app.get("/api/protected")
    async def protected(request: Request) -> JSONResponse:
        claims = getattr(request.state, "user", None)
        return JSONResponse({"username": claims.username if claims else None})

    app.add_middleware(JwtAuthMiddleware, secret=secret)
    return app


def test_middleware_noop_without_secret() -> None:
    client = TestClient(_make_protected_app(None))
    assert client.get("/api/protected").status_code == 200


def test_middleware_rejects_missing_bearer() -> None:
    client = TestClient(_make_protected_app("s"))
    r = client.get("/api/protected")
    assert r.status_code == 401
    assert "Authorization" in r.json()["detail"]


def test_middleware_rejects_bad_token() -> None:
    client = TestClient(_make_protected_app("s"))
    r = client.get("/api/protected", headers={"Authorization": "Bearer garbage"})
    assert r.status_code == 401


def test_middleware_accepts_valid_token_and_exposes_claims() -> None:
    client = TestClient(_make_protected_app("s"))
    tok = encode_token(subject="1", username="alice", role="admin", secret="s")
    r = client.get(
        "/api/protected", headers={"Authorization": f"Bearer {tok}"}
    )
    assert r.status_code == 200
    assert r.json()["username"] == "alice"


def test_middleware_exempts_health() -> None:
    client = TestClient(_make_protected_app("s"))
    assert client.get("/api/health").status_code == 200


def _make_full_auth_app(tmp_path: Path, secret: str = "test-secret") -> TestClient:
    store = UserStore(tmp_path / "users.json")
    app = FastAPI()
    app.add_middleware(JwtAuthMiddleware, secret=secret)
    app.include_router(
        build_auth_router(store=store, secret=secret), prefix="/api/auth"
    )

    @app.get("/api/protected")
    async def protected(request: Request) -> dict[str, str]:
        return {"user": request.state.user.username}

    return TestClient(app)


def test_first_run_signup_then_login(tmp_path: Path) -> None:
    client = _make_full_auth_app(tmp_path)

    # setup-required reports empty store
    r = client.get("/api/auth/setup-required")
    assert r.json()["setup_required"] is True

    # first signup succeeds and returns a usable token
    r = client.post(
        "/api/auth/signup",
        json={"username": "admin", "password": "supersecret"},
    )
    assert r.status_code == 200
    token = r.json()["token"]
    assert r.json()["user"]["role"] == "admin"

    # the token authenticates a protected route
    r = client.get(
        "/api/protected", headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 200
    assert r.json() == {"user": "admin"}

    # setup-required now reports False
    assert (
        client.get("/api/auth/setup-required").json()["setup_required"] is False
    )


def test_signup_disabled_after_first_user(tmp_path: Path) -> None:
    client = _make_full_auth_app(tmp_path)
    client.post(
        "/api/auth/signup",
        json={"username": "admin", "password": "supersecret"},
    )
    r = client.post(
        "/api/auth/signup",
        json={"username": "second", "password": "anothersecret"},
    )
    assert r.status_code == 403


def test_login_with_wrong_password_same_error_as_unknown_user(
    tmp_path: Path,
) -> None:
    client = _make_full_auth_app(tmp_path)
    client.post(
        "/api/auth/signup",
        json={"username": "admin", "password": "supersecret"},
    )
    unknown = client.post(
        "/api/auth/login",
        json={"username": "nobody", "password": "supersecret"},
    )
    wrong = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "wrongpassword"},
    )
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json()["detail"] == wrong.json()["detail"]


def test_me_endpoint_returns_decoded_claims(tmp_path: Path) -> None:
    client = _make_full_auth_app(tmp_path)
    r = client.post(
        "/api/auth/signup",
        json={"username": "alice", "password": "supersecret"},
    )
    token = r.json()["token"]
    r = client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["username"] == "alice"
    assert body["role"] == "admin"


def test_me_without_token_returns_401(tmp_path: Path) -> None:
    client = _make_full_auth_app(tmp_path)
    client.post(
        "/api/auth/signup",
        json={"username": "alice", "password": "supersecret"},
    )
    r = client.get("/api/auth/me")
    assert r.status_code == 401


def _make_saas_auth_app(tmp_path: Path, secret: str = "test-secret") -> TestClient:
    store = UserStore(tmp_path / "users.json")
    app = FastAPI()
    app.add_middleware(JwtAuthMiddleware, secret=secret)
    app.include_router(
        build_auth_router(store=store, secret=secret, mode="saas", trial_days=7),
        prefix="/api/auth",
    )
    return TestClient(app)


def test_setup_required_reports_mode_and_registration(tmp_path: Path) -> None:
    # single-tenant: registration is open only while the store is empty.
    single = _make_full_auth_app(tmp_path / "single")
    body = single.get("/api/auth/setup-required").json()
    assert body["mode"] == "single-tenant"
    assert body["can_register"] is True
    single.post(
        "/api/auth/signup", json={"username": "admin", "password": "supersecret"}
    )
    assert single.get("/api/auth/setup-required").json()["can_register"] is False

    # saas: registration stays open after the first admin.
    saas = _make_saas_auth_app(tmp_path / "saas")
    saas.post(
        "/api/auth/signup", json={"username": "admin", "password": "supersecret"}
    )
    body = saas.get("/api/auth/setup-required").json()
    assert body["mode"] == "saas"
    assert body["can_register"] is True


def test_saas_first_user_is_admin_then_trial(tmp_path: Path) -> None:
    client = _make_saas_auth_app(tmp_path)

    # first signup -> admin, no trial
    first = client.post(
        "/api/auth/signup", json={"username": "owner", "password": "supersecret"}
    ).json()["user"]
    assert first["role"] == "admin"
    assert first["plan"] == "unlimited"
    assert first["trial_ends_at"] is None

    # second signup -> open registration, time-boxed trial user
    second = client.post(
        "/api/auth/signup",
        json={
            "username": "customer",
            "password": "supersecret",
            "email": "customer@example.com",
        },
    ).json()["user"]
    assert second["role"] == "user"
    assert second["plan"] == "trial"
    ends = dt.datetime.fromisoformat(second["trial_ends_at"])
    delta = ends - dt.datetime.now(dt.UTC)
    assert dt.timedelta(days=6) < delta <= dt.timedelta(days=7)


def test_single_tenant_blocks_second_signup_even_for_trial(tmp_path: Path) -> None:
    client = _make_full_auth_app(tmp_path)
    client.post(
        "/api/auth/signup", json={"username": "admin", "password": "supersecret"}
    )
    r = client.post(
        "/api/auth/signup", json={"username": "intruder", "password": "supersecret"}
    )
    assert r.status_code == 403


def test_me_returns_fresh_plan_and_trial(tmp_path: Path) -> None:
    client = _make_saas_auth_app(tmp_path)
    client.post(
        "/api/auth/signup", json={"username": "owner", "password": "supersecret"}
    )
    token = client.post(
        "/api/auth/signup",
        json={
            "username": "customer",
            "password": "supersecret",
            "email": "customer@example.com",
        },
    ).json()["token"]
    me = client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert me.status_code == 200
    assert me.json()["plan"] == "trial"
    assert me.json()["trial_ends_at"] is not None


def _make_avatar_app(
    tmp_path: Path, secret: str = "test-secret"
) -> tuple[TestClient, UserStore]:
    store = UserStore(tmp_path / "users.json")
    storage = LocalAvatarStorage(tmp_path / "avatars")
    app = FastAPI()
    app.add_middleware(JwtAuthMiddleware, secret=secret)
    app.include_router(
        build_auth_router(store=store, secret=secret, avatar_storage=storage),
        prefix="/api/auth",
    )
    return TestClient(app), store


def test_local_avatar_storage_roundtrip_and_guards(tmp_path: Path) -> None:
    storage = LocalAvatarStorage(tmp_path / "avatars")
    url = storage.save("abc123", b"\x89PNG\r\n", "png")
    assert url == "/api/auth/avatars/abc123.png"
    assert storage.resolve("abc123.png") is not None
    # traversal / unknown name / wrong ext are refused
    assert storage.resolve("../users.json") is None
    assert storage.resolve("abc123.exe") is None
    with pytest.raises(ValueError):
        storage.save("abc123", b"x", "exe")
    storage.remove("abc123")
    assert storage.resolve("abc123.png") is None


def test_me_includes_avatar_field(tmp_path: Path) -> None:
    # No avatar_storage here on purpose: the avatar field must round-trip
    # through signup/me regardless of the (multipart-dependent) upload route.
    store = UserStore(tmp_path / "users.json")
    app = FastAPI()
    app.add_middleware(JwtAuthMiddleware, secret="test-secret")
    app.include_router(
        build_auth_router(store=store, secret="test-secret"), prefix="/api/auth"
    )
    client = TestClient(app)
    body = client.post(
        "/api/auth/signup", json={"username": "a", "password": "supersecret"}
    ).json()
    assert body["user"]["avatar"] is None
    store.update(body["user"]["id"], avatar="/api/auth/avatars/x.png")
    me = client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {body['token']}"}
    )
    assert me.json()["avatar"] == "/api/auth/avatars/x.png"


def test_avatar_upload_serve_and_delete(tmp_path: Path) -> None:
    pytest.importorskip("multipart")
    client, _ = _make_avatar_app(tmp_path)
    token = client.post(
        "/api/auth/signup", json={"username": "a", "password": "supersecret"}
    ).json()["token"]
    auth = {"Authorization": f"Bearer {token}"}
    png = b"\x89PNG\r\n\x1a\n" + b"0" * 64

    up = client.post(
        "/api/auth/avatar", headers=auth, files={"file": ("a.png", png, "image/png")}
    )
    assert up.status_code == 200
    avatar = up.json()["avatar"]
    assert avatar.startswith("/api/auth/avatars/")

    name = avatar.rsplit("/", 1)[-1]
    served = client.get(f"/api/auth/avatars/{name}")
    assert served.status_code == 200
    assert served.content == png

    cleared = client.delete("/api/auth/avatar", headers=auth)
    assert cleared.json()["avatar"] is None
    assert client.get(f"/api/auth/avatars/{name}").status_code == 404


def test_avatar_upload_requires_auth(tmp_path: Path) -> None:
    pytest.importorskip("multipart")
    client, _ = _make_avatar_app(tmp_path)
    r = client.post(
        "/api/auth/avatar", files={"file": ("a.png", b"\x89PNG", "image/png")}
    )
    assert r.status_code == 401


def test_level_curve_and_xp_rules() -> None:
    assert level_for_xp(0) == 1
    assert level_for_xp(99) == 1
    assert level_for_xp(100) == 2
    assert level_for_xp(300) == 3
    assert level_progress(150) == (2, 50, 150)
    # base + capped per-finding bonus
    assert xp_for_event("phishing", 0) == 12
    assert xp_for_event("phishing", 3) == 24
    assert xp_for_event("misp", 100) == 48  # 8 + min(100, 10) * 4
    assert xp_for_event("unknown-action", 0) == 8


def test_xp_endpoint_awards_and_levels_up(tmp_path: Path) -> None:
    store = UserStore(tmp_path / "users.json")
    app = FastAPI()
    app.add_middleware(JwtAuthMiddleware, secret="test-secret")
    app.include_router(
        build_auth_router(store=store, secret="test-secret"), prefix="/api/auth"
    )
    client = TestClient(app)
    token = client.post(
        "/api/auth/signup", json={"username": "a", "password": "supersecret"}
    ).json()["token"]
    auth = {"Authorization": f"Bearer {token}"}

    me0 = client.get("/api/auth/me", headers=auth).json()
    assert me0["xp"] == 0
    assert me0["level"] == 1

    first = client.post(
        "/api/auth/xp", headers=auth, json={"action": "phishing", "findings": 3}
    ).json()
    assert first["gained"] == 24
    assert first["user"]["xp"] == 24
    assert first["leveled_up"] is False

    # 24 + 52 + 52 = 128 -> crosses 100 into level 2
    client.post(
        "/api/auth/xp", headers=auth, json={"action": "phishing", "findings": 10}
    )
    crossed = client.post(
        "/api/auth/xp", headers=auth, json={"action": "phishing", "findings": 10}
    ).json()
    assert crossed["user"]["xp"] == 128
    assert crossed["user"]["level"] == 2
    assert crossed["leveled_up"] is True


def _make_licensed_app(tmp_path: Path, secret: str = "test-secret") -> TestClient:
    store = UserStore(tmp_path / "users.json")
    app = FastAPI()
    app.add_middleware(JwtAuthMiddleware, secret=secret)
    app.include_router(
        build_auth_router(
            store=store,
            secret=secret,
            mode="saas",
            license_server_url="http://license.test",
            license_server_api_key="client-key",
        ),
        prefix="/api/auth",
    )
    return TestClient(app)


def _signup_token(client: TestClient, username: str = "a") -> dict[str, str]:
    token = client.post(
        "/api/auth/signup", json={"username": username, "password": "supersecret"}
    ).json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_redeem_license_not_configured_returns_503(tmp_path: Path) -> None:
    client = _make_saas_auth_app(tmp_path)  # no license server configured
    auth = _signup_token(client)
    r = client.post("/api/auth/redeem-license", headers=auth, json={"key": "SOCK-x"})
    assert r.status_code == 503


def test_redeem_valid_license_upgrades_plan(tmp_path: Path) -> None:
    client = _make_licensed_app(tmp_path)
    auth = _signup_token(client)
    with patch(
        "sec_common.auth.routes.validate_license",
        AsyncMock(return_value={"valid": True, "plan": "pro", "expires_at": None}),
    ):
        r = client.post(
            "/api/auth/redeem-license", headers=auth, json={"key": "SOCK-good"}
        )
    assert r.status_code == 200
    body = r.json()
    assert body["plan"] == "pro"
    assert body["trial_ends_at"] is None


def test_redeem_invalid_license_returns_400(tmp_path: Path) -> None:
    client = _make_licensed_app(tmp_path)
    auth = _signup_token(client)
    with patch(
        "sec_common.auth.routes.validate_license",
        AsyncMock(return_value={"valid": False, "reason": "license expired"}),
    ):
        r = client.post(
            "/api/auth/redeem-license", headers=auth, json={"key": "SOCK-bad"}
        )
    assert r.status_code == 400
    assert "expired" in r.json()["detail"]


class _CapturingSender:
    def __init__(self) -> None:
        self.sent: list[dict[str, str]] = []

    def send(self, *, to: str, subject: str, body: str) -> None:
        self.sent.append({"to": to, "subject": subject, "body": body})


def test_saas_signup_requires_valid_email(tmp_path: Path) -> None:
    client = _make_saas_auth_app(tmp_path)
    client.post(
        "/api/auth/signup", json={"username": "admin", "password": "supersecret"}
    )
    r = client.post(
        "/api/auth/signup", json={"username": "x", "password": "supersecret"}
    )
    assert r.status_code == 422


def test_saas_signup_rejects_duplicate_email(tmp_path: Path) -> None:
    client = _make_saas_auth_app(tmp_path)
    client.post(
        "/api/auth/signup", json={"username": "admin", "password": "supersecret"}
    )
    client.post(
        "/api/auth/signup",
        json={"username": "a", "password": "supersecret", "email": "dup@example.com"},
    )
    r = client.post(
        "/api/auth/signup",
        json={"username": "b", "password": "supersecret", "email": "dup@example.com"},
    )
    assert r.status_code == 409


def test_signup_sends_verification_then_verify_flow(tmp_path: Path) -> None:
    store = UserStore(tmp_path / "users.json")
    sender = _CapturingSender()
    app = FastAPI()
    app.add_middleware(JwtAuthMiddleware, secret="test-secret")
    app.include_router(
        build_auth_router(
            store=store,
            secret="test-secret",
            mode="saas",
            email_sender=sender,
            app_base_url="https://app.test",
        ),
        prefix="/api/auth",
    )
    client = TestClient(app)

    # First user = admin: no email, no verification message.
    client.post(
        "/api/auth/signup", json={"username": "admin", "password": "supersecret"}
    )
    assert sender.sent == []

    # SaaS customer: created unverified, a verification email is sent.
    created = client.post(
        "/api/auth/signup",
        json={"username": "cust", "password": "supersecret", "email": "c@example.com"},
    ).json()["user"]
    assert created["email"] == "c@example.com"
    assert created["email_verified"] is False
    assert len(sender.sent) == 1
    assert "https://app.test/verify?token=" in sender.sent[0]["body"]

    token = sender.sent[0]["body"].split("token=")[1].split()[0].strip()
    assert client.post("/api/auth/verify", json={"token": token}).status_code == 200

    login = client.post(
        "/api/auth/login", json={"username": "cust", "password": "supersecret"}
    ).json()
    me = client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {login['token']}"}
    ).json()
    assert me["email_verified"] is True


def test_verify_with_bad_token_returns_400(tmp_path: Path) -> None:
    client = _make_saas_auth_app(tmp_path)
    r = client.post("/api/auth/verify", json={"token": "nope"})
    assert r.status_code == 400


def _make_email_app(tmp_path: Path) -> tuple[TestClient, _CapturingSender]:
    store = UserStore(tmp_path / "users.json")
    sender = _CapturingSender()
    app = FastAPI()
    app.add_middleware(JwtAuthMiddleware, secret="test-secret")
    app.include_router(
        build_auth_router(
            store=store,
            secret="test-secret",
            mode="saas",
            email_sender=sender,
            app_base_url="https://app.test",
        ),
        prefix="/api/auth",
    )
    return TestClient(app), sender


def test_forgot_then_reset_password_flow(tmp_path: Path) -> None:
    client, sender = _make_email_app(tmp_path)
    client.post(
        "/api/auth/signup", json={"username": "admin", "password": "supersecret"}
    )
    client.post(
        "/api/auth/signup",
        json={"username": "cust", "password": "oldpassword", "email": "c@example.com"},
    )
    sender.sent.clear()  # drop the verification email

    forgot = client.post(
        "/api/auth/forgot-password", json={"email": "c@example.com"}
    )
    assert forgot.status_code == 200
    assert len(sender.sent) == 1
    assert "https://app.test/reset?token=" in sender.sent[0]["body"]

    token = sender.sent[0]["body"].split("reset?token=")[1].split()[0].strip()
    reset = client.post(
        "/api/auth/reset-password",
        json={"token": token, "password": "newpassword"},
    )
    assert reset.status_code == 200

    # old password no longer works, the new one does
    assert (
        client.post(
            "/api/auth/login",
            json={"username": "cust", "password": "oldpassword"},
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/auth/login",
            json={"username": "cust", "password": "newpassword"},
        ).status_code
        == 200
    )


def test_forgot_password_unknown_email_is_silent(tmp_path: Path) -> None:
    client, sender = _make_email_app(tmp_path)
    client.post(
        "/api/auth/signup", json={"username": "admin", "password": "supersecret"}
    )
    sender.sent.clear()
    r = client.post(
        "/api/auth/forgot-password", json={"email": "nobody@example.com"}
    )
    assert r.status_code == 200  # no account enumeration
    assert sender.sent == []  # and nothing is sent


def test_reset_with_bad_token_returns_400(tmp_path: Path) -> None:
    client = _make_saas_auth_app(tmp_path)
    r = client.post(
        "/api/auth/reset-password",
        json={"token": "nope", "password": "whatever123"},
    )
    assert r.status_code == 400


def test_login_throttle_locks_and_clears() -> None:
    from sec_common.auth.login_throttle import LoginThrottle

    throttle = LoginThrottle(max_attempts=3, window_seconds=900)
    assert throttle.is_locked("u") is False
    for _ in range(3):
        throttle.record_failure("u")
    assert throttle.is_locked("u") is True
    assert throttle.is_locked("other") is False  # keys are independent
    throttle.record_success("u")
    assert throttle.is_locked("u") is False


def test_login_locks_out_after_repeated_failures(tmp_path: Path) -> None:
    store = UserStore(tmp_path / "users.json")
    app = FastAPI()
    app.add_middleware(JwtAuthMiddleware, secret="test-secret")
    app.include_router(
        build_auth_router(store=store, secret="test-secret", login_max_attempts=3),
        prefix="/api/auth",
    )
    client = TestClient(app)
    client.post(
        "/api/auth/signup", json={"username": "a", "password": "supersecret"}
    )
    for _ in range(3):
        bad = client.post(
            "/api/auth/login", json={"username": "a", "password": "wrongpass"}
        )
        assert bad.status_code == 401
    # Locked now: even the correct password is refused.
    locked = client.post(
        "/api/auth/login", json={"username": "a", "password": "supersecret"}
    )
    assert locked.status_code == 429


def _make_licensed_store_app(tmp_path: Path) -> tuple[TestClient, UserStore]:
    store = UserStore(tmp_path / "users.json")
    app = FastAPI()
    app.add_middleware(JwtAuthMiddleware, secret="test-secret")
    app.include_router(
        build_auth_router(
            store=store,
            secret="test-secret",
            mode="saas",
            license_server_url="http://license.test",
            license_server_api_key="client-key",
        ),
        prefix="/api/auth",
    )
    return TestClient(app), store


def _seed_pro_user(store: UserStore, key: str) -> None:
    pro = store.create(
        username="pro",
        password_hash=hash_password("supersecret"),
        role="user",
        plan="pro",
        email="p@example.com",
        email_verified=True,
    )
    store.update(pro.id, license_key=key)


def test_login_revalidates_and_downgrades_expired_license(tmp_path: Path) -> None:
    client, store = _make_licensed_store_app(tmp_path)
    _seed_pro_user(store, "SOCK-stale")
    with patch(
        "sec_common.auth.routes.validate_license",
        AsyncMock(return_value={"valid": False, "reason": "license expired"}),
    ):
        login = client.post(
            "/api/auth/login",
            json={"username": "pro", "password": "supersecret"},
        ).json()
    assert login["user"]["plan"] == "expired"


def test_login_keeps_plan_when_license_still_valid(tmp_path: Path) -> None:
    client, store = _make_licensed_store_app(tmp_path)
    _seed_pro_user(store, "SOCK-ok")
    with patch(
        "sec_common.auth.routes.validate_license",
        AsyncMock(return_value={"valid": True, "plan": "pro"}),
    ):
        login = client.post(
            "/api/auth/login",
            json={"username": "pro", "password": "supersecret"},
        ).json()
    assert login["user"]["plan"] == "pro"


def test_badges_for_level_milestones() -> None:
    from sec_common.auth.gamification import badges_for

    assert badges_for(1) == []
    ids_at_5 = {b["id"] for b in badges_for(5)}
    assert "apprentice" in ids_at_5
    assert "analyst" in ids_at_5
    assert "veteran" not in ids_at_5  # level 10 not yet reached
    assert {b["id"] for b in badges_for(20)} == {
        "apprentice",
        "analyst",
        "veteran",
        "elite",
    }


def test_me_revalidates_paid_license_when_due(tmp_path: Path) -> None:
    client, store = _make_licensed_store_app(tmp_path)
    _seed_pro_user(store, "SOCK-stale")
    pro = store.get_by_username("pro")
    assert pro is not None
    # A fresh token (no prior login) means the license re-check is due on /me.
    token = encode_token(
        subject=pro.id, username="pro", role="user", secret="test-secret"
    )
    with patch(
        "sec_common.auth.routes.validate_license",
        AsyncMock(return_value={"valid": False, "reason": "revoked"}),
    ):
        me = client.get(
            "/api/auth/me", headers={"Authorization": f"Bearer {token}"}
        ).json()
    assert me["plan"] == "expired"
