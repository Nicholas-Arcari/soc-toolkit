"""JWT auth: token codec, password hashing, user store, middleware, routes.

Covers the full auth layer end-to-end: issuing a JWT, verifying it,
gating a protected route, first-run signup flow, and the "signup is
disabled after the first user exists" safeguard.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.responses import JSONResponse

from sec_common.auth import (
    JwtAuthMiddleware,
    TokenError,
    UserStore,
    build_auth_router,
    decode_token,
    encode_token,
    hash_password,
    verify_password,
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
    past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
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


def test_user_store_survives_corrupt_file(tmp_path: Path) -> None:
    path = tmp_path / "users.json"
    path.write_text("not json {")
    store = UserStore(path)
    # Treat corrupt store as empty - app boots, operator can rebuild.
    assert store.is_empty()


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
    assert r.json() == {"setup_required": True}

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
    assert client.get("/api/auth/setup-required").json() == {
        "setup_required": False
    }


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
