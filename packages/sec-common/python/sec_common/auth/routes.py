"""FastAPI router exposing /api/auth/{signup,login,me,logout}.

The router is constructed by ``build_auth_router`` so each app can pass
its own ``UserStore`` path and JWT secret without a global singleton.
Apps mount it under ``/api/auth``.

Security posture:
- signup is gated on an empty store (first-run admin setup only). After
  the first user exists, signup returns 403 and new users must be
  provisioned out-of-band (CLI or manual edit) - avoids exposing a
  self-registration endpoint on an internet-facing install.
- login returns a JWT plus the user record (username/role) so the
  frontend can render the right nav without an extra /me round-trip.
- /me echoes the decoded claims for session-restore on page reload.
- logout is a no-op server-side (stateless JWT) but kept so the frontend
  has a symmetric endpoint to call.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from .jwt import TokenError, decode_token, encode_token
from .passwords import hash_password, verify_password
from .store import UserStore


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=256)


class UserOut(BaseModel):
    id: str
    username: str
    role: str


class LoginResponse(BaseModel):
    token: str
    user: UserOut


def build_auth_router(*, store: UserStore, secret: str, ttl_minutes: int = 60) -> APIRouter:
    router = APIRouter()

    @router.get("/setup-required")
    async def setup_required() -> dict[str, bool]:
        """Frontend calls this on boot to decide whether to show signup or login."""
        return {"setup_required": store.is_empty()}

    @router.post("/signup", response_model=LoginResponse)
    async def signup(credentials: Credentials) -> LoginResponse:
        if not store.is_empty():
            raise HTTPException(
                status_code=403,
                detail="signup is disabled once the first user exists",
            )
        user = store.create(
            username=credentials.username,
            password_hash=hash_password(credentials.password),
            role="admin",
        )
        token = encode_token(
            subject=user.id,
            username=user.username,
            role=user.role,
            secret=secret,
            ttl_minutes=ttl_minutes,
        )
        return LoginResponse(
            token=token,
            user=UserOut(id=user.id, username=user.username, role=user.role),
        )

    @router.post("/login", response_model=LoginResponse)
    async def login(credentials: Credentials) -> LoginResponse:
        user = store.get_by_username(credentials.username)
        # Same error envelope for unknown user and wrong password so the
        # endpoint can't be used to enumerate usernames.
        if user is None or not verify_password(credentials.password, user.password_hash):
            raise HTTPException(status_code=401, detail="invalid credentials")
        token = encode_token(
            subject=user.id,
            username=user.username,
            role=user.role,
            secret=secret,
            ttl_minutes=ttl_minutes,
        )
        return LoginResponse(
            token=token,
            user=UserOut(id=user.id, username=user.username, role=user.role),
        )

    @router.get("/me", response_model=UserOut)
    async def me(request: Request) -> UserOut:
        # /api/auth/ is in the middleware exempt list (so signup/login
        # can run pre-auth), which means request.state.user isn't
        # populated on this path. Decode the header ourselves.
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="not authenticated")
        try:
            claims = decode_token(header.split(" ", 1)[1].strip(), secret=secret)
        except TokenError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        return UserOut(id=claims.sub, username=claims.username, role=claims.role)

    @router.post("/logout")
    async def logout() -> dict[str, bool]:
        # Client-side token discard - server doesn't track sessions.
        return {"ok": True}

    return router


__all__ = ["build_auth_router", "Credentials", "LoginResponse", "UserOut"]
