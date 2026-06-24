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

import datetime as dt
import re
import secrets
import time

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from ..email import EmailSender
from .avatars import AvatarStorage
from .gamification import badges_for, level_progress, xp_for_event
from .jwt import TokenError, decode_token, encode_token
from .license_client import validate_license
from .login_throttle import LoginThrottle
from .passwords import hash_password, verify_password
from .store import User, UserStore

# 2 MB is plenty for a profile picture and caps per-upload memory.
_MAX_AVATAR_BYTES = 2 * 1024 * 1024
_CONTENT_TYPE_EXT = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/jpg": "jpg",
    "image/webp": "webp",
    "image/gif": "gif",
}
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _valid_email(email: str) -> bool:
    return bool(_EMAIL_RE.match(email))


def _send_verification(
    sender: EmailSender, base_url: str, email: str, token: str
) -> None:
    link = f"{base_url.rstrip('/')}/verify?token={token}"
    sender.send(
        to=email,
        subject="Verify your SOC Toolkit account",
        body=(
            "Welcome to SOC Toolkit.\n\n"
            f"Confirm your email to activate your account:\n{link}\n\n"
            "If you didn't sign up, you can ignore this message."
        ),
    )


def _send_reset(sender: EmailSender, base_url: str, email: str, token: str) -> None:
    link = f"{base_url.rstrip('/')}/reset?token={token}"
    sender.send(
        to=email,
        subject="Reset your SOC Toolkit password",
        body=(
            "A password reset was requested for your account.\n\n"
            f"Set a new password:\n{link}\n\n"
            "The link expires in 1 hour. If you didn't ask for this, ignore "
            "this message - your password is unchanged."
        ),
    )


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=256)
    email: str = Field(default="", max_length=254)


class UserOut(BaseModel):
    id: str
    username: str
    role: str
    plan: str = "unlimited"
    trial_ends_at: str | None = None
    avatar: str | None = None
    xp: int = 0
    level: int = 1
    xp_into_level: int = 0
    xp_to_next: int = 100
    email: str = ""
    email_verified: bool = False
    badges: list[dict[str, str]] = []


class LoginResponse(BaseModel):
    token: str
    user: UserOut


class XpEvent(BaseModel):
    action: str = Field(min_length=1, max_length=32)
    findings: int = Field(default=0, ge=0, le=10_000)


class XpAward(BaseModel):
    user: UserOut
    gained: int
    leveled_up: bool


class RedeemRequest(BaseModel):
    key: str = Field(min_length=1, max_length=128)


class VerifyRequest(BaseModel):
    token: str = Field(min_length=1, max_length=128)


class ForgotPasswordRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=8, max_length=256)


def build_auth_router(
    *,
    store: UserStore,
    secret: str,
    ttl_minutes: int = 60,
    mode: str = "single-tenant",
    trial_days: int = 7,
    avatar_storage: AvatarStorage | None = None,
    license_server_url: str = "",
    license_server_api_key: str = "",
    email_sender: EmailSender | None = None,
    app_base_url: str = "",
    login_max_attempts: int = 5,
    login_window_seconds: float = 900.0,
) -> APIRouter:
    router = APIRouter()
    mode = (mode or "single-tenant").strip().lower()
    _login_throttle = LoginThrottle(login_max_attempts, login_window_seconds)
    # In-memory per-user timestamp of the last license re-validation, so /me
    # re-checks a paid plan periodically (not on every call) without a DB field.
    _license_checked: dict[str, float] = {}

    async def _revalidate_license(user: User) -> User:
        """Re-check a paid license; downgrade to 'expired' if it no longer validates."""
        if not (
            license_server_url
            and license_server_api_key
            and user.license_key
            and user.plan not in ("trial", "unlimited")
        ):
            return user
        _license_checked[user.id] = time.monotonic()
        check = await validate_license(
            license_server_url, license_server_api_key, user.license_key
        )
        if not check.get("valid"):
            return store.update(user.id, plan="expired", license_key="") or user
        return user

    def _license_recheck_due(user: User) -> bool:
        if user.plan in ("trial", "unlimited") or not user.license_key:
            return False
        last = _license_checked.get(user.id)
        return last is None or (time.monotonic() - last) > 6 * 3600

    def _user_out(user: User) -> UserOut:
        level, into, to_next = level_progress(user.xp)
        return UserOut(
            id=user.id,
            username=user.username,
            role=user.role,
            plan=user.plan,
            trial_ends_at=user.trial_ends_at,
            avatar=user.avatar,
            xp=user.xp,
            level=level,
            xp_into_level=into,
            xp_to_next=to_next,
            email=user.email,
            email_verified=user.email_verified,
            badges=badges_for(level),
        )

    def _authenticated_user(request: Request) -> User:
        # /api/auth/* is exempt from JwtAuthMiddleware (so signup/login run
        # pre-auth), so request.state.user isn't populated here - decode the
        # bearer header ourselves and load the live user from the store.
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="not authenticated")
        try:
            claims = decode_token(header.split(" ", 1)[1].strip(), secret=secret)
        except TokenError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        user = store.get_by_id(claims.sub)
        if user is None:
            raise HTTPException(status_code=401, detail="user no longer exists")
        return user

    @router.get("/setup-required")
    async def setup_required() -> dict[str, object]:
        """Frontend boot probe: signup-vs-login + whether registration is open."""
        empty = store.is_empty()
        return {
            "setup_required": empty,
            "mode": mode,
            "can_register": empty or mode == "saas",
        }

    @router.post("/signup", response_model=LoginResponse)
    async def signup(credentials: Credentials) -> LoginResponse:
        empty = store.is_empty()
        # Single-tenant: only the very first user (the admin) may sign up.
        # SaaS: registration stays open, but every account after the first
        # admin is a time-boxed trial.
        if not empty and mode != "saas":
            raise HTTPException(
                status_code=403,
                detail="signup is disabled once the first user exists",
            )
        email = credentials.email.strip().lower()
        if empty:
            # First user is the operator/admin - no email verification needed.
            role, plan, trial_ends_at = "admin", "unlimited", None
            email_verified, verify_token = True, ""
        else:
            # SaaS trial: a unique, verifiable email is required (anti-abuse).
            if not _valid_email(email):
                raise HTTPException(
                    status_code=422, detail="a valid email is required"
                )
            if store.get_by_email(email) is not None:
                raise HTTPException(
                    status_code=409,
                    detail="an account with this email already exists",
                )
            role, plan = "user", "trial"
            trial_ends_at = (
                dt.datetime.now(dt.UTC) + dt.timedelta(days=trial_days)
            ).isoformat()
            email_verified = False
            verify_token = secrets.token_urlsafe(24)
        user = store.create(
            username=credentials.username,
            password_hash=hash_password(credentials.password),
            role=role,
            plan=plan,
            trial_ends_at=trial_ends_at,
            email=email,
            email_verified=email_verified,
            verify_token=verify_token,
        )
        if verify_token and email_sender is not None:
            _send_verification(email_sender, app_base_url, email, verify_token)
        token = encode_token(
            subject=user.id,
            username=user.username,
            role=user.role,
            secret=secret,
            ttl_minutes=ttl_minutes,
        )
        return LoginResponse(token=token, user=_user_out(user))

    @router.post("/login", response_model=LoginResponse)
    async def login(credentials: Credentials) -> LoginResponse:
        key = credentials.username.strip().lower()
        if _login_throttle.is_locked(key):
            raise HTTPException(
                status_code=429,
                detail="too many failed attempts; try again later",
            )
        user = store.get_by_username(credentials.username)
        # Same error envelope for unknown user and wrong password so the
        # endpoint can't be used to enumerate usernames.
        if user is None or not verify_password(credentials.password, user.password_hash):
            _login_throttle.record_failure(key)
            raise HTTPException(status_code=401, detail="invalid credentials")
        _login_throttle.record_success(key)
        user = await _revalidate_license(user)
        token = encode_token(
            subject=user.id,
            username=user.username,
            role=user.role,
            secret=secret,
            ttl_minutes=ttl_minutes,
        )
        return LoginResponse(token=token, user=_user_out(user))

    @router.get("/me", response_model=UserOut)
    async def me(request: Request) -> UserOut:
        user = _authenticated_user(request)
        if _license_recheck_due(user):
            user = await _revalidate_license(user)
        return _user_out(user)

    @router.post("/xp", response_model=XpAward)
    async def award_user_xp(request: Request, event: XpEvent) -> XpAward:
        user = _authenticated_user(request)
        before_level = level_progress(user.xp)[0]
        gained = xp_for_event(event.action, event.findings)
        updated = store.update(user.id, xp=user.xp + gained) or user
        after_level = level_progress(updated.xp)[0]
        return XpAward(
            user=_user_out(updated),
            gained=gained,
            leveled_up=after_level > before_level,
        )

    @router.post("/redeem-license", response_model=UserOut)
    async def redeem_license(request: Request, body: RedeemRequest) -> UserOut:
        user = _authenticated_user(request)
        if not license_server_url or not license_server_api_key:
            raise HTTPException(
                status_code=503, detail="licensing is not configured"
            )
        result = await validate_license(
            license_server_url, license_server_api_key, body.key
        )
        if not result.get("valid"):
            raise HTTPException(
                status_code=400,
                detail=str(result.get("reason") or "invalid license"),
            )
        plan = str(result.get("plan") or "pro")
        # A paid plan clears the trial window; the key is stored so login can
        # re-validate it against the license-server and downgrade on expiry.
        updated = (
            store.update(
                user.id, plan=plan, trial_ends_at=None, license_key=body.key
            )
            or user
        )
        return _user_out(updated)

    @router.post("/verify")
    async def verify_email(body: VerifyRequest) -> dict[str, bool]:
        user = store.get_by_verify_token(body.token)
        if user is None:
            raise HTTPException(
                status_code=400, detail="invalid or already-used token"
            )
        store.update(user.id, email_verified=True, verify_token="")
        return {"ok": True}

    @router.post("/resend-verification")
    async def resend_verification(request: Request) -> dict[str, bool]:
        user = _authenticated_user(request)
        if user.email_verified or not user.email:
            return {"ok": True}
        token = secrets.token_urlsafe(24)
        store.update(user.id, verify_token=token)
        if email_sender is not None:
            _send_verification(email_sender, app_base_url, user.email, token)
        return {"ok": True}

    @router.post("/forgot-password")
    async def forgot_password(body: ForgotPasswordRequest) -> dict[str, bool]:
        # Always returns ok so the endpoint can't enumerate registered emails.
        user = store.get_by_email(body.email)
        if user is not None and user.email:
            token = secrets.token_urlsafe(24)
            expires = (dt.datetime.now(dt.UTC) + dt.timedelta(hours=1)).isoformat()
            store.update(user.id, reset_token=token, reset_expires_at=expires)
            if email_sender is not None:
                _send_reset(email_sender, app_base_url, user.email, token)
        return {"ok": True}

    @router.post("/reset-password")
    async def reset_password(body: ResetPasswordRequest) -> dict[str, bool]:
        user = store.get_by_reset_token(body.token)
        if user is None:
            raise HTTPException(status_code=400, detail="invalid or used token")
        if user.reset_expires_at:
            try:
                expired = dt.datetime.fromisoformat(
                    user.reset_expires_at
                ) <= dt.datetime.now(dt.UTC)
            except ValueError:
                expired = False
            if expired:
                raise HTTPException(status_code=400, detail="reset link expired")
        store.update(
            user.id,
            password_hash=hash_password(body.password),
            reset_token="",
            reset_expires_at=None,
        )
        return {"ok": True}

    @router.post("/logout")
    async def logout() -> dict[str, bool]:
        # Client-side token discard - server doesn't track sessions.
        return {"ok": True}

    # Avatar routes exist only when the host app wired storage. That keeps
    # the upload route's python-multipart requirement opt-in: an auth router
    # built without storage (e.g. a minimal test app) never pulls it in.
    if avatar_storage is not None:
        storage = avatar_storage

        @router.post("/avatar", response_model=UserOut)
        async def upload_avatar(
            request: Request, file: UploadFile = File(...)
        ) -> UserOut:
            user = _authenticated_user(request)
            ext = _CONTENT_TYPE_EXT.get((file.content_type or "").lower(), "")
            if not ext and file.filename and "." in file.filename:
                ext = file.filename.rsplit(".", 1)[-1].lower()
            data = await file.read()
            if len(data) > _MAX_AVATAR_BYTES:
                raise HTTPException(
                    status_code=413, detail="image too large (max 2 MB)"
                )
            try:
                url = storage.save(user.id, data, ext)
            except ValueError as exc:
                raise HTTPException(status_code=415, detail=str(exc)) from exc
            updated = store.update(user.id, avatar=url)
            return _user_out(updated or user)

        @router.delete("/avatar", response_model=UserOut)
        async def delete_avatar(request: Request) -> UserOut:
            user = _authenticated_user(request)
            storage.remove(user.id)
            updated = store.update(user.id, avatar=None)
            return _user_out(updated or user)

        @router.get("/avatars/{name}")
        async def serve_avatar(name: str) -> FileResponse:
            # Public (auth-exempt prefix) so <img> tags load without a bearer
            # header. `resolve` validates the name + blocks path traversal.
            path = storage.resolve(name)
            if path is None:
                raise HTTPException(status_code=404, detail="not found")
            return FileResponse(path)

    return router


__all__ = ["build_auth_router", "Credentials", "LoginResponse", "UserOut"]
