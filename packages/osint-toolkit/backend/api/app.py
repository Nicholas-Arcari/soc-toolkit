import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sec_common.auth import (
    ApiKeyMiddleware,
    JwtAuthMiddleware,
    LocalAvatarStorage,
    UserStore,
    build_auth_router,
)
from sec_common.email import ConsoleEmailSender, SmtpEmailSender
from sec_common.logging import RequestIDMiddleware, configure_logging
from sec_common.metrics import (
    PrometheusMiddleware,
    build_metrics_router,
    new_registry,
)
from sec_common.runtime_keys import ApiKeyOverrideMiddleware

from api.middleware.error_handler import ErrorHandlerMiddleware
from api.middleware.rate_limiter import RateLimitMiddleware
from api.routes import investigate, reports, scans, targets
from config import settings
from db.session import init_db

# Format=console (human-readable) in dev, JSON (default) in containers.
configure_logging(
    service="osint-toolkit",
    level=os.environ.get("LOG_LEVEL", "INFO"),
    json=os.environ.get("LOG_FORMAT", "json").lower() != "console",
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Tables are created via Alembic migrations in production
    # (`alembic upgrade head`). init_db here creates them from metadata
    # for dev convenience - harmless when migrations are already applied
    # because create_all is idempotent.
    await init_db()
    yield


app = FastAPI(
    title="OSINT Toolkit",
    description=(
        "Attack surface management + investigative OSINT. "
        "Passive by default - active scans are gated behind a config flag "
        "and explicit authorization acknowledgment per target."
    ),
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

_metrics_registry = new_registry()

app.add_middleware(ErrorHandlerMiddleware)
# JWT (per-user) + ApiKey (shared-secret proxy gate) stack. Both no-op
# when unconfigured, so defaults match "local dev, no auth".
app.add_middleware(JwtAuthMiddleware, secret=settings.auth_secret or None)
app.add_middleware(ApiKeyMiddleware, api_key=settings.api_key)
# Per-request API-key overrides (a SaaS user's own keys, sent from the UI).
app.add_middleware(ApiKeyOverrideMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    PrometheusMiddleware, service="osint-toolkit", registry=_metrics_registry
)
# RequestIDMiddleware must be registered last so it runs first on the
# request way in - binding the id before anything else logs.
app.add_middleware(RequestIDMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


if settings.has_auth():
    _user_store = UserStore(Path(settings.auth_users_file))
    _email_sender = (
        SmtpEmailSender(
            host=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_username,
            password=settings.smtp_password,
            from_addr=settings.smtp_from,
            starttls=settings.smtp_starttls,
        )
        if settings.has_smtp()
        else ConsoleEmailSender()
    )
    app.include_router(
        build_auth_router(
            store=_user_store,
            secret=settings.auth_secret,
            ttl_minutes=settings.auth_token_ttl_minutes,
            mode=settings.auth_mode,
            trial_days=settings.trial_days,
            avatar_storage=LocalAvatarStorage(Path(settings.avatar_dir)),
            license_server_url=settings.license_server_url,
            license_server_api_key=settings.license_server_api_key,
            email_sender=_email_sender,
            app_base_url=settings.app_base_url,
            login_max_attempts=settings.login_max_attempts,
            login_window_seconds=settings.login_window_seconds,
        ),
        prefix="/api/auth",
        tags=["Authentication"],
    )

app.include_router(build_metrics_router(_metrics_registry))

app.include_router(targets.router, prefix="/api/targets", tags=["targets"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(investigate.router, prefix="/api/investigate", tags=["investigate"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])


@app.get("/api/health")
async def health_check() -> dict[str, object]:
    configured_apis = [
        service
        for service in ["virustotal", "shodan", "urlscan", "securitytrails"]
        if settings.has_api_key(service)
    ]
    return {
        "status": "healthy",
        "version": "0.1.0",
        "toolkit": "osint",
        "configured_apis": configured_apis,
        "active_scanning_enabled": settings.enable_active_scanning,
    }
