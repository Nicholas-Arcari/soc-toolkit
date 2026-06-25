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
from sec_common.cache import configure as configure_cache
from sec_common.cache import init_db
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
from api.routes import (
    fileinspect,
    ioc,
    link,
    logs,
    misp,
    news,
    osint_pivot,
    phishing,
    reports,
    sigma,
    yara,
)
from config import settings

configure_logging(
    service="soc-toolkit",
    level=os.environ.get("LOG_LEVEL", "INFO"),
    json=os.environ.get("LOG_FORMAT", "json").lower() != "console",
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_cache(settings.database_url, echo=settings.is_development)
    await init_db()
    yield


app = FastAPI(
    title="SOC Toolkit",
    description="Modular SOC analyst toolkit - Phishing Analyzer, Log Analyzer, IOC Extractor",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# Middleware order matters: error handler wraps everything, rate limiter
# runs before route handlers, CORS must be outermost for preflight requests.
# RequestIDMiddleware registers last so it runs earliest on the way in -
# the request id must be bound into contextvars before anything else logs.
_metrics_registry = new_registry()

app.add_middleware(ErrorHandlerMiddleware)
# JWT (per-user) runs inside ApiKey (shared-secret proxy gate). Both are
# no-ops when unset, so the default "local dev, no auth" posture holds.
app.add_middleware(JwtAuthMiddleware, secret=settings.auth_secret or None)
app.add_middleware(ApiKeyMiddleware, api_key=settings.api_key)
# Per-request API-key overrides (a SaaS user's own keys, sent from the UI).
app.add_middleware(ApiKeyOverrideMiddleware)
app.add_middleware(RateLimitMiddleware)
# Prometheus sits outside rate-limiting so scrapes don't burn budget,
# and inside RequestIDMiddleware so the per-request id binds before
# we record latency (nice for correlating a long /metrics-lined
# outlier back to a log line).
app.add_middleware(
    PrometheusMiddleware, service="soc-toolkit", registry=_metrics_registry
)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth router is only mounted when per-user auth is configured -
# otherwise first-run setup would silently create users that never get
# validated by the (no-op) JwtAuthMiddleware.
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

app.include_router(phishing.router, prefix="/api/phishing", tags=["Phishing Analyzer"])
app.include_router(logs.router, prefix="/api/logs", tags=["Log Analyzer"])
app.include_router(ioc.router, prefix="/api/ioc", tags=["IOC Extractor"])
app.include_router(osint_pivot.router, prefix="/api/osint", tags=["OSINT Pivot"])
app.include_router(yara.router, prefix="/api/yara", tags=["YARA Scanner"])
app.include_router(misp.router, prefix="/api/misp", tags=["MISP"])
app.include_router(sigma.router, prefix="/api/sigma", tags=["Sigma Rules"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(news.router, prefix="/api/news", tags=["News"])
app.include_router(fileinspect.router, prefix="/api/file", tags=["File Inspector"])
app.include_router(link.router, prefix="/api/link", tags=["Link Analyzer"])


@app.get("/api/health")
async def health_check() -> dict:
    configured_apis = [
        service
        for service in ["virustotal", "abuseipdb", "shodan", "urlscan", "otx", "securitytrails"]
        if settings.has_api_key(service)
    ]
    if settings.has_misp():
        configured_apis.append("misp")
    return {
        "status": "healthy",
        "version": "0.1.0",
        "configured_apis": configured_apis,
    }
