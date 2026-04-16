from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.middleware.error_handler import ErrorHandlerMiddleware
from api.middleware.rate_limiter import RateLimitMiddleware
from api.routes import ioc, logs, misp, phishing, reports, sigma, yara
from cache.db import init_db
from config import settings


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
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
# runs before route handlers, CORS must be outermost for preflight requests
app.add_middleware(ErrorHandlerMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(phishing.router, prefix="/api/phishing", tags=["Phishing Analyzer"])
app.include_router(logs.router, prefix="/api/logs", tags=["Log Analyzer"])
app.include_router(ioc.router, prefix="/api/ioc", tags=["IOC Extractor"])
app.include_router(yara.router, prefix="/api/yara", tags=["YARA Scanner"])
app.include_router(misp.router, prefix="/api/misp", tags=["MISP"])
app.include_router(sigma.router, prefix="/api/sigma", tags=["Sigma Rules"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])


@app.get("/api/health")
async def health_check() -> dict:
    configured_apis = [
        service
        for service in ["virustotal", "abuseipdb", "shodan", "urlscan", "otx"]
        if settings.has_api_key(service)
    ]
    if settings.has_misp():
        configured_apis.append("misp")
    return {
        "status": "healthy",
        "version": "0.1.0",
        "configured_apis": configured_apis,
    }
