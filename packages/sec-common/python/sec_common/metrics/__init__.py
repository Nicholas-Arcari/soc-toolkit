"""Prometheus instrumentation for sec-toolkit backends.

Exposes two building blocks:

- ``PrometheusMiddleware`` - request count + latency + in-flight gauge
  stamped with method, route template, and status class. Route template
  (``/api/ioc/{ioc_id}``) instead of raw path so cardinality stays
  bounded under high-traffic IDs.
- ``build_metrics_router`` - a FastAPI router serving ``/metrics`` with
  the standard Prometheus exposition format.

Apps wire both in ``api/app.py``. The ``/metrics`` endpoint is on the
shared auth middleware's exempt list so a Prometheus scraper can reach
it without provisioning a token.
"""
from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response as StarletteResponse
from starlette.routing import Match
from starlette.types import ASGIApp

# Standard latency buckets - tuned for a mix of sub-second API calls and
# the occasional log-analyzer / YARA scan that crosses a second. Adding
# higher buckets is cheap; removing is an instrumentation break.
_LATENCY_BUCKETS = (
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    30.0,
)


class PrometheusMiddleware(BaseHTTPMiddleware):
    """Record request count, in-flight gauge, and latency histogram.

    Labels: ``service`` (constant), ``method``, ``route`` (template),
    ``status_code``. Route templates keep cardinality bounded - raw
    ``request.url.path`` would explode on per-ID endpoints.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        service: str,
        registry: CollectorRegistry,
    ) -> None:
        super().__init__(app)
        self.service = service
        self.requests_total = Counter(
            "http_requests_total",
            "Total HTTP requests handled by the app.",
            ["service", "method", "route", "status_code"],
            registry=registry,
        )
        self.requests_in_flight = Gauge(
            "http_requests_in_flight",
            "Requests currently being served.",
            ["service", "method"],
            registry=registry,
        )
        self.request_latency = Histogram(
            "http_request_duration_seconds",
            "HTTP request latency in seconds, by route and status.",
            ["service", "method", "route"],
            buckets=_LATENCY_BUCKETS,
            registry=registry,
        )

    def _route_template(self, request: Request) -> str:
        """Resolve the matched route's path template, falling back to the raw path.

        Using ``request.url.path`` directly would explode cardinality on
        endpoints like ``/api/ioc/{ioc_id}``. Starlette exposes the match
        via ``app.router``; we mimic its own resolution logic here.
        """
        router = request.scope.get("app").router  # type: ignore[union-attr]
        for route in router.routes:
            match, _ = route.matches(request.scope)
            if match == Match.FULL:
                return getattr(route, "path", request.url.path)
        return request.url.path

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> StarletteResponse:
        # /metrics scrapes are excluded from instrumentation - otherwise
        # every scrape self-reports (gauge always >0, counter grows at
        # the scrape rate), which is both noise and misleading in
        # dashboards.
        if request.url.path == "/metrics":
            return await call_next(request)

        method = request.method
        self.requests_in_flight.labels(service=self.service, method=method).inc()
        started = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            elapsed = time.perf_counter() - started
            route = self._route_template(request)
            self.requests_total.labels(
                service=self.service,
                method=method,
                route=route,
                status_code=str(status_code),
            ).inc()
            self.request_latency.labels(
                service=self.service,
                method=method,
                route=route,
            ).observe(elapsed)
            self.requests_in_flight.labels(
                service=self.service, method=method
            ).dec()


def build_metrics_router(registry: CollectorRegistry) -> APIRouter:
    """Expose ``/metrics`` in Prometheus text-exposition format."""
    router = APIRouter()

    @router.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        return Response(
            content=generate_latest(registry),
            media_type=CONTENT_TYPE_LATEST,
        )

    return router


def new_registry() -> CollectorRegistry:
    """Private registry per app - keeps two FastAPI apps in the same
    process (tests, notebook) from re-registering the same collector.
    """
    return CollectorRegistry()


__all__: list[Any] = [
    "PrometheusMiddleware",
    "build_metrics_router",
    "new_registry",
]
