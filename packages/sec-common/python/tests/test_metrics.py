"""PrometheusMiddleware + /metrics exposition.

Verifies: counter and histogram are populated after a request, the
route template is used (not the raw path) so cardinality stays bounded,
and /metrics returns the Prometheus text format.
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sec_common.metrics import (
    PrometheusMiddleware,
    build_metrics_router,
    new_registry,
)


def _make_app() -> tuple[FastAPI, TestClient]:
    registry = new_registry()
    app = FastAPI()
    app.add_middleware(PrometheusMiddleware, service="test", registry=registry)
    app.include_router(build_metrics_router(registry))

    @app.get("/api/items/{item_id}")
    async def get_item(item_id: int) -> dict[str, int]:
        return {"id": item_id}

    @app.get("/api/boom")
    async def boom() -> None:
        raise RuntimeError("nope")

    return app, TestClient(app, raise_server_exceptions=False)


def test_metrics_endpoint_returns_prometheus_format() -> None:
    _app, client = _make_app()
    client.get("/api/items/42")
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]
    body = r.text
    assert "http_requests_total" in body
    assert "http_request_duration_seconds" in body


def test_requests_total_uses_route_template_not_raw_path() -> None:
    _app, client = _make_app()
    # Two requests, different IDs, same route template.
    client.get("/api/items/1")
    client.get("/api/items/2")
    r = client.get("/metrics")
    # The counter line should carry the template, not the literal "1"/"2".
    assert 'route="/api/items/{item_id}"' in r.text
    assert 'route="/api/items/1"' not in r.text


def test_counter_records_server_errors_as_500() -> None:
    _app, client = _make_app()
    r = client.get("/api/boom")
    assert r.status_code == 500
    metrics = client.get("/metrics").text
    # Unhandled exception path still gets counted so alerting on 5xx works.
    assert 'status_code="500"' in metrics


def test_in_flight_gauge_returns_to_zero_after_request() -> None:
    _app, client = _make_app()
    client.get("/api/items/1")
    metrics = client.get("/metrics").text
    # Gauge back to 0 once the request completed.
    assert 'http_requests_in_flight{method="GET",service="test"} 0.0' in metrics
