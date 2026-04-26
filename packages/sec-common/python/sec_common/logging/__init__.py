"""Shared structlog wiring for every sec-toolkit app.

The module exposes two entry points:

- :func:`configure_logging` - call once at app startup to set up
  structlog + the standard-library ``logging`` so uvicorn/alembic logs
  also flow through the same renderer.
- :class:`RequestIDMiddleware` - Starlette middleware that binds a
  per-request UUID into structlog's contextvars so every log line
  inside a request handler picks up the same ``request_id``.

Design choice: JSON by default (ready for a log aggregator out of the
box), flip to console renderer when ``FORMAT=console`` - the dev
experience we want locally. Everything else is defaulted; callers just
pass the service name.
"""
from __future__ import annotations

import logging
import sys
import uuid
from collections.abc import MutableMapping
from typing import Any

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp


def configure_logging(
    *,
    service: str,
    level: str = "INFO",
    json: bool = True,
) -> None:
    """Configure structlog + stdlib logging for the given service.

    Safe to call multiple times - structlog's ``configure`` is
    idempotent, and the stdlib handler replacement guards against
    duplicate handlers on re-entry.
    """
    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=True)
    shared_processors: list[structlog.typing.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        timestamper,
        _add_service(service),
    ]

    renderer: structlog.typing.Processor = (
        structlog.processors.JSONRenderer()
        if json
        else structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
    )

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )

    # Route stdlib logging (uvicorn, sqlalchemy, alembic) through the
    # same processors so everything lands in one line-delimited JSON
    # stream.
    stdlib_handler = logging.StreamHandler(sys.stderr)
    stdlib_handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            processor=renderer,
            foreign_pre_chain=shared_processors,
        )
    )
    root = logging.getLogger()
    root.handlers = [stdlib_handler]
    root.setLevel(getattr(logging, level.upper(), logging.INFO))


def _add_service(service: str) -> structlog.typing.Processor:
    """Stamp every event dict with the service name for log routing."""

    def _processor(
        _: Any, __: str, event_dict: MutableMapping[str, Any]
    ) -> MutableMapping[str, Any]:
        event_dict.setdefault("service", service)
        return event_dict

    return _processor


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Bind a request-id into structlog's contextvars for the lifetime of a request.

    Honours an inbound ``X-Request-ID`` if present (useful for tracing
    calls through a load balancer), otherwise generates a short UUID.
    The id lands in every log line emitted inside the handler *and* on
    the response header so clients can correlate their call to our
    logs.
    """

    def __init__(self, app: ASGIApp, header: str = "X-Request-ID") -> None:
        super().__init__(app)
        self.header = header

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        rid = request.headers.get(self.header) or uuid.uuid4().hex[:16]
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=rid,
            method=request.method,
            path=request.url.path,
        )
        try:
            response = await call_next(request)
        finally:
            # Leaving contextvars bound would leak the id into background
            # tasks. Clear on exit so each request sees a clean slate.
            structlog.contextvars.clear_contextvars()
        response.headers[self.header] = rid
        return response


__all__ = ["configure_logging", "RequestIDMiddleware"]
