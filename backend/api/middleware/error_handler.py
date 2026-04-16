import logging

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

logger = logging.getLogger("soc-toolkit")


class ErrorHandlerMiddleware(BaseHTTPMiddleware):
    """Global error handler that returns consistent JSON error responses."""

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        try:
            return await call_next(request)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception(f"Unhandled error: {e}")
            return JSONResponse(
                status_code=500,
                content={
                    "detail": "Internal server error",
                    "type": type(e).__name__,
                },
            )
