import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Add backend to Python path so tests can import modules
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))


@pytest_asyncio.fixture
async def async_client() -> AsyncIterator[AsyncClient]:
    """ASGI client for route-level tests - no external DB / lifespan required.

    The lifespan hook configures the cache DB, which tests don't need
    here; skipping it keeps every route test a fast, in-process call.
    """
    from api.app import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
