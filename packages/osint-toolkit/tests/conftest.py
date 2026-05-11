"""Shared fixtures - in-memory async DB + HTTP client.

Every test sees a fresh SQLite `:memory:` database (via `StaticPool` so
the same connection is reused across the async session) with the full
Alembic schema created from the ORM metadata. No migrations run inside
tests - faster, and isolates the test suite from migration state.
"""
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from api.app import app  # noqa: E402
from api.middleware.rate_limiter import RateLimitMiddleware  # noqa: E402
from db.models import Base  # noqa: E402
from db.session import get_session  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_rate_limiter() -> None:
    """The rate limiter stores request timestamps in a process-global dict
    on the middleware instance. Across a full pytest run those accumulate
    and eventually trip the 30/min cap - not the behavior under test. We
    clear the dict before each test and bump the ceiling high enough that
    one test can never breach it on its own."""
    for m in app.user_middleware:
        if m.cls is RateLimitMiddleware:
            # Starlette instantiates the middleware lazily; we set the
            # max_requests on the options so every new instance starts
            # generous. But the existing instance (if any) also needs
            # its `requests` dict cleared.
            m.kwargs["max_requests"] = 100_000
    # Clear any live instance's state by walking the ASGI app chain.
    current: object = app
    for _ in range(10):
        inst = getattr(current, "app", None)
        if isinstance(current, RateLimitMiddleware):
            current.requests.clear()
            current.max_requests = 100_000
            break
        if inst is None:
            break
        current = inst


@pytest_asyncio.fixture
async def db_session() -> AsyncIterator[AsyncSession]:
    """One isolated in-memory DB per test."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with factory() as session:
        yield session

    await engine.dispose()


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncIterator[AsyncClient]:
    """ASGI client with the session dependency overridden.

    Commits inside the request handler flush to the in-memory DB; the
    session is torn down together with the engine at fixture teardown.
    """

    async def _override_session() -> AsyncIterator[AsyncSession]:
        # Mirror the real `get_session`: commit on success, rollback on
        # failure. Without this, deletes stay in the identity map and
        # subsequent reads in the same test still see the "deleted" row.
        try:
            yield db_session
            await db_session.commit()
        except Exception:
            await db_session.rollback()
            raise

    app.dependency_overrides[get_session] = _override_session
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            yield c
    finally:
        app.dependency_overrides.pop(get_session, None)


@pytest.fixture(autouse=True)
def _isolate_cache(tmp_path, monkeypatch):
    """Redirect sec-common's disk cache to a per-test path.

    Without this, CrtSh/SecurityTrails integration tests would either
    share state between tests or try to write to a DB that doesn't exist
    in the current working directory. The cache schema is also created
    here so tests that use real clients (HIBP, crt.sh) don't fail the
    first ``SELECT`` with "no such table: cache".
    """
    cache_path = tmp_path / "cache.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{cache_path}")
    from sec_common.cache import db as cache_db

    cache_db.configure(f"sqlite+aiosqlite:///{cache_path}")
    cache_db.Base.metadata.create_all(bind=cache_db._engine)
    yield
