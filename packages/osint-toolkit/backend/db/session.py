"""Async SQLAlchemy session + engine for osint-toolkit.

Separate from sec-common's cache DB - this one's persistent (target
history, scan results). Uses a single shared AsyncEngine per process
and opens a fresh AsyncSession per request via dependency injection.
"""
from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from config import settings
from db.models import Base

_engine = create_async_engine(settings.database_url, echo=settings.is_development)
_SessionFactory = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession)


async def init_db() -> None:
    """Create tables from metadata.

    In production Alembic manages schema (``alembic upgrade head``).
    Called at app startup so local dev works without an explicit
    migration step; ``create_all`` is idempotent.
    """
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency - yields a session, commits on success."""
    async with _SessionFactory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def new_session() -> AsyncSession:
    """A standalone session (not request-scoped) for background persistence."""
    return _SessionFactory()
