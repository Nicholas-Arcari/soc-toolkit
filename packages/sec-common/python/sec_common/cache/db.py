"""SQLite cache for external API responses.

Lazy-initialized so sec-common can live independently of any app's config
module. Apps call `configure(database_url, echo=...)` at startup before
triggering `init_db()` or any `get_cached`/`set_cached` call.
"""
import asyncio
import json
import time

from sqlalchemy import Engine, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class CacheEntry(Base):
    __tablename__ = "cache"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    service: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    query_type: Mapped[str] = mapped_column(String(50), nullable=False)
    query_value: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    response: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[float] = mapped_column(nullable=False, default=time.time)
    ttl: Mapped[int] = mapped_column(nullable=False, default=3600)


_engine: Engine | None = None
_SessionLocal: sessionmaker | None = None


def configure(database_url: str, echo: bool = False) -> None:
    """Bind the cache module to a SQLAlchemy engine.

    Must be called once at app startup. The aiosqlite driver is stripped
    because the cache uses a sync engine (SQLite DDL is fast and the cache
    doesn't benefit from async).
    """
    global _engine, _SessionLocal
    _engine = create_engine(database_url.replace("+aiosqlite", ""), echo=echo)
    _SessionLocal = sessionmaker(bind=_engine)


def _require_session_factory() -> sessionmaker:
    if _SessionLocal is None:
        raise RuntimeError(
            "sec_common.cache.db.configure() must be called before using the cache"
        )
    return _SessionLocal


async def init_db() -> None:
    """Create tables. Idempotent. Requires configure() to have been called."""
    if _engine is None:
        raise RuntimeError("configure() must be called before init_db()")
    await asyncio.to_thread(Base.metadata.create_all, bind=_engine)


def get_cached(service: str, query_type: str, query_value: str) -> dict | None:
    """Get a cached API response if it exists and hasn't expired.

    Caching is critical for free-tier APIs: without it, analyzing an email
    with 10 URLs would burn 10 VirusTotal requests (out of 4/min). With
    cache, repeated analysis of the same IOC costs zero API calls.
    """
    SessionLocal = _require_session_factory()  # noqa: N806 - SQLAlchemy sessionmaker convention
    with SessionLocal() as session:
        entry = (
            session.query(CacheEntry)
            .filter_by(service=service, query_type=query_type, query_value=query_value)
            .first()
        )

        if entry is None:
            return None

        if time.time() - entry.created_at > entry.ttl:
            session.delete(entry)
            session.commit()
            return None

        return json.loads(entry.response)


def set_cached(
    service: str,
    query_type: str,
    query_value: str,
    response: dict,
    ttl: int = 3600,
) -> None:
    """Cache an API response."""
    SessionLocal = _require_session_factory()  # noqa: N806 - SQLAlchemy sessionmaker convention
    with SessionLocal() as session:
        existing = (
            session.query(CacheEntry)
            .filter_by(service=service, query_type=query_type, query_value=query_value)
            .first()
        )

        if existing:
            existing.response = json.dumps(response)
            existing.created_at = time.time()
            existing.ttl = ttl
        else:
            entry = CacheEntry(
                service=service,
                query_type=query_type,
                query_value=query_value,
                response=json.dumps(response),
                created_at=time.time(),
                ttl=ttl,
            )
            session.add(entry)

        session.commit()
