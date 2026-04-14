import asyncio
import json
import time

from sqlalchemy import Column, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from config import settings


class Base(DeclarativeBase):
    pass


class CacheEntry(Base):
    __tablename__ = "cache"

    id = Column(Integer, primary_key=True, autoincrement=True)
    service = Column(String(50), nullable=False, index=True)
    query_type = Column(String(50), nullable=False)
    query_value = Column(String(500), nullable=False, index=True)
    response = Column(Text, nullable=False)
    created_at = Column(Float, nullable=False, default=time.time)
    ttl = Column(Integer, nullable=False, default=3600)


# Use sync engine for SQLite (simpler, no async overhead needed for cache)
engine = create_engine(
    settings.database_url.replace("+aiosqlite", ""),
    echo=settings.is_development,
)
SessionLocal = sessionmaker(bind=engine)


async def init_db():
    """Initialize the database and create tables.

    Runs the sync create_all in a thread to avoid blocking the async event
    loop during startup - SQLite DDL is fast but should not block coroutines.
    """
    await asyncio.to_thread(Base.metadata.create_all, bind=engine)


def get_cached(service: str, query_type: str, query_value: str) -> dict | None:
    """Get a cached API response if it exists and hasn't expired.

    Caching is critical for free-tier APIs: without it, analyzing an email
    with 10 URLs would burn 10 VirusTotal requests (out of 4/min). With
    cache, repeated analysis of the same IOC costs zero API calls.
    """
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

        return json.loads(str(entry.response))


def set_cached(
    service: str,
    query_type: str,
    query_value: str,
    response: dict,
    ttl: int = 3600,
):
    """Cache an API response."""
    with SessionLocal() as session:
        existing = (
            session.query(CacheEntry)
            .filter_by(service=service, query_type=query_type, query_value=query_value)
            .first()
        )

        if existing:
            existing.response = json.dumps(response)  # type: ignore[assignment]
            existing.created_at = time.time()  # type: ignore[assignment]
            existing.ttl = ttl  # type: ignore[assignment]
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
