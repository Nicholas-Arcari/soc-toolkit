"""Shared fixtures for the sec-common test suite.

The cache module is process-global state keyed on a SQLAlchemy engine.
We reconfigure it to point at a per-test tmp SQLite file so real API
responses can't leak between tests and the engine can be discarded with
the tmpdir.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio

from sec_common.cache import db as cache_db


@pytest_asyncio.fixture(autouse=True)
async def _reset_cache(tmp_path: Path) -> AsyncIterator[None]:
    """Point the cache at a fresh SQLite file for every test.

    Autouse so individual tests don't have to remember. Using a file
    instead of `:memory:` because the cache module uses a sync engine
    and `:memory:` would open a new DB per connection.
    """
    db_path = tmp_path / "cache.sqlite"
    cache_db.configure(f"sqlite:///{db_path}")
    await cache_db.init_db()
    yield
    # Drop module-global engine so the next test can't see stale data
    # even if it forgets to reconfigure.
    cache_db._engine = None
    cache_db._SessionLocal = None


@pytest.fixture
def vt_key() -> str:
    return "fake-vt-key"


@pytest.fixture
def abuseipdb_key() -> str:
    return "fake-abuseipdb-key"
