"""Cache round-trips + TTL expiry.

These exercise the storage layer directly; integration tests for
cache-aware clients live alongside each client.
"""
from __future__ import annotations

import time

import pytest

from sec_common.cache import get_cached, set_cached
from sec_common.cache import db as cache_db


def test_set_then_get_returns_payload() -> None:
    set_cached("vt", "ip", "1.2.3.4", {"positives": 3, "total": 80})
    assert get_cached("vt", "ip", "1.2.3.4") == {"positives": 3, "total": 80}


def test_miss_returns_none() -> None:
    assert get_cached("vt", "ip", "never-seen") is None


def test_set_replaces_existing_entry() -> None:
    set_cached("vt", "ip", "1.2.3.4", {"positives": 1})
    set_cached("vt", "ip", "1.2.3.4", {"positives": 5})
    assert get_cached("vt", "ip", "1.2.3.4") == {"positives": 5}


def test_ttl_expiry_deletes_entry() -> None:
    set_cached("vt", "ip", "1.2.3.4", {"positives": 1}, ttl=-1)
    assert get_cached("vt", "ip", "1.2.3.4") is None


def test_cache_segregates_by_service_and_type() -> None:
    """Same value cached under different (service, type) must not collide."""
    set_cached("vt", "ip", "1.2.3.4", {"src": "vt"})
    set_cached("abuseipdb", "ip", "1.2.3.4", {"src": "abuseipdb"})
    set_cached("vt", "domain", "1.2.3.4", {"src": "vt-domain"})

    assert get_cached("vt", "ip", "1.2.3.4") == {"src": "vt"}
    assert get_cached("abuseipdb", "ip", "1.2.3.4") == {"src": "abuseipdb"}
    assert get_cached("vt", "domain", "1.2.3.4") == {"src": "vt-domain"}


def test_ttl_respected_on_fresh_entry() -> None:
    """A long TTL means a just-written entry should still be readable."""
    set_cached("svc", "qt", "v", {"n": 1}, ttl=60)
    time.sleep(0.05)
    assert get_cached("svc", "qt", "v") == {"n": 1}


def test_unconfigured_cache_raises() -> None:
    """Dropping the engine reference should produce a clear error, not
    a cryptic attribute error at query time."""
    cache_db._engine = None
    cache_db._SessionLocal = None
    with pytest.raises(RuntimeError, match="configure"):
        get_cached("vt", "ip", "x")
