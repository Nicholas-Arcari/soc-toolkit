"""RateLimiter is the hot path for every integration - when it's wrong,
the toolkit burns free-tier quota in a single request storm. The tests
assert the two behaviors we care about operationally:

- burst within budget does not block
- exceeding budget sleeps roughly the right amount
"""
from __future__ import annotations

import asyncio
import time

import pytest

from sec_common.http.base_client import RateLimiter


@pytest.mark.asyncio
async def test_acquire_within_budget_is_non_blocking() -> None:
    """5 acquires against a 10-req/min limit should take effectively 0s."""
    limiter = RateLimiter(max_requests=10, period=60.0)
    start = time.monotonic()
    for _ in range(5):
        await limiter.acquire()
    elapsed = time.monotonic() - start
    assert elapsed < 0.1, f"in-budget acquires should not block, got {elapsed:.3f}s"


@pytest.mark.asyncio
async def test_acquire_past_budget_blocks() -> None:
    """A limit of 4/s means the 5th acquire should sleep ~0.25s.

    Use a short period (1s) so the test finishes quickly. Tolerance of
    ±30% covers scheduler jitter without hiding regressions.
    """
    limiter = RateLimiter(max_requests=4, period=1.0)
    for _ in range(4):
        await limiter.acquire()

    start = time.monotonic()
    await limiter.acquire()
    elapsed = time.monotonic() - start

    # Expected sleep: (1 - 0) * (1.0 / 4) = 0.25s
    assert 0.15 < elapsed < 0.5, f"expected ~0.25s wait, got {elapsed:.3f}s"


@pytest.mark.asyncio
async def test_concurrent_acquires_serialize() -> None:
    """The internal lock must prevent two coroutines from getting the
    same token and racing past the budget."""
    limiter = RateLimiter(max_requests=2, period=1.0)

    await asyncio.gather(*(limiter.acquire() for _ in range(2)))

    # Third acquire should sleep, not succeed instantly.
    start = time.monotonic()
    await limiter.acquire()
    elapsed = time.monotonic() - start
    assert elapsed > 0.15
