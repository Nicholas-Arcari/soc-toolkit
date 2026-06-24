"""Sliding-window rate limiter."""

from sec_common.ratelimit import SlidingWindowLimiter


def test_caps_then_blocks_and_keys_are_independent() -> None:
    limiter = SlidingWindowLimiter(max_events=3, window_seconds=60)
    assert [limiter.allow("ip") for _ in range(3)] == [True, True, True]
    assert limiter.allow("ip") is False  # 4th request is over the cap
    assert limiter.allow("other") is True  # a different key is unaffected
