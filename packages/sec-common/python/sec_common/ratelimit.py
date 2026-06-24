"""Generic in-memory sliding-window rate limiter.

Process-local (one uvicorn worker), like the auth store and login throttle.
Used to cap the outbound-fetch endpoints (link tracer, website fingerprint)
per client so the server can't be driven as a high-volume scanning proxy.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict


class SlidingWindowLimiter:
    def __init__(self, max_events: int, window_seconds: float) -> None:
        self.max_events = max_events
        self.window_seconds = window_seconds
        self._events: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        """Record an event for ``key``; return False if over the limit."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            recent = [t for t in self._events[key] if t >= cutoff]
            if len(recent) >= self.max_events:
                self._events[key] = recent
                return False
            recent.append(now)
            self._events[key] = recent
            return True


__all__ = ["SlidingWindowLimiter"]
