"""In-memory per-key login throttle (brute-force mitigation).

Single-process, like the JSON UserStore - fine for one uvicorn worker. Keys
are usernames (lowercased); failures are pruned to a sliding window so a key
unlocks itself once the old attempts age out.
"""
from __future__ import annotations

import threading
import time


class LoginThrottle:
    def __init__(self, max_attempts: int = 5, window_seconds: float = 900.0) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def is_locked(self, key: str) -> bool:
        with self._lock:
            return len(self._recent(key)) >= self.max_attempts

    def record_failure(self, key: str) -> None:
        with self._lock:
            recent = self._recent(key)
            recent.append(time.monotonic())
            self._failures[key] = recent

    def record_success(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)

    def _recent(self, key: str) -> list[float]:
        cutoff = time.monotonic() - self.window_seconds
        return [t for t in self._failures.get(key, []) if t >= cutoff]


__all__ = ["LoginThrottle"]
