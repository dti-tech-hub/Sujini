"""Thread-safe in-memory rate limiting.

For a single-process academic deployment this is sufficient. A production
deployment should use a shared store (Redis) behind the same interface.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class SlidingWindowRateLimiter:
    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = max(1, int(limit))
        self.window = max(1, int(window_seconds))
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> tuple[bool, float]:
        current = now if now is not None else time.monotonic()
        cutoff = current - self.window
        with self._lock:
            bucket = self._events[key]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.limit:
                retry_after = max(0.0, self.window - (current - bucket[0]))
                return False, retry_after
            bucket.append(current)
            return True, 0.0

    def reset(self) -> None:
        with self._lock:
            self._events.clear()
