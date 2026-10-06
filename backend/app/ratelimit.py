"""A small in-process request counter, keyed by source address.

The account lockout (LOGIN_MAX_FAILS) protects one account from guessing, and
nginx throttles the sign-in path per address. Neither covers the endpoints
that do work for anyone without a session - a forgotten-password request
creates a token and sends a mail, every time, for whoever asks. Those need a
per-address ceiling inside the application, where it is enforced regardless
of which proxy sits in front.

Fixed window, in memory, one process: the backend deliberately runs as a
single instance (see deploy/k8s/permitra.yaml), so there is nothing to share.
A restart forgets the counters, which is acceptable - the window is minutes,
and the restart is the rarer event. Stale keys are swept on the way through,
so a long-running process does not accumulate one entry per address it ever
saw.
"""
from __future__ import annotations

import threading
import time


class Window:
    """Allow at most `max_requests` per key within `minutes`."""

    def __init__(self, max_requests: int, minutes: int) -> None:
        self.max_requests = max_requests
        self.minutes = minutes
        self._lock = threading.Lock()
        # key -> (window start, count)
        self._hits: dict[str, tuple[float, int]] = {}
        self._last_sweep = 0.0

    def allow(self, key: str) -> bool:
        """Count a request for `key` and say whether it is within the limit.

        An empty key (no client address at all) is never throttled - that only
        happens outside a real request, and refusing there would hide a bug
        rather than an attacker.
        """
        if not key or self.max_requests <= 0:
            return True
        now = time.monotonic()
        span = self.minutes * 60
        with self._lock:
            if now - self._last_sweep > span:
                self._hits = {k: v for k, v in self._hits.items() if now - v[0] < span}
                self._last_sweep = now
            start, count = self._hits.get(key, (now, 0))
            if now - start >= span:
                start, count = now, 0
            count += 1
            self._hits[key] = (start, count)
            return count <= self.max_requests

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()
