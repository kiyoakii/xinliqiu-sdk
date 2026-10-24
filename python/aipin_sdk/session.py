# -*- coding: utf-8 -*-
"""Connection caching.

Every probe invocation authenticates from scratch (3-5 s).  To avoid paying
that on every call the session keeps a cached credential validity window: if a
successful operation finished less than `ttl` seconds ago, callers may skip
any optimistic pre-checks.  The probe itself is always invoked; this cache only
affects SDK-side heuristics.
"""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class SessionState:
    ttl: float = 30.0
    last_success: float | None = None
    last_error: str | None = None

    def mark_success(self) -> None:
        self.last_success = time.monotonic()
        self.last_error = None

    def mark_failure(self, reason: str) -> None:
        self.last_error = reason

    @property
    def warm(self) -> bool:
        if self.last_success is None:
            return False
        return (time.monotonic() - self.last_success) < self.ttl
