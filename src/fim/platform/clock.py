"""The real clock and sleeper: the only place that reads the time or waits (CLAUDE.md section 5).

Everything else receives a ``Clock`` and a ``Sleeper`` (core/clock.py), so tests run on a fake
clock and never wait.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime

__all__ = ["SystemClock", "SystemSleeper"]


class SystemClock:
    """Wall-clock time in UTC and a monotonic counter for measuring durations."""

    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        return time.monotonic()


class SystemSleeper:
    """Blocks the calling thread."""

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)
