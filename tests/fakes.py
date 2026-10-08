"""Deterministic stand-ins for the clock and the sleeper (CLAUDE.md section 6)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

DEFAULT_START = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


class FakeClock:
    """A clock that only moves when the test says so."""

    def __init__(self, start: datetime = DEFAULT_START, monotonic: float = 1000.0) -> None:
        self._now = start
        self._monotonic = monotonic

    def now(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return self._monotonic

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("a clock cannot run backwards")
        self._now += timedelta(seconds=seconds)
        self._monotonic += seconds


class FakeSleeper:
    """Records every requested sleep and advances the fake clock instead of waiting."""

    def __init__(self, clock: FakeClock) -> None:
        self._clock = clock
        self.sleeps: list[float] = []

    def sleep(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("cannot sleep for a negative time")
        self.sleeps.append(seconds)
        self._clock.advance(seconds)
