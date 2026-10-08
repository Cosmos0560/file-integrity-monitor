"""Clock and sleeper protocols.

Only platform/clock.py reads the real clock or sleeps (the architecture checker enforces it).
Everything else receives a ``Clock`` and a ``Sleeper``, so tests run on a fake clock with no
real waiting and no wall-clock assertions.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    """A source of time."""

    def now(self) -> datetime:
        """The current time as a timezone-aware UTC datetime."""
        ...

    def monotonic(self) -> float:
        """Seconds from a monotonic clock, for measuring durations and budgets."""
        ...


@runtime_checkable
class Sleeper(Protocol):
    """Something that can wait."""

    def sleep(self, seconds: float) -> None:
        """Block for ``seconds`` (a fake sleeper just advances a fake clock)."""
        ...
