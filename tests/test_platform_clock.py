"""platform/clock.py: the real clock, checked by shape and properties, not by wall-clock values."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from fim.core.clock import Clock, Sleeper
from fim.platform.clock import SystemClock, SystemSleeper


def test_the_system_objects_satisfy_the_protocols() -> None:
    assert isinstance(SystemClock(), Clock)
    assert isinstance(SystemSleeper(), Sleeper)


def test_now_is_a_timezone_aware_utc_datetime() -> None:
    now = SystemClock().now()
    assert isinstance(now, datetime)
    assert now.tzinfo is UTC
    assert now.utcoffset() == timedelta(0)


def test_monotonic_never_goes_backwards() -> None:
    clock = SystemClock()
    readings = [clock.monotonic() for _ in range(50)]
    assert readings == sorted(readings)
    assert all(isinstance(reading, float) for reading in readings)


def test_sleeping_for_zero_returns_at_once_and_a_negative_time_is_refused() -> None:
    sleeper = SystemSleeper()
    sleeper.sleep(0)
    with pytest.raises(ValueError, match="non-negative"):
        sleeper.sleep(-1)
