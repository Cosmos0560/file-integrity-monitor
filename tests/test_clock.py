"""core/clock.py protocols and the deterministic fakes the other tests rely on."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from fakes import DEFAULT_START, FakeClock, FakeSleeper
from fim.core.clock import Clock, Sleeper


def test_fakes_satisfy_the_protocols() -> None:
    clock: Clock = FakeClock()
    sleeper: Sleeper = FakeSleeper(FakeClock())
    assert isinstance(clock, Clock)
    assert isinstance(sleeper, Sleeper)


def test_objects_without_the_methods_are_not_clocks() -> None:
    assert not isinstance(object(), Clock)
    assert not isinstance(object(), Sleeper)
    assert not isinstance(FakeSleeper(FakeClock()), Clock)


def test_fake_clock_starts_where_told_and_is_timezone_aware() -> None:
    clock = FakeClock()
    assert clock.now() == DEFAULT_START
    assert clock.now().tzinfo is UTC
    other = FakeClock(datetime(2030, 5, 6, tzinfo=UTC), monotonic=5.0)
    assert (other.now().year, other.monotonic()) == (2030, 5.0)


def test_advance_moves_wall_and_monotonic_time_together() -> None:
    clock = FakeClock(monotonic=100.0)
    clock.advance(90.5)
    assert clock.monotonic() == 190.5
    assert (clock.now() - DEFAULT_START).total_seconds() == 90.5


def test_the_clock_cannot_run_backwards() -> None:
    with pytest.raises(ValueError, match="backwards"):
        FakeClock().advance(-1)


def test_sleeper_records_sleeps_and_advances_the_clock_without_waiting() -> None:
    clock = FakeClock(monotonic=0.0)
    sleeper = FakeSleeper(clock)
    sleeper.sleep(300)
    sleeper.sleep(10)
    assert sleeper.sleeps == [300, 10]
    assert clock.monotonic() == 310


def test_sleeper_rejects_negative_durations() -> None:
    with pytest.raises(ValueError, match="negative"):
        FakeSleeper(FakeClock()).sleep(-0.1)
