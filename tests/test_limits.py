"""core/limits.py: defaults, hard ceilings, validation and drift against PLAN.md D11."""

from __future__ import annotations

import dataclasses
import re
from typing import Any

import pytest

from fim.core import limits
from fim.core.errors import ConfigError
from fim.core.limits import CEILINGS, DEFAULT_LIMITS, Limits
from plan_doc import parse_quantity, section

FIELD_NAMES = [f.name for f in dataclasses.fields(Limits)]


def test_defaults_are_the_module_constants() -> None:
    assert Limits() == DEFAULT_LIMITS
    for name in FIELD_NAMES:
        assert getattr(DEFAULT_LIMITS, name) == getattr(limits, name.upper())
        assert getattr(CEILINGS, name) == getattr(limits, name.upper() + "_CEILING")


@pytest.mark.parametrize("name", FIELD_NAMES)
def test_a_default_never_exceeds_its_ceiling_and_is_positive(name: str) -> None:
    default = getattr(DEFAULT_LIMITS, name)
    ceiling = getattr(CEILINGS, name)
    assert 1 <= default <= ceiling


def test_ceilings_are_the_documented_hard_values() -> None:
    assert CEILINGS.max_files == 1_000_000
    assert CEILINGS.max_depth == 128
    assert CEILINGS.max_hash_file_bytes == 4 * 1024**3
    assert CEILINGS.max_run_seconds == 3600
    assert limits.HASH_CHUNK_BYTES == 1024**2
    assert (
        limits.WATCH_INTERVAL_MIN_SECONDS,
        limits.WATCH_INTERVAL_DEFAULT_SECONDS,
        limits.WATCH_INTERVAL_MAX_SECONDS,
    ) == (10, 300, 86_400)


def test_with_no_overrides_the_limits_are_unchanged() -> None:
    assert DEFAULT_LIMITS.with_overrides({}) == DEFAULT_LIMITS


def test_overrides_may_lower_a_limit() -> None:
    lowered = DEFAULT_LIMITS.with_overrides({"max_files": 100, "max_depth": 3})
    assert (lowered.max_files, lowered.max_depth) == (100, 3)
    assert lowered.max_roots == DEFAULT_LIMITS.max_roots


def test_overrides_may_raise_a_limit_up_to_its_ceiling() -> None:
    raised = DEFAULT_LIMITS.with_overrides({"max_files": limits.MAX_FILES_CEILING})
    assert raised.max_files == 1_000_000


@pytest.mark.parametrize("name", FIELD_NAMES)
def test_one_above_the_ceiling_is_refused(name: str) -> None:
    ceiling = getattr(CEILINGS, name)
    with pytest.raises(ConfigError) as raised:
        DEFAULT_LIMITS.with_overrides({name: ceiling + 1})
    assert name in str(raised.value)
    assert "ceiling" in str(raised.value)


@pytest.mark.parametrize("name", FIELD_NAMES)
@pytest.mark.parametrize("value", [0, -1, -(10**9)])
def test_zero_and_negative_values_are_refused(name: str, value: int) -> None:
    with pytest.raises(ConfigError, match="at least 1"):
        DEFAULT_LIMITS.with_overrides({name: value})


@pytest.mark.parametrize("value", [True, False, "100", 1.5, None, [1], 2**100])
def test_wrong_types_and_huge_numbers_are_refused(value: Any) -> None:
    with pytest.raises(ConfigError):
        DEFAULT_LIMITS.with_overrides({"max_files": value})


def test_unknown_limit_names_are_refused() -> None:
    with pytest.raises(ConfigError, match="unknown limit 'max_everything'"):
        DEFAULT_LIMITS.with_overrides({"max_everything": 5})


def test_a_hostile_limit_name_is_scrubbed_in_the_error() -> None:
    with pytest.raises(ConfigError) as raised:
        DEFAULT_LIMITS.with_overrides({"bad\x1b[31m": 5})
    assert "\x1b" not in str(raised.value)


def test_constructing_limits_directly_is_validated_too() -> None:
    with pytest.raises(ConfigError):
        Limits(max_files=limits.MAX_FILES_CEILING + 1)
    with pytest.raises(ConfigError):
        Limits(max_depth=0)


def test_limits_are_immutable() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        DEFAULT_LIMITS.max_files = 5  # type: ignore[misc]  # proving the dataclass is frozen


def test_failed_override_leaves_the_original_untouched() -> None:
    before = dataclasses.astuple(DEFAULT_LIMITS)
    with pytest.raises(ConfigError):
        DEFAULT_LIMITS.with_overrides({"max_files": 0})
    assert dataclasses.astuple(DEFAULT_LIMITS) == before


# ---- drift: PLAN.md D11 table against the constants -------------------------------------------


def _d11_rows() -> list[tuple[str, str, str]]:
    rows = []
    for line in section("### D11").splitlines():
        if line.startswith(("| `", "| watch")):
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            rows.append((cells[0], cells[1], cells[2]))
    return rows


def _expected(names: list[str]) -> list[tuple[int, int | None]]:
    out: list[tuple[int, int | None]] = []
    for name in names:
        default = getattr(limits, name)
        ceiling = getattr(limits, name + "_CEILING", None)
        out.append((default, ceiling))
    return out


def test_d11_table_matches_limits_py() -> None:
    rows = _d11_rows()
    assert len(rows) == 14
    documented_names: set[str] = set()
    for label, default_cell, ceiling_cell in rows:
        if label.startswith("watch interval"):
            parts = [parse_quantity(part) for part in default_cell.split("/")]
            assert parts == [
                limits.WATCH_INTERVAL_MIN_SECONDS,
                limits.WATCH_INTERVAL_DEFAULT_SECONDS,
                limits.WATCH_INTERVAL_MAX_SECONDS,
            ]
            continue
        names = re.findall(r"`(\w+)`", label)
        documented_names.update(names)
        defaults = [parse_quantity(part) for part in default_cell.split("/")]
        if ceiling_cell == "same":
            ceilings: list[int | None] = list(defaults)
        elif ceiling_cell == "-":
            ceilings = [None] * len(names)
        else:
            ceilings = [parse_quantity(part) for part in ceiling_cell.split("/")]
        expected = _expected(names)
        assert [d for d, _ in expected] == defaults, label
        assert [c for _, c in expected] == ceilings, label
    # every MAX_* default in limits.py is documented, and the other way round
    in_code = {
        name
        for name in dir(limits)
        if re.fullmatch(r"MAX_[A-Z_]+", name) and not name.endswith("_CEILING")
    }
    assert documented_names - {"HASH_CHUNK_BYTES"} == in_code
