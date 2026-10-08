"""core/canonical.py and decision D14: storage is exact and never depends on Unicode tables.

Dangerous characters are built with chr(), never written raw.
"""

from __future__ import annotations

import json
import math
import unicodedata
from collections.abc import Callable, Iterator
from typing import Any

import pytest

import factories as make
from fim.core import sanitize
from fim.core.canonical import canonical_json
from fim.core.errors import ModelError
from fim.core.pathrules import record_path, split_record_path

# ---- canonical_json ------------------------------------------------------------------------------


def test_keys_are_sorted_and_separators_fixed() -> None:
    assert canonical_json({"b": 1, "a": [1, 2, {"d": None, "c": True}]}) == (
        b'{"a":[1,2,{"c":true,"d":null}],"b":1}'
    )


def test_equal_data_gives_equal_bytes_whatever_the_insertion_order() -> None:
    assert canonical_json({"x": 1, "y": 2}) == canonical_json({"y": 2, "x": 1})


def test_output_is_pure_ascii_with_lower_case_escapes() -> None:
    out = canonical_json({"k": "caf" + chr(0xE9) + chr(0x202E) + chr(0x1D2C0)})
    assert out.isascii()
    assert out == b'{"k":"caf\\u00e9\\u202e\\ud834\\udec0"}'


def test_a_lone_surrogate_survives_and_round_trips() -> None:
    value = {"p": "a" + chr(0xDC80) + "b" + chr(0xD800)}
    out = canonical_json(value)
    assert out == b'{"p":"a\\udc80b\\ud800"}'
    assert json.loads(out) == value


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_nan_and_infinity_have_no_canonical_form(bad: float) -> None:
    with pytest.raises(ModelError, match="canonical"):
        canonical_json({"v": bad})


@pytest.mark.parametrize("bad", [{1, 2}, b"bytes", {1: "int key"}, {"a": object()}, {(1,): 2}])
def test_values_without_a_json_form_are_refused(bad: Any) -> None:
    with pytest.raises(ModelError, match="canonical"):
        canonical_json(bad)


def test_mixed_key_types_are_refused_not_sorted_arbitrarily() -> None:
    with pytest.raises(ModelError):
        canonical_json({"a": 1, 2: 3})


def test_tuples_are_lists_and_booleans_stay_booleans() -> None:
    assert canonical_json({"a": (1, 2), "b": True, "c": 0}) == b'{"a":[1,2],"b":true,"c":0}'


def test_absurd_nesting_is_refused_instead_of_blowing_the_stack() -> None:
    value: Any = []
    for _ in range(100):
        value = [value]
    with pytest.raises(ModelError, match="deeply"):
        canonical_json(value)


def test_the_error_never_echoes_the_value() -> None:
    with pytest.raises(ModelError) as raised:
        canonical_json({"v": {"secret\x1b": object()}})
    assert "secret" not in str(raised.value)
    assert "\x1b" not in str(raised.value)


# ---- D14: storage keys do not depend on the running Python's Unicode tables ----------------------

# Code points whose general category differs between Unicode 14.0 (Python 3.11), 15.0 (Python
# 3.12) and 15.1 (Python 3.13). The value is the Unicode version that first assigned the code
# point (source: the Unicode Character Database, DerivedAge.txt, versions 15.0 and 15.1). Before
# that version a table reports Cn (unassigned, which the sanitiser escapes); from it, a letter,
# mark or symbol (which the sanitiser leaves readable).
INTRODUCED_IN: dict[int, tuple[int, int]] = {
    0x0CF3: (15, 0),  # KANNADA SIGN COMBINING ANUSVARA ABOVE RIGHT
    0x0ECE: (15, 0),  # LAO YAMAKKAN
    0x10EFD: (15, 0),  # ARABIC SMALL LOW WORD SAKTA
    0x1123F: (15, 0),  # KHOJKI LETTER QA
    0x11B00: (15, 0),  # DEVANAGARI HEAD MARK
    0x11F00: (15, 0),  # KAWI SIGN CANDRABINDU
    0x1D2C0: (15, 0),  # KAKTOVIK NUMERAL ZERO
    0x1E030: (15, 0),  # MODIFIER LETTER CYRILLIC SMALL A
    0x1E4D0: (15, 0),  # NAG MUNDARI LETTER O
    0x31350: (15, 0),  # CJK UNIFIED IDEOGRAPH-31350 (extension H)
    0x1FA75: (15, 0),  # LIGHT BLUE HEART
    0x2FFC: (15, 1),  # IDEOGRAPHIC DESCRIPTION CHARACTER SURROUND FROM RIGHT
    0x31EF: (15, 1),  # IDEOGRAPHIC DESCRIPTION CHARACTER SUBTRACTION
    0x2EBF0: (15, 1),  # CJK UNIFIED IDEOGRAPH-2EBF0 (extension I)
    0x2EE5D: (15, 1),  # CJK UNIFIED IDEOGRAPH-2EE5D (extension I)
}
UNICODE_VERSIONS = {(14, 0): "14.0", (15, 0): "15.0", (15, 1): "15.1"}


REAL_CATEGORY = unicodedata.category


def fake_category_for(version: tuple[int, int]) -> Callable[[str], str]:
    """A ``unicodedata.category`` that behaves like the tables of ``version``."""

    def category(char: str) -> str:
        introduced = INTRODUCED_IN.get(ord(char))
        if introduced is None:
            return REAL_CATEGORY(char)
        return "Cn" if introduced > version else "Lo"

    return category


@pytest.fixture
def unicode_tables(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[tuple[int, int]], None]]:
    """Switch the sanitiser to the tables of a given Unicode version for the test."""

    def use(version: tuple[int, int]) -> None:
        monkeypatch.setattr(unicodedata, "category", fake_category_for(version))
        sanitize._sequence_for.cache_clear()

    yield use
    monkeypatch.undo()
    sanitize._sequence_for.cache_clear()


def sample_parts() -> tuple[str, ...]:
    return tuple(f"n{chr(codepoint)}x" for codepoint in INTRODUCED_IN)


def storage_key(parts: tuple[str, ...]) -> bytes:
    """What the baseline would hold for a record: the exact path, canonical JSON."""
    return canonical_json({"path": record_path(parts)})


def test_the_sample_really_spans_three_unicode_versions() -> None:
    assert set(INTRODUCED_IN.values()) == {(15, 0), (15, 1)}
    assert len(INTRODUCED_IN) >= 10
    # The running Python knows some of them as assigned and, on an older one, some as Cn: either
    # way the sample is meaningful. Show which tables this interpreter has (informational).
    categories = {unicodedata.category(chr(codepoint)) for codepoint in INTRODUCED_IN}
    assert categories <= {"Cn", "Lo", "Mn", "Mc", "Po", "No", "Lm", "So"}


def test_display_depends_on_the_tables_which_is_why_storage_must_not(
    unicode_tables: Callable[[tuple[int, int]], None],
) -> None:
    text = "".join(sample_parts())
    shown: dict[tuple[int, int], str] = {}
    for version in UNICODE_VERSIONS:
        unicode_tables(version)
        shown[version] = sanitize.escape(text)
    # The premise of D14: the same name is displayed differently under different tables.
    assert len({*shown.values()}) == 3
    assert shown[(14, 0)].count("\\u") + shown[(14, 0)].count("\\U") == len(INTRODUCED_IN)
    assert shown[(15, 1)] == text  # nothing escaped once every character is assigned


def test_storage_keys_are_identical_under_unicode_14_15_0_and_15_1(
    unicode_tables: Callable[[tuple[int, int]], None],
) -> None:
    parts = sample_parts()
    keys = {}
    for version in UNICODE_VERSIONS:
        unicode_tables(version)
        keys[version] = storage_key(parts)
    assert len(set(keys.values())) == 1
    key = keys[(15, 1)]
    assert key.isascii()
    assert json.loads(key) == {"path": "/".join(parts)}
    assert split_record_path(json.loads(key)["path"]) == parts


def test_each_code_point_has_one_storage_key_whatever_the_tables(
    unicode_tables: Callable[[tuple[int, int]], None],
) -> None:
    for codepoint in INTRODUCED_IN:
        keys = set()
        for version in UNICODE_VERSIONS:
            unicode_tables(version)
            keys.add(storage_key((chr(codepoint),)))
        assert len(keys) == 1, f"U+{codepoint:04X}"


def test_a_record_with_such_a_name_builds_under_every_table_set(
    unicode_tables: Callable[[tuple[int, int]], None],
) -> None:
    path = record_path(sample_parts())
    for version in UNICODE_VERSIONS:
        unicode_tables(version)
        assert make.record(path=path).path == path


def test_golden_bytes_for_one_bmp_and_one_astral_code_point() -> None:
    assert storage_key((chr(0x0CF3),)) == b'{"path":"\\u0cf3"}'
    assert storage_key((chr(0x1D2C0),)) == b'{"path":"\\ud834\\udec0"}'
    assert storage_key(("a", chr(0xDC80))) == b'{"path":"a/\\udc80"}'


def test_the_real_tables_agree_with_the_simulated_ones_for_old_characters() -> None:
    # A control: characters assigned long ago are not in the sample and never change category.
    assert unicodedata.category("a") == "Ll"
    assert unicodedata.category(chr(0x202E)) == "Cf"
