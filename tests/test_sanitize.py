"""core/sanitize.py: one escaper, injective and reversible, nothing dangerous survives (D10).

Dangerous characters are written as code points or escapes in this file, never raw.
"""

from __future__ import annotations

import itertools
import random
import unicodedata

import pytest

from fim.core import sanitize

DANGEROUS_CATEGORIES = {"Cc", "Cf", "Co", "Cn", "Zl", "Zp", "Cs"}


def survives_safely(text: str) -> bool:
    """True if no character of ``text`` is one the sanitiser promises to remove."""
    for char in text:
        category = unicodedata.category(char)
        if category in DANGEROUS_CATEGORIES:
            return False
        if category == "Zs" and ord(char) > 0x7F:
            return False
    return True


ESCAPE_TABLE = [
    pytest.param("plain.txt", "plain.txt", id="plain-ascii"),
    pytest.param("with space", "with space", id="ascii-space-kept"),
    pytest.param("", "", id="empty"),
    pytest.param("a\\b", "a\\\\b", id="backslash-doubled"),
    pytest.param("\\\\", "\\\\\\\\", id="two-backslashes"),
    pytest.param("\x1b[31mred", "\\x1b[31mred", id="ansi-escape"),
    pytest.param("line1\nline2", "line1\\x0aline2", id="newline"),
    pytest.param("a\rb", "a\\x0db", id="carriage-return"),
    pytest.param("a\tb", "a\\x09b", id="tab"),
    pytest.param("a\x00b", "a\\x00b", id="nul"),
    pytest.param("\x7f", "\\x7f", id="del"),
    pytest.param("\x85", "\\x85", id="c1-next-line"),
    pytest.param("\x9f", "\\x9f", id="c1-last"),
    pytest.param(chr(0x202E), "\\u202e", id="bidi-override"),
    pytest.param(chr(0x2066), "\\u2066", id="bidi-isolate"),
    pytest.param(chr(0x200B), "\\u200b", id="zero-width-space"),
    pytest.param(chr(0xFEFF), "\\ufeff", id="bom"),
    pytest.param(chr(0x00AD), "\\u00ad", id="soft-hyphen"),
    pytest.param(chr(0x2028), "\\u2028", id="line-separator"),
    pytest.param(chr(0x2029), "\\u2029", id="paragraph-separator"),
    pytest.param(chr(0xE000), "\\ue000", id="private-use"),
    pytest.param(chr(0x0378), "\\u0378", id="unassigned"),
    pytest.param(chr(0x00A0), "\\u00a0", id="no-break-space"),
    pytest.param(chr(0x3000), "\\u3000", id="ideographic-space"),
    pytest.param(chr(0xE0001), "\\U000e0001", id="tag-character-outside-bmp"),
    pytest.param(chr(0xF0000), "\\U000f0000", id="private-use-plane-15"),
    pytest.param(chr(0x10FFFF), "\\U0010ffff", id="last-codepoint"),
    pytest.param(chr(0xD800), "\\ud800", id="lone-high-surrogate"),
    pytest.param(chr(0xDC7F), "\\udc7f", id="surrogate-below-escape-range"),
    pytest.param(chr(0xDC80), "\\y80", id="undecodable-byte-80"),
    pytest.param(chr(0xDCFF), "\\yff", id="undecodable-byte-ff"),
    pytest.param("caf\u00e9", "caf\u00e9", id="latin-letters-stay"),
    pytest.param("\u0436\u0443\u043a", "\u0436\u0443\u043a", id="cyrillic-stays"),
    pytest.param("\u65e5\u672c\u8a9e", "\u65e5\u672c\u8a9e", id="cjk-stays"),
    pytest.param("\U0001f600", "\U0001f600", id="emoji-stays"),
    pytest.param("a" + chr(0x202E) + "txt.exe", "a\\u202etxt.exe", id="rtl-extension-trick"),
]


@pytest.mark.parametrize(("raw", "expected"), ESCAPE_TABLE)
def test_escape_table(raw: str, expected: str) -> None:
    assert sanitize.escape(raw) == expected


@pytest.mark.parametrize(("raw", "expected"), ESCAPE_TABLE)
def test_escape_then_unescape_returns_the_original(raw: str, expected: str) -> None:
    assert sanitize.unescape(sanitize.escape(raw)) == raw
    assert sanitize.unescape(expected) == raw


def test_plain_text_is_returned_unchanged_without_copying() -> None:
    text = "just/a plain path-1.txt"
    assert sanitize.escape(text) is text


def test_a_raw_backslash_x_sequence_and_a_real_control_character_stay_distinct() -> None:
    literal = "\\x1b"  # four characters: backslash, x, 1, b
    control = "\x1b"
    assert sanitize.escape(literal) == "\\\\x1b"
    assert sanitize.escape(control) == "\\x1b"
    assert sanitize.escape(literal) != sanitize.escape(control)
    assert sanitize.unescape("\\\\x1b") == literal
    assert sanitize.unescape("\\x1b") == control


def test_escape_is_injective_over_a_small_adversarial_alphabet() -> None:
    alphabet = ["\\", "x", "y", "u", "1", "b", "\x1b", chr(0x202E), "2", "0", "e", chr(0xDC80)]
    inputs = {
        "".join(combo) for size in range(5) for combo in itertools.product(alphabet, repeat=size)
    }
    outputs = {sanitize.escape(text) for text in inputs}
    assert len(outputs) == len(inputs)


def _random_text(rng: random.Random) -> str:
    pools = [
        (0x00, 0x7F),
        (0x80, 0x2FF),
        (0x2000, 0x206F),
        (0xD800, 0xDFFF),
        (0xE000, 0xF8FF),
        (0xFFF0, 0xFFFF),
        (0x10000, 0x10FFFF),
    ]
    chars = []
    for _ in range(rng.randrange(0, 24)):
        low, high = rng.choice(pools)
        chars.append(chr(rng.randrange(low, high + 1)))
    return "".join(chars)


# The default gate runs a smaller seeded sweep of the same generator; the full-size one is slow
# only because every escape and unescape is traced by the branch-coverage tracer (about 1 s).
SWEEP_SIZES = [
    pytest.param(300, id="default"),
    pytest.param(5000, id="full", marks=pytest.mark.slow),
]


@pytest.mark.parametrize("count", SWEEP_SIZES)
def test_seeded_random_strings_round_trip_and_come_out_safe(count: int) -> None:
    rng = random.Random(20261008)
    for _ in range(count):
        text = _random_text(rng)
        escaped = sanitize.escape(text)
        assert sanitize.unescape(escaped) == text
        assert survives_safely(escaped)
        assert sanitize.escape(sanitize.unescape(escaped)) == escaped


def test_escaped_text_is_pure_ascii_unless_the_characters_are_harmless_letters() -> None:
    for text in ["\x1b\x00\x7f", chr(0x202E) + chr(0xFEFF), chr(0xD800) + chr(0xDC80)]:
        assert sanitize.escape(text).isascii()


# ---- unescape refuses anything that escape would not have produced -----------------------------

BAD_ESCAPED = [
    pytest.param("\\", id="dangling-backslash"),
    pytest.param("abc\\", id="dangling-after-text"),
    pytest.param("\\q", id="unknown-escape"),
    pytest.param("\\n", id="python-style-newline"),
    pytest.param("\\x1", id="short-x"),
    pytest.param("\\xzz", id="non-hex-x"),
    pytest.param("\\x1B", id="upper-case-hex"),
    pytest.param("\\u202E", id="upper-case-hex-u"),
    pytest.param("\\x41", id="escape-of-a-plain-letter"),
    pytest.param("\\u0041", id="u-escape-of-a-plain-letter"),
    pytest.param("\\x5c", id="escape-of-a-backslash"),
    pytest.param("\\u00e9", id="escape-of-a-readable-letter"),
    pytest.param("\\u12", id="short-u"),
    pytest.param("\\U0001f600", id="escape-of-a-readable-emoji"),
    pytest.param("\\U00110000", id="above-max-codepoint"),
    pytest.param("\\Uffffffff", id="way-above-max-codepoint"),
    pytest.param("\\y41", id="y-below-80"),
    pytest.param("\\y7f", id="y-7f"),
    pytest.param("\\y1", id="short-y"),
    pytest.param("\\x+1", id="signed-hex"),
    pytest.param("\\x 1", id="space-in-hex"),
    pytest.param("\x1b[31m", id="raw-escape-character"),
    pytest.param("a\nb", id="raw-newline"),
    pytest.param(chr(0x202E), id="raw-bidi-override"),
    pytest.param(chr(0xFEFF), id="raw-bom"),
    pytest.param(chr(0xDC80), id="raw-surrogate-escape"),
    pytest.param("\\x0a\n", id="valid-escape-then-raw-newline"),
]


@pytest.mark.parametrize("text", BAD_ESCAPED)
def test_unescape_refuses_non_canonical_text(text: str) -> None:
    with pytest.raises(sanitize.InvalidEscapeError):
        sanitize.unescape(text)


def test_unescape_error_never_contains_the_offending_text() -> None:
    hostile = "ok\x1b[31m" + chr(0x202E)
    with pytest.raises(sanitize.InvalidEscapeError) as raised:
        sanitize.unescape(hostile)
    message = str(raised.value)
    assert "\x1b" not in message
    assert chr(0x202E) not in message


def test_invalid_escape_error_is_a_value_error() -> None:
    assert issubclass(sanitize.InvalidEscapeError, ValueError)


# ---- scrub: for sentences, idempotent, keeps backslashes ----------------------------------------


def test_scrub_removes_dangerous_characters_but_leaves_backslashes() -> None:
    assert sanitize.scrub("bad\x1b name" + chr(0x202E) + "\\keep") == "bad\\x1b name\\u202e\\keep"


@pytest.mark.parametrize("count", [pytest.param(200, id="default"), *SWEEP_SIZES[1:]])
def test_scrub_is_idempotent_and_safe(count: int) -> None:
    rng = random.Random(7)
    for _ in range(count):
        text = _random_text(rng)
        once = sanitize.scrub(text)
        assert sanitize.scrub(once) == once
        assert survives_safely(once)


def test_scrub_returns_plain_text_unchanged() -> None:
    text = "an ordinary sentence."
    assert sanitize.scrub(text) is text


# ---- first_unsafe ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "index"),
    [
        ("clean", None),
        ("back\\slash is not unsafe here", None),
        ("a\x00b", 1),
        ("abc" + chr(0x202E), 3),
        (chr(0xFEFF) + "x", 0),
        ("caf\u00e9", None),
        ("a" + chr(0xDC80), 1),
    ],
)
def test_first_unsafe(text: str, index: int | None) -> None:
    assert sanitize.first_unsafe(text) == index


# ---- escape_components -------------------------------------------------------------------------


def test_escape_components_escapes_each_part_on_its_own() -> None:
    parts = ["Users", "a\\b", "x\ny"]
    assert sanitize.escape_components(parts) == ("Users", "a\\\\b", "x\\x0ay")


def test_escape_components_of_nothing_is_empty() -> None:
    assert sanitize.escape_components([]) == ()


# ---- clip_escaped ------------------------------------------------------------------------------


def test_clip_escaped_leaves_short_text_alone() -> None:
    assert sanitize.clip_escaped("short", 20) == "short"


def test_clip_escaped_cuts_long_text_and_marks_the_cut() -> None:
    clipped = sanitize.clip_escaped("a" * 100, 20)
    assert clipped == "a" * 17 + "..."
    assert len(clipped) == 20


def test_clip_escaped_never_cuts_an_escape_sequence_in_half() -> None:
    clipped = sanitize.clip_escaped("\x1b" * 10, 10)
    assert clipped == "\\x1b..."
    assert len(clipped) <= 10
    assert sanitize.unescape(clipped.removesuffix("...")) == "\x1b"


def test_clip_escaped_with_a_tiny_limit() -> None:
    assert sanitize.clip_escaped("abcdef", 3) == "..."
    assert sanitize.clip_escaped("abcdef", 2) == ".."
    assert sanitize.clip_escaped("abcdef", 0) == ""


def test_clip_escaped_doubles_backslashes_like_escape() -> None:
    assert sanitize.clip_escaped("a\\b", 20) == "a\\\\b"
    assert sanitize.clip_escaped("\\" * 20, 10) == "\\\\" * 3 + "..."


def test_clip_escaped_output_is_always_safe_and_within_the_limit() -> None:
    rng = random.Random(99)
    for _ in range(1000):
        limit = rng.randrange(4, 30)
        clipped = sanitize.clip_escaped(_random_text(rng), limit)
        assert len(clipped) <= limit
        assert survives_safely(clipped)


# ---- csv_neutralize ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cell", "expected"),
    [
        ("=SUM(A1)", "'=SUM(A1)"),
        ("+1+1", "'+1+1"),
        ("-2+3", "'-2+3"),
        ("@cmd", "'@cmd"),
        ("\tcell", "'\tcell"),
        ("\rcell", "'\rcell"),
        ("normal", "normal"),
        ("a=b", "a=b"),
        ("", ""),
        (" =leading space", " =leading space"),
    ],
)
def test_csv_neutralize(cell: str, expected: str) -> None:
    assert sanitize.csv_neutralize(cell) == expected


def test_escaped_control_characters_never_start_a_formula() -> None:
    for text in ["\tcmd", "\rcmd", "\ncmd"]:
        assert sanitize.csv_neutralize(sanitize.escape(text)).startswith("\\x")


# ---- exhaustive sweep --------------------------------------------------------------------------


@pytest.mark.slow
def test_every_codepoint_escapes_safely_and_round_trips() -> None:
    """All 1,114,112 code points: nothing dangerous survives, and escape is reversible."""
    for codepoint in range(0x110000):
        char = chr(codepoint)
        escaped = sanitize.escape(char)
        if not survives_safely(escaped):
            pytest.fail(f"U+{codepoint:04X} survives escaping")
        if sanitize.unescape(escaped) != char:
            pytest.fail(f"U+{codepoint:04X} does not round trip")


def test_clip_escaped_returns_text_that_fits_even_with_a_tiny_limit() -> None:
    assert sanitize.clip_escaped("ab", 3) == "ab"
    assert sanitize.clip_escaped("", 0) == ""
