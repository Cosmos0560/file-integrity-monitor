"""The single sanitiser (PLAN.md D10): every string that comes from the filesystem passes here
before it is stored or shown.

``escape`` is injective and reversible, so the escaped text on screen stands for exactly one
path and ``unescape(escape(s)) == s`` for every string, including lone surrogates:

* ``\\`` becomes ``\\\\``;
* C0 and C1 controls and DEL become ``\\xHH``;
* characters of Unicode category Cf (bidi controls, zero-width characters, BOM), Zl, Zp, Co,
  Cn, Cs and every non-ASCII Zs (such as the no-break space) become ``\\uXXXX`` or
  ``\\UXXXXXXXX``;
* undecodable POSIX bytes, which Python carries as the surrogates U+DC80..U+DCFF, become
  ``\\yHH``;
* everything else, including non-Latin letters, stays readable.

All hex digits are lower case. Confusable glyphs (Latin "a" and Cyrillic "a") are not solved;
that is documented, not hidden.

Display only (PLAN.md D14): unassigned (Cn) and newly assigned format characters are decided by
the running Python's Unicode tables, which differ between Python versions. That is harmless for
output but would not be for storage, so the baseline never holds escaped text: it holds the exact
path, serialised by core/canonical.py.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable
from functools import lru_cache
from itertools import accumulate

__all__ = [
    "InvalidEscapeError",
    "clip_already_escaped",
    "clip_escaped",
    "csv_neutralize",
    "escape",
    "escape_components",
    "first_unsafe",
    "scrub",
    "unescape",
]


class InvalidEscapeError(ValueError):
    """Text handed to ``unescape`` is not the canonical output of ``escape``."""


_ESCAPED_CATEGORIES = frozenset({"Cf", "Zl", "Zp", "Co", "Cn", "Cs"})
_HEX_DIGITS = frozenset("0123456789abcdef")
_ESCAPE_WIDTHS = {"x": 2, "y": 2, "u": 4, "U": 8}
_MAX_ESCAPE_WIDTH = 10  # a backslash, the letter and at most eight hex digits
_SURROGATE_ESCAPE_FIRST = 0xDC80
_SURROGATE_ESCAPE_LAST = 0xDCFF
_SURROGATE_ESCAPE_BASE = 0xDC00
_MAX_CODEPOINT = 0x10FFFF
_CSV_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")
_ELLIPSIS = "..."


@lru_cache(maxsize=16384)
def _sequence_for(char: str) -> str | None:
    """The escape sequence for ``char`` (a character other than backslash), or None to keep it."""
    codepoint = ord(char)
    if _SURROGATE_ESCAPE_FIRST <= codepoint <= _SURROGATE_ESCAPE_LAST:
        return f"\\y{codepoint - _SURROGATE_ESCAPE_BASE:02x}"
    category = unicodedata.category(char)
    if category == "Cc":
        return f"\\x{codepoint:02x}"
    if category in _ESCAPED_CATEGORIES or (category == "Zs" and codepoint > 0x7F):
        if codepoint <= 0xFFFF:
            return f"\\u{codepoint:04x}"
        return f"\\U{codepoint:08x}"
    return None


def _is_plain(text: str) -> bool:
    """True if ``text`` is printable ASCII without a backslash (the common case, fast)."""
    return text.isascii() and text.isprintable() and "\\" not in text


def escape(text: str) -> str:
    """Return the canonical, reversible, display-safe form of ``text``."""
    if _is_plain(text):
        return text
    pieces: list[str] = []
    for char in text:
        if char == "\\":
            pieces.append("\\\\")
        else:
            pieces.append(_sequence_for(char) or char)
    return "".join(pieces)


def scrub(text: str) -> str:
    """Make ``text`` display-safe without doubling backslashes (idempotent, not reversible).

    For messages that may already contain escaped paths: ``escape`` would double their
    backslashes. Use ``escape`` for data and ``scrub`` for sentences.
    """
    if text.isascii() and text.isprintable():
        return text
    return "".join(_sequence_for(char) or char for char in text)


def first_unsafe(text: str) -> int | None:
    """Index of the first character ``escape`` would change other than a backslash, or None."""
    if text.isascii() and text.isprintable():
        return None
    for index, char in enumerate(text):
        if _sequence_for(char) is not None:
            return index
    return None


def escape_components(parts: Iterable[str]) -> tuple[str, ...]:
    """Escape each path component on its own (PLAN.md D10 amendment)."""
    return tuple(escape(part) for part in parts)


def clip_escaped(text: str, limit: int) -> str:
    """``escape(text)`` cut at an escape-sequence boundary to at most ``limit`` characters.

    A cut ends in "...". Used to put a hostile name into an error message without letting it
    take over the message.
    """
    full = escape(text)
    if len(full) <= limit:
        return full
    if limit < len(_ELLIPSIS) + 1:
        return _ELLIPSIS[: max(limit, 0)]
    budget = limit - len(_ELLIPSIS)
    pieces = ["\\\\" if char == "\\" else (_sequence_for(char) or char) for char in text]
    # Cumulative lengths only grow, so the pieces that fit are exactly a prefix.
    keep = sum(1 for total in accumulate(len(piece) for piece in pieces) if total <= budget)
    return "".join(pieces[:keep]) + _ELLIPSIS


def clip_already_escaped(text: str, limit: int) -> str:
    """Cut text that is already escaped to ``limit`` characters without ending inside an escape.

    ``clip_escaped`` escapes raw text; this one is for text that went through ``escape`` or
    ``scrub`` already (a finding's path or evidence), where escaping again would double its
    backslashes. A cut ends in "...".
    """
    if len(text) <= limit:
        return text
    cut = max(limit - len(_ELLIPSIS), 0)
    window_start = max(cut - _MAX_ESCAPE_WIDTH, 0)
    backslash = text.rfind("\\", window_start, cut)
    if backslash >= 0 and backslash + 1 < len(text) and text[backslash + 1] in _ESCAPE_WIDTHS:
        width = _ESCAPE_WIDTHS[text[backslash + 1]]
        digits = text[backslash + 2 : backslash + 2 + width]
        if len(digits) == width and _HEX_DIGITS.issuperset(digits) and backslash + 2 + width > cut:
            cut = backslash  # the cut would split a complete escape sequence
    return text[:cut] + _ELLIPSIS


def _decode_escape(text: str, start: int) -> tuple[str, int]:
    """Decode the escape sequence starting at ``text[start] == '\\\\'``; return (char, next)."""
    if start + 1 >= len(text):
        raise InvalidEscapeError(f"dangling backslash at position {start}")
    kind = text[start + 1]
    if kind == "\\":
        return "\\", start + 2
    width = _ESCAPE_WIDTHS.get(kind)
    if width is None:
        raise InvalidEscapeError(f"unknown escape at position {start}")
    digits = text[start + 2 : start + 2 + width]
    if len(digits) != width or not _HEX_DIGITS.issuperset(digits):
        raise InvalidEscapeError(f"malformed escape at position {start}")
    value = int(digits, 16)
    if kind == "y":
        if value < 0x80:
            raise InvalidEscapeError(f"escape out of range at position {start}")
        return chr(_SURROGATE_ESCAPE_BASE + value), start + 2 + width
    if value > _MAX_CODEPOINT:
        raise InvalidEscapeError(f"escape out of range at position {start}")
    return chr(value), start + 2 + width


def unescape(text: str) -> str:
    """Invert ``escape``. Only canonical input is accepted, so each string has one spelling.

    Raises InvalidEscapeError for malformed escapes, upper-case hex, escapes of characters
    that ``escape`` would not have escaped, and raw dangerous characters. The message never
    contains the offending text.
    """
    pieces: list[str] = []
    position = 0
    while position < len(text):
        if text[position] == "\\":
            char, position = _decode_escape(text, position)
            pieces.append(char)
        else:
            pieces.append(text[position])
            position += 1
    result = "".join(pieces)
    if escape(result) != text:
        raise InvalidEscapeError("text is not in canonical escaped form")
    return result


def csv_neutralize(cell: str) -> str:
    """Prefix a quote to a cell a spreadsheet could read as a formula (CWE-1236).

    Applied after ``escape``. It makes CSV output lossy by design; JSON is the lossless format.
    """
    return "'" + cell if cell.startswith(_CSV_TRIGGERS) else cell
