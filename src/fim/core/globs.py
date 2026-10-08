"""Segment-wise glob matching (PLAN.md section 1.6) without regular expressions.

A pattern is matched against a path *relative to its root*, given as components. Rules:

* ``/`` separates segments. A pattern without ``/`` matches the final component at any depth
  (``*.tmp`` means ``**/*.tmp``).
* ``*`` matches any run of characters inside one component, ``?`` exactly one character, and
  ``[abc]``, ``[a-z]``, ``[!abc]`` / ``[^abc]`` one character from (or not from) a set. A
  literal ``]`` comes first in a set; there is no escape character, put a metacharacter in a
  set to match it literally (``[*]``).
* A segment that is exactly ``**`` matches zero or more whole components, so ``a/**`` matches
  ``a`` itself and everything below it, and ``**/x`` matches ``x`` at any depth, including the
  top. ``**`` inside a longer segment is an ordinary ``*``.
* Case: sensitive on POSIX, insensitive (``str.casefold``) on Windows.

Matching simulates the pattern as a set of states walked over the input once (no backtracking),
so the cost is at most (input length) x (pattern length) however hostile the pattern is.
Patterns are checked when compiled; a bad one is a ConfigError with a clear message.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from fim.core.errors import ConfigError
from fim.core.limits import MAX_PATTERN_CHARS
from fim.core.sanitize import clip_escaped, first_unsafe

__all__ = ["Pattern", "compile_pattern", "matches_any", "pattern_matches"]

_DOUBLE_STAR = "**"
_MESSAGE_PATTERN_CHARS = 80


@dataclass(frozen=True, slots=True)
class _CharSet:
    """One ``[...]`` set: single characters and inclusive ranges, possibly negated."""

    negated: bool
    singles: frozenset[str]
    ranges: tuple[tuple[str, str], ...]

    def accepts(self, char: str) -> bool:
        hit = char in self.singles or any(low <= char <= high for low, high in self.ranges)
        return hit != self.negated


class _Token:
    """Marker tokens (``?`` and ``*``) that must not be confused with literal characters."""

    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name


ANY_ONE = _Token("any-one")
STAR = _Token("star")
# A segment is a tuple of tokens: a str (one literal character), ANY_ONE, STAR or a _CharSet.
Token = str | _Token | _CharSet


@dataclass(frozen=True, slots=True)
class Pattern:
    """A compiled glob. ``segments`` holds None for a ``**`` segment."""

    source: str
    case_sensitive: bool
    segments: tuple[tuple[Token, ...] | None, ...]


def _refuse(source: str, reason: str) -> ConfigError:
    shown = clip_escaped(source, _MESSAGE_PATTERN_CHARS)
    return ConfigError(f"pattern '{shown}' refused: {reason}")


def compile_pattern(
    source: str, *, case_sensitive: bool, max_chars: int = MAX_PATTERN_CHARS
) -> Pattern:
    """Compile ``source`` or raise ConfigError."""
    if not isinstance(source, str):
        raise ConfigError("a pattern must be text")
    if source == "":
        raise _refuse(source, "empty pattern")
    if len(source) > max_chars:
        raise _refuse(source, f"longer than {max_chars} characters")
    if first_unsafe(source) is not None:
        raise _refuse(source, "contains a control or invisible character")
    if source.startswith("/"):
        raise _refuse(source, "patterns are relative to the root; remove the leading '/'")
    if source.endswith("/"):
        raise _refuse(source, "a trailing '/' is not supported; match the name or use '/**'")
    texts = source.split("/")
    for text in texts:
        if text == "":
            raise _refuse(source, "empty segment ('//')")
        if text in (".", ".."):
            raise _refuse(source, "'.' and '..' segments are not allowed")
    if len(texts) == 1 and texts[0] != _DOUBLE_STAR:
        texts = [_DOUBLE_STAR, *texts]  # no '/': the name may be at any depth
    segments: list[tuple[Token, ...] | None] = []
    for text in texts:
        if text == _DOUBLE_STAR:
            if segments and segments[-1] is None:
                continue  # '**/**' is the same as '**'
            segments.append(None)
        else:
            folded = text if case_sensitive else text.casefold()  # whole text: 'ss' for sharp s
            segments.append(_compile_segment(source, folded))
    return Pattern(source, case_sensitive, tuple(segments))


def _compile_segment(source: str, text: str) -> tuple[Token, ...]:
    tokens: list[Token] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "*":
            if not tokens or tokens[-1] is not STAR:  # '**' inside a segment is one '*'
                tokens.append(STAR)
            index += 1
        elif char == "?":
            tokens.append(ANY_ONE)
            index += 1
        elif char == "[":
            charset, index = _compile_set(source, text, index)
            tokens.append(charset)
        elif char == "\\":
            raise _refuse(
                source, "'\\' is not an escape; use '/' to separate and [\\] for a literal"
            )
        else:
            tokens.append(char)
            index += 1
    return tuple(tokens)


def _compile_set(source: str, text: str, start: int) -> tuple[_CharSet, int]:
    """Parse the set that opens at ``text[start] == '['``; return it and the index after ']'."""
    index = start + 1
    negated = False
    if index < len(text) and text[index] in "!^":
        negated = True
        index += 1
    singles: set[str] = set()
    ranges: list[tuple[str, str]] = []
    first = True
    while True:
        if index >= len(text):
            raise _refuse(source, "unterminated '[' set")
        char = text[index]
        if char == "]" and not first:
            index += 1
            break
        first = False
        if index + 2 < len(text) and text[index + 1] == "-" and text[index + 2] != "]":
            low, high = char, text[index + 2]
            if low > high:
                raise _refuse(source, "reversed range in a set")
            ranges.append((low, high))
            index += 3
        else:
            singles.add(char)
            index += 1
    return _CharSet(negated, frozenset(singles), tuple(ranges)), index


# ---- matching ------------------------------------------------------------------------------------


def _segment_matches(tokens: tuple[Token, ...], name: str, case_sensitive: bool) -> bool:
    """Does ``name`` match one segment? Walks a set of token positions once per character."""
    end = len(tokens)

    def close(states: set[int]) -> set[int]:
        # A star may also match nothing, so the position after it is reachable too.
        for state in sorted(states):
            while state < end and tokens[state] is STAR:
                state += 1
                states.add(state)
        return states

    current = close({0})
    for char in name if case_sensitive else name.casefold():
        following: set[int] = set()
        for state in current:
            if state == end:
                continue
            token = tokens[state]
            if token is STAR:
                following.add(state)
            elif token is ANY_ONE:
                following.add(state + 1)
            elif isinstance(token, _CharSet):
                if token.accepts(char):
                    following.add(state + 1)
            elif token == char:
                following.add(state + 1)
        if not following:
            return False
        current = close(following)
    return end in current


def pattern_matches(pattern: Pattern, parts: Sequence[str]) -> bool:
    """True if the root-relative path ``parts`` (components, no separators) matches."""
    segments = pattern.segments
    last = len(segments)

    def close(states: set[int]) -> set[int]:
        # '**' may match zero components, so the position after it is reachable too.
        for state in sorted(states):
            while state < last and segments[state] is None:
                state += 1
                states.add(state)
        return states

    current = close({0})
    for part in parts:
        following: set[int] = set()
        for state in current:
            if state == last:
                continue
            segment = segments[state]
            if segment is None:
                following.add(state)
            elif _segment_matches(segment, part, pattern.case_sensitive):
                following.add(state + 1)
        if not following:
            return False
        current = close(following)
    return last in current


def matches_any(patterns: Sequence[Pattern], parts: Sequence[str]) -> bool:
    """True if any pattern matches; False for an empty sequence."""
    return any(pattern_matches(pattern, parts) for pattern in patterns)
