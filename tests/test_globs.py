"""core/globs.py: the segment matcher of PLAN.md section 1.6."""

from __future__ import annotations

import fnmatch
import random

import pytest

from fim.core import globs
from fim.core.errors import ConfigError
from fim.core.globs import compile_pattern, matches_any, pattern_matches


def match(pattern: str, path: str, *, case_sensitive: bool = True) -> bool:
    parts = tuple(path.split("/")) if path else ()
    return pattern_matches(compile_pattern(pattern, case_sensitive=case_sensitive), parts)


MATCH_TABLE = [
    # a pattern without '/' matches the name at any depth
    ("*.tmp", "a.tmp", True),
    ("*.tmp", "d/e/a.tmp", True),
    ("*.tmp", "a.tmpx", False),
    ("*.tmp", "a.tmp/x", False),  # the directory a.tmp matches; its children are pruned with it
    ("mtab", "mtab", True),
    ("mtab", "etc/mtab", True),
    ("mtab", "etc/mtab2", False),
    ("*", "anything", True),
    ("*", "a/b/c", True),
    # '**' spans zero or more components
    ("**", "", True),
    ("**", "a/b/c", True),
    ("**/__pycache__/**", "__pycache__", True),
    ("**/__pycache__/**", "a/__pycache__", True),
    ("**/__pycache__/**", "a/__pycache__/x.pyc", True),
    ("**/__pycache__/**", "a/b", False),
    ("**/__pycache__/**", "a/__pycache__x/y", False),
    ("a/**", "a", True),
    ("a/**", "a/b/c", True),
    ("a/**", "b/a/c", False),
    ("a/**/b", "a/b", True),
    ("a/**/b", "a/x/y/b", True),
    ("a/**/b", "a", False),
    ("a/**/b", "a/x/y/c", False),
    ("**/**/a", "a", True),
    ("a/**/**/b", "a/q/b", True),
    # a pattern with '/' is anchored at the root
    ("etc/*.conf", "etc/a.conf", True),
    ("etc/*.conf", "x/etc/a.conf", False),
    ("etc/*.conf", "etc/d/a.conf", False),
    ("etc/*/x", "etc/d/x", True),
    ("etc/*/x", "etc/x", False),
    # '*' stays inside one component
    ("a*b", "axxb", True),
    ("a*b", "ab", True),
    ("a*b", "a/b", False),
    ("a**b", "axxb", True),  # '**' inside a segment is an ordinary '*'
    ("*a*b*c*", "xaxbxcx", True),
    ("*a*b*c*", "xaxcxbx", False),
    ("*.*", "name.ext", True),
    ("*.*", "noext", False),
    # '?' is exactly one character
    ("a?c", "abc", True),
    ("a?c", "ac", False),
    ("a?c", "abbc", False),
    ("???", "abc", True),
    # sets
    ("[abc]x", "bx", True),
    ("[abc]x", "dx", False),
    ("[a-c]x", "bx", True),
    ("[a-c]x", "dx", False),
    ("[!a]x", "bx", True),
    ("[!a]x", "ax", False),
    ("[^a]x", "bx", True),
    ("[^a]x", "ax", False),
    ("[]]x", "]x", True),  # ']' first in a set is a literal
    ("[!]]x", "]x", False),
    ("[!]]x", "ax", True),
    ("[*]", "*", True),  # the way to match a metacharacter literally
    ("[*]", "a", False),
    ("[?]x", "?x", True),
    ("[-a]", "-", True),
    ("[a-]", "-", True),
    ("[a-]", "a", True),
    ("[a-]", "b", False),
    ("[\\]", "\\", True),  # the way to match a literal backslash
    ("file[0-9][0-9]", "file42", True),
    ("file[0-9][0-9]", "file4x", False),
    # literals that look special elsewhere
    ("a.b", "a.b", True),
    ("a.b", "aXb", False),
    ("a+b(c)", "a+b(c)", True),
    ("a$b", "a$b", True),
    ("~backup", "~backup", True),
    # non-ASCII names
    ("*" + chr(0x65E5) + "*", "x" + chr(0x65E5) + "y", True),
    ("?", chr(0x1F600), True),  # one code point, not two UTF-16 units
]


@pytest.mark.parametrize(("pattern", "path", "expected"), MATCH_TABLE)
def test_match_table(pattern: str, path: str, expected: bool) -> None:
    assert match(pattern, path) is expected


def test_posix_is_case_sensitive_and_windows_is_not() -> None:
    assert match("*.TMP", "a.tmp", case_sensitive=True) is False
    assert match("*.TMP", "a.tmp", case_sensitive=False) is True
    assert match("[A-C]x", "bx", case_sensitive=True) is False
    assert match("[A-C]x", "bx", case_sensitive=False) is True
    assert match("Etc/**", "etc/passwd", case_sensitive=True) is False
    assert match("Etc/**", "etc/passwd", case_sensitive=False) is True
    assert match("[!a]", "A", case_sensitive=False) is False
    assert match("[!a]", "A", case_sensitive=True) is True
    assert match("ReadMe", "README", case_sensitive=True) is False
    assert match("ReadMe", "README", case_sensitive=False) is True
    assert match("etc/ss" + chr(0xDF), "ETC/SSSS", case_sensitive=False) is True  # casefold


# ---- refused patterns ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("", "empty"),
        ("/etc", "leading"),
        ("etc/", "trailing"),
        ("a//b", "empty segment"),
        ("./a", "'.'"),
        ("a/..", "'..'"),
        ("..", "'..'"),
        ("[abc", "unterminated"),
        ("[", "unterminated"),
        ("[!", "unterminated"),
        ("[]", "unterminated"),
        ("[z-a]", "reversed"),
        ("a\\b", "not an escape"),
        ("dir\\*.tmp", "not an escape"),
        ("a\x1bb", "control"),
        ("a\nb", "control"),
        ("a" + chr(0x202E) + "b", "control"),
        ("x" * 600, "longer"),
    ],
)
def test_bad_patterns_are_refused_with_a_reason(source: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        compile_pattern(source, case_sensitive=True)


def test_a_pattern_must_be_text() -> None:
    with pytest.raises(ConfigError, match="text"):
        compile_pattern(5, case_sensitive=True)  # type: ignore[arg-type]  # the YAML loader can hand over any type


def test_the_length_limit_is_a_parameter_and_the_boundary_is_inclusive() -> None:
    compile_pattern("a" * 10, case_sensitive=True, max_chars=10)
    with pytest.raises(ConfigError, match="longer than 10"):
        compile_pattern("a" * 11, case_sensitive=True, max_chars=10)


def test_refusal_messages_never_carry_hostile_text() -> None:
    with pytest.raises(ConfigError) as raised:
        compile_pattern("\x1b[31m" + chr(0x202E) + "[", case_sensitive=True)
    text = str(raised.value)
    assert "\x1b" not in text
    assert chr(0x202E) not in text


# ---- structure ---------------------------------------------------------------------------------


def test_a_pattern_without_a_slash_is_compiled_as_any_depth() -> None:
    plain = compile_pattern("*.tmp", case_sensitive=True)
    explicit = compile_pattern("**/*.tmp", case_sensitive=True)
    assert plain.segments == explicit.segments
    assert plain.segments[0] is None


def test_double_stars_collapse() -> None:
    assert len(compile_pattern("a/**/**/b", case_sensitive=True).segments) == 3
    assert len(compile_pattern("a/**", case_sensitive=True).segments) == 2


def test_matches_any() -> None:
    patterns = (
        compile_pattern("*.tmp", case_sensitive=True),
        compile_pattern("etc/**", case_sensitive=True),
    )
    assert matches_any(patterns, ("x", "a.tmp"))
    assert matches_any(patterns, ("etc", "passwd"))
    assert not matches_any(patterns, ("usr", "bin"))
    assert not matches_any((), ("anything",))


def test_module_exports() -> None:
    assert set(globs.__all__) == {"Pattern", "compile_pattern", "matches_any", "pattern_matches"}


# ---- agreement with the standard library on single components ------------------------------------


def test_single_component_patterns_agree_with_fnmatch() -> None:
    rng = random.Random(20261008)
    pattern_alphabet = ["a", "b", "c", "*", "?", "[ab]", "[!a]", "[a-b]", "[!b-c]", "."]
    name_alphabet = ["a", "b", "c", "."]
    for _ in range(3000):
        pattern = "".join(rng.choice(pattern_alphabet) for _ in range(rng.randrange(1, 7)))
        name = "".join(rng.choice(name_alphabet) for _ in range(rng.randrange(0, 7)))
        if name == "" or pattern in (".", ".."):
            continue
        expected = fnmatch.fnmatchcase(name, pattern)
        assert match(pattern, name) is expected, (pattern, name)


# ---- hostile patterns terminate -----------------------------------------------------------------


def test_the_classic_exponential_pattern_finishes_and_is_correct() -> None:
    # A backtracking matcher takes exponential time on this; a state simulation does not.
    pattern = "*a" * 60 + "b"
    assert match(pattern, "a" * 200) is False
    assert match(pattern, "a" * 200 + "b") is True


def test_many_double_stars_across_segments_finish() -> None:
    pattern = "/".join(["**", "a"] * 100)
    assert match(pattern, "/".join(["a"] * 150)) is True
    assert match(pattern, "/".join(["a"] * 99)) is False


def test_a_maximum_size_pattern_against_a_maximum_size_name() -> None:
    pattern = "*a" * 255 + "b"  # 511 characters, the pattern limit is 512
    assert match(pattern, "a" * 4096) is False
    assert match(pattern, "a" * 4096 + "b") is True
