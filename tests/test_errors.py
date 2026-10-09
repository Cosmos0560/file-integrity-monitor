"""core/errors.py: one exit code per error, precedence, scrubbed messages, plan drift."""

from __future__ import annotations

import itertools
import re
import traceback

import pytest

from fim.core import errors
from fim.core.errors import ExitCode
from plan_doc import section


def all_subclasses(cls: type[errors.FimError]) -> set[type[errors.FimError]]:
    found: set[type[errors.FimError]] = set()
    for sub in cls.__subclasses__():
        found.add(sub)
        found |= all_subclasses(sub)
    return found


def test_exit_code_values_are_the_documented_ones() -> None:
    assert {code.name: int(code) for code in ExitCode} == {
        "OK": 0,
        "FINDINGS": 1,
        "ERROR": 2,
        "INTEGRITY": 3,
        "INCOMPLETE": 4,
    }


def test_precedence_is_3_2_4_1_0() -> None:
    assert [int(code) for code in errors.EXIT_PRECEDENCE] == [3, 2, 4, 1, 0]


def test_worst_of_nothing_is_ok() -> None:
    assert errors.worst([]) == ExitCode.OK


@pytest.mark.parametrize(
    "subset",
    [
        pytest.param(subset, id="+".join(str(int(c)) for c in subset))
        for size in range(1, 6)
        for subset in itertools.combinations(list(ExitCode), size)
    ],
)
def test_worst_follows_the_precedence_table_for_every_subset(
    subset: tuple[ExitCode, ...],
) -> None:
    expected = next(code for code in errors.EXIT_PRECEDENCE if code in subset)
    assert errors.worst(subset) == expected
    assert errors.worst(list(reversed(subset))) == expected


def test_specific_precedence_cases_from_the_plan() -> None:
    assert errors.worst([ExitCode.FINDINGS, ExitCode.INCOMPLETE]) == ExitCode.INCOMPLETE
    assert errors.worst([ExitCode.INCOMPLETE, ExitCode.ERROR]) == ExitCode.ERROR
    assert errors.worst([ExitCode.ERROR, ExitCode.INTEGRITY]) == ExitCode.INTEGRITY
    assert errors.worst([ExitCode.OK, ExitCode.FINDINGS]) == ExitCode.FINDINGS


def test_every_error_class_maps_to_exactly_one_failure_exit_code() -> None:
    classes = all_subclasses(errors.FimError) | {errors.FimError}
    for cls in classes:
        assert cls.exit_code in {ExitCode.ERROR, ExitCode.INTEGRITY, ExitCode.INCOMPLETE}, cls
        assert isinstance(cls.exit_code, ExitCode)


@pytest.mark.parametrize(
    ("cls", "code"),
    [
        (errors.FimError, ExitCode.ERROR),
        (errors.UsageError, ExitCode.ERROR),
        (errors.ConfigError, ExitCode.ERROR),
        (errors.PathRuleError, ExitCode.ERROR),
        (errors.ModelError, ExitCode.ERROR),
        (errors.FileAccessError, ExitCode.ERROR),
        (errors.FileMissingError, ExitCode.ERROR),
        (errors.BaselineIntegrityError, ExitCode.INTEGRITY),
        (errors.LimitReachedError, ExitCode.INCOMPLETE),
    ],
)
def test_error_classes_and_their_exit_codes(cls: type[errors.FimError], code: ExitCode) -> None:
    assert cls("message").exit_code == code


def test_every_error_is_an_exception_and_a_fim_error() -> None:
    for cls in all_subclasses(errors.FimError):
        assert issubclass(cls, errors.FimError)
        assert issubclass(cls, Exception)


# ---- messages are scrubbed at creation ---------------------------------------------------------


def test_plain_messages_are_kept_as_they_are() -> None:
    error = errors.ConfigError("limit 'max_files' must be at least 1")
    assert error.message == "limit 'max_files' must be at least 1"
    assert str(error) == error.message
    assert error.args == (error.message,)


def test_hostile_characters_never_reach_the_message() -> None:
    hostile = "bad \x1b[31m name" + chr(0x202E) + "\nsecond line" + chr(0xFEFF)
    error = errors.PathRuleError("refused: " + hostile)
    for text in (error.message, str(error), repr(error), *map(str, error.args)):
        assert "\x1b" not in text
        assert "\n" not in text
        assert chr(0x202E) not in text
        assert chr(0xFEFF) not in text
    assert "\\x1b" in error.message
    assert "\\u202e" in error.message


def test_a_traceback_of_a_hostile_error_is_clean() -> None:
    try:
        raise errors.BaselineIntegrityError("tampered " + "\x1b]0;title\x07")
    except errors.BaselineIntegrityError as exc:
        rendered = "".join(traceback.format_exception(exc))
    assert "\x1b" not in rendered
    assert "\x07" not in rendered


def test_already_escaped_text_is_not_double_escaped() -> None:
    error = errors.PathRuleError("refused C:\\dir\\name and \\x1b")
    assert error.message == "refused C:\\dir\\name and \\x1b"


# ---- drift against PLAN.md section 1.5 ---------------------------------------------------------


def test_exit_codes_in_the_plan_match_the_code() -> None:
    text = section("### 1.5 Exit codes")
    documented = {int(number) for number in re.findall(r"`(\d)`", text)}
    assert documented == {int(code) for code in ExitCode}
    precedence = re.search(r"Precedence:\s*([\d >]+)", text)
    assert precedence is not None
    order = [int(part) for part in precedence.group(1).replace(">", " ").split()]
    assert order == [int(code) for code in errors.EXIT_PRECEDENCE]
