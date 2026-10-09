"""The error hierarchy and the exit codes (PLAN.md section 1.5).

Every error maps to exactly one exit code, and the CLI turns an error into that code. Messages
are scrubbed when the error is created, so a hostile file name that reaches a message cannot
carry terminal escapes or bidi controls into a log, a traceback or the console. Pass paths
through ``sanitize.escape`` (or ``clip_escaped``) first; the scrub is the second line of defence.
"""

from __future__ import annotations

import enum
from typing import ClassVar

from fim.core.sanitize import scrub


class ExitCode(enum.IntEnum):
    """Process exit codes. ``worst`` picks the winner when several apply."""

    OK = 0  # clean and complete
    FINDINGS = 1  # findings were reported
    ERROR = 2  # usage, configuration or I/O error
    INTEGRITY = 3  # baseline integrity failure (tampered, wrong key, unknown format)
    INCOMPLETE = 4  # a limit or the time budget was hit


# Highest priority first: 3 > 2 > 4 > 1 > 0.
EXIT_PRECEDENCE = (
    ExitCode.INTEGRITY,
    ExitCode.ERROR,
    ExitCode.INCOMPLETE,
    ExitCode.FINDINGS,
    ExitCode.OK,
)


def worst(codes: list[ExitCode] | tuple[ExitCode, ...]) -> ExitCode:
    """The exit code that wins under the precedence rule; OK for an empty sequence."""
    for candidate in EXIT_PRECEDENCE:
        if candidate in codes:
            return candidate
    return ExitCode.OK


class FimError(Exception):
    """Base class. Subclasses set ``exit_code``; the message is scrubbed on creation."""

    exit_code: ClassVar[ExitCode] = ExitCode.ERROR

    def __init__(self, message: str) -> None:
        self.message = scrub(message)
        super().__init__(self.message)


class UsageError(FimError):
    """Bad command line."""


class ConfigError(FimError):
    """Bad configuration, or a limit set above its hard ceiling."""


class PathRuleError(FimError):
    """A user-supplied path that the path rules refuse."""


class FileAccessError(FimError):
    """The tool could not read or write one of its own files (key, baseline, anchor, config)."""


class FileMissingError(FileAccessError):
    """One of the tool's own files does not exist (so callers can tell "absent" from "broken")."""


class ModelError(FimError):
    """A data object that would break an invariant (an internal error, never user input)."""


class BaselineIntegrityError(FimError):
    """The baseline did not verify: tampered, wrong key, unknown format or rolled back."""

    exit_code: ClassVar[ExitCode] = ExitCode.INTEGRITY


class LimitReachedError(FimError):
    """A hard limit stopped the run before it could finish."""

    exit_code: ClassVar[ExitCode] = ExitCode.INCOMPLETE
