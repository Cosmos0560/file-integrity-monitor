"""The ``demo`` use case: the whole tool, end to end, on files it makes itself.

Everything happens in one new temporary directory (``fs/sandbox.py``): a few files to watch, a
throw-away key, a signed baseline, a clean check, then scripted changes (a modified file, a
deleted one, new ones, a permission change, a file whose name tries to abuse the terminal), a
check that finds them, and finally a tampered baseline that the check refuses. The directory is
removed in a ``finally`` block, also when a step raises, and its removal is verified.

The demo uses the real use cases (``run_init_key``, ``run_baseline``, ``run_check``) with their
real checks; only the files are staged. Nothing here prints: the transcript is returned as text.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass

from fim.app.baseline import (
    BaselineRequest,
    InitKeyRequest,
    run_baseline,
    run_init_key,
)
from fim.app.check import CheckOutcome, CheckRequest, run_check
from fim.core.clock import Clock
from fim.core.errors import BaselineIntegrityError, ExitCode, FimError
from fim.core.models import FindingKind
from fim.core.pathrules import display_user_path
from fim.core.sanitize import escape
from fim.fs.sandbox import Sandbox
from fim.platform.hostinfo import path_flavour

__all__ = ["EXPECTED_KINDS", "DemoError", "DemoOutcome", "hostile_names", "run_demo"]

# What the scripted changes must produce; a demo that does not is a failed demo, not a pass.
EXPECTED_KINDS = (
    FindingKind.MODIFIED,
    FindingKind.DELETED,
    FindingKind.CREATED,
    FindingKind.PERMISSION_CHANGED,
)

_WATCHED = "watched"
_STATE = "state"
_SHOWN_CHARS = 240
# The name tries a right-to-left override and a zero-width space; the table shows it escaped.
# Plain text under a harmless extension: an ``.exe`` with a PE-looking body made Windows Defender
# refuse the read (EINVAL) while the demo was being tested.
_HOSTILE_NAME = "payroll\u202e\u200btxt.bak"
# POSIX file names may also hold an ANSI escape and a newline; Windows names may not.
_HOSTILE_POSIX_NAME = "\x1b[2Jcleared\nsecond-line.txt"
_FILES = {
    "notes.txt": b"meeting notes\n",
    "config/app.conf": b"mode = production\nverbose = false\n",
    "config/users.list": b"alice\nbob\n",
    "docs/readme.md": b"# readme\n",
    "docs/old-notes.txt": b"to be removed\n",
    "bin/run.sh": b"#!/bin/sh\necho running\n",
}


class DemoError(FimError):
    """The demo did not produce what its script says it must (exit code 2)."""


@dataclass(frozen=True, slots=True)
class DemoOutcome:
    text: str  # the transcript
    exit_code: ExitCode
    workspace_removed: bool  # verified after the removal, False only if removal failed


def hostile_names() -> tuple[str, ...]:
    """The file names the demo plants: Windows takes only the first, POSIX takes both."""
    if sys.platform == "win32":
        return (_HOSTILE_NAME,)
    else:
        return (_HOSTILE_NAME, _HOSTILE_POSIX_NAME)


def _shown(path: str) -> str:
    return display_user_path(path, path_flavour(), _SHOWN_CHARS)


def _config_text(watched: str, key_file: str) -> str:
    # JSON strings are valid YAML double-quoted scalars, so Windows paths need no escaping care.
    return (
        "version: 1\n"
        'host_label: "demo-host"\n'
        f"key_file: {json.dumps(key_file)}\n"
        "paths:\n"
        f"  - path: {json.dumps(watched)}\n"
        "    severity: high\n"
    )


def _kinds(outcome: CheckOutcome) -> set[FindingKind]:
    return {finding.kind for finding in outcome.report.findings}


def run_demo(clock: Clock, *, base_directory: str | None = None) -> DemoOutcome:
    """Run the scripted demo and return its transcript. ``base_directory`` is for tests."""
    sandbox = Sandbox.create(base_directory)
    lines: list[str] = []
    try:
        _script(sandbox, clock, lines)
    finally:
        sandbox.destroy()
    removed = not sandbox.exists()
    lines.append("")
    lines.append(
        "the temporary directory was removed"
        if removed
        else "WARNING: the temporary directory could not be removed"
    )
    return DemoOutcome("\n".join(lines) + "\n", ExitCode.OK, removed)


def _script(sandbox: Sandbox, clock: Clock, lines: list[str]) -> None:
    say = lines.append
    watched = sandbox.path(_WATCHED)
    key_file = sandbox.path(f"{_STATE}/fim.key")
    baseline_file = sandbox.path(f"{_STATE}/demo.baseline")
    config_file = sandbox.path(f"{_STATE}/config.yaml")

    say("fim demo: a throw-away copy of the whole workflow on files made for it.")
    say(f"workspace: {_shown(sandbox.root)} (removed when the demo ends)")
    say("")
    for name, content in _FILES.items():
        sandbox.write_file(f"{_WATCHED}/{name}", content)
    sandbox.write_file(f"{_STATE}/config.yaml", _config_text(watched, key_file).encode("ascii"))

    say("step 1: create a key and record a signed baseline")
    created = run_init_key(InitKeyRequest(key_file=key_file, config_path=config_file, force=False))
    say(f"  fim init-key   -> key id {created.key_id}")
    made = run_baseline(
        BaselineRequest(
            config_path=config_file,
            baseline_path=baseline_file,
            key_file=None,
            force=False,
            allow_incomplete=False,
        ),
        clock,
    )
    say(f"  fim baseline   -> {made.records} entries, sequence {made.sequence}, signed")
    say("")

    request = CheckRequest(baseline_path=baseline_file, key_file=None, config_path=config_file)
    say("step 2: check before anything changes")
    clean = run_check(request, clock)
    count = len(clean.report.findings)
    say(f"  fim check      -> {count} findings, exit code {int(clean.exit_code)}")
    if clean.report.findings or clean.exit_code is not ExitCode.OK:
        raise DemoError("the demo's own files were reported as changed before any change")
    say("")

    say("step 3: change the watched files the way an intruder might")
    sandbox.write_file(f"{_WATCHED}/config/app.conf", b"mode = production\nverbose = true\n# x\n")
    say("  modified config/app.conf")
    sandbox.remove_file(f"{_WATCHED}/docs/old-notes.txt")
    say("  deleted  docs/old-notes.txt")
    sandbox.write_file(f"{_WATCHED}/bin/helper.sh", b"#!/bin/sh\nid\n")
    say("  created  bin/helper.sh")
    for name in hostile_names():
        sandbox.write_file(f"{_WATCHED}/{name}", b"noise")
        say(f"  created  a file named {escape(name)}")
    sandbox.set_mode(f"{_WATCHED}/notes.txt", 0o444)
    say("  made notes.txt read-only")
    say("")

    say("step 4: check again (the file names below are shown escaped, never raw)")
    found = run_check(request, clock)
    for row in (found.text or "").splitlines():
        say(f"  {row}" if row else "")
    say(f"  exit code {int(found.exit_code)}")
    missing = [kind.value for kind in EXPECTED_KINDS if kind not in _kinds(found)]
    if missing or found.exit_code is not ExitCode.FINDINGS:
        raise DemoError(f"the demo did not find what it changed: missing {', '.join(missing)}")
    say("")

    say("step 5: tamper with the baseline file itself (one byte)")
    sandbox.flip_byte(f"{_STATE}/demo.baseline", -20)  # inside the signed payload
    try:
        run_check(request, clock)
    except BaselineIntegrityError as exc:
        say(f"  fim check      -> refused, exit code {int(exc.exit_code)}: {exc.message}")
    else:
        raise DemoError("a tampered baseline was accepted")
