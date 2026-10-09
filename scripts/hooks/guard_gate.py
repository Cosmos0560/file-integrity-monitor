"""Claude Code PreToolUse hook: keep the quality gate's output whole.

CLAUDE.md section 3 says the gate output is never piped, filtered or redirected, because a
filter can hide a failing step and a redirect can swallow the exit status. This hook reads the
hook JSON from stdin and blocks (exit code 2, reason on stderr) a Bash command that runs
``scripts/gate.py`` together with a pipe, an output redirect (including ``2>&1``), ``|| true``,
``; true``, or one of the filters tail, head, tee, Select-String and their kin.

Allowed: ``python scripts/gate.py``, ``... --full``, ``... --log FILE`` and
``python scripts/gate.py && git commit -m "..."``. Text inside quotes is data, not shell syntax,
so a commit message may mention a pipe or the word "head". If a quoted string itself contains
``gate.py`` (``bash -c "python scripts/gate.py | tail"``) it is checked as a command too.

Standard library only. Exit codes: 0 allow, 2 block, 1 the hook could not read its input (a
non-blocking error that Claude Code shows, so a broken hook never locks the session out).
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Sequence
from typing import TextIO

__all__ = ["check_command", "main", "skeleton"]

# gate.py as a whole file name: guard_gate.py and test_gate.py are not the gate.
_GATE_RE = re.compile(r"(?<![\w.\-])gate\.py(?![\w.\-])")
_MAX_DEPTH = 4
# Filters and sinks that hide or replace the gate's output, matched as whole words.
_FILTER_WORDS = (
    "tail",
    "head",
    "tee",
    "select-string",
    "sls",
    "grep",
    "findstr",
    "out-file",
    "tee-object",
    "out-null",
)
_FILTER_RE = re.compile(
    r"(?<![\w.\-/\\])(" + "|".join(re.escape(word) for word in _FILTER_WORDS) + r")(?![\w.\-])",
    re.IGNORECASE,
)
_SWALLOW_RE = re.compile(r"(?:;|&&)\s*(?:true|exit\s+0|:)(?![\w.\-])")
_ESCAPABLE = frozenset("|&;<>()$`\"' \n\t")


def skeleton(command: str) -> tuple[str, list[str]]:
    """The command with quoted text blanked out, plus the contents of the quoted strings.

    Quotes follow shell rules: single quotes hold everything, double quotes allow a backslash
    escape. Outside quotes a backslash before an operator character makes it a literal; before
    any other character it is kept as it is, so a Windows path stays readable.
    """
    plain: list[str] = []
    quoted: list[str] = []
    current: list[str] = []
    quote = ""
    index = 0
    while index < len(command):
        char = command[index]
        if quote:
            if char == "\\" and quote == '"' and index + 1 < len(command):
                current.append(command[index + 1])
                index += 2
                continue
            if char == quote:
                quoted.append("".join(current))
                current = []
                plain.append(quote + quote)
                quote = ""
            else:
                current.append(char)
        elif char in "'\"":
            quote = char
        elif char == "\\" and index + 1 < len(command) and command[index + 1] in _ESCAPABLE:
            plain.append("_")
            index += 2
            continue
        else:
            plain.append(char)
        index += 1
    if quote:  # an unterminated quote: treat what follows as quoted text
        quoted.append("".join(current))
    return "".join(plain), quoted


def check_command(command: str, depth: int = 0) -> list[str]:
    """Reasons to block ``command`` (empty if it may run)."""
    if _GATE_RE.search(command) is None:
        return []
    plain, quoted = skeleton(command)
    reasons: list[str] = []
    if "|" in plain:
        reasons.append("a pipe ('|', '||' or '|&')")
    if ">" in plain:
        reasons.append("an output redirect ('>', '>>', '2>&1' or '&>')")
    if _SWALLOW_RE.search(plain):
        reasons.append("a command that swallows the exit status ('; true', '&& true')")
    reasons.extend(f"the filter '{match.lower()}'" for match in _FILTER_RE.findall(plain))
    if depth < _MAX_DEPTH:
        for text in quoted:
            if _GATE_RE.search(text) is not None:
                reasons.extend(check_command(text, depth + 1))
    return list(dict.fromkeys(reasons))


def _message(reasons: Sequence[str]) -> str:
    return (
        "BLOCKED by scripts/hooks/guard_gate.py: this command runs scripts/gate.py together with "
        + "; ".join(reasons)
        + ".\nCLAUDE.md section 3: never pipe, filter or redirect the gate output. Run it plainly "
        "(python scripts/gate.py [--full]), or write a log with --log FILE, which keeps the exit "
        "status, or commit with: python scripts/gate.py && git commit -m \"...\". "
        "Run other commands separately."
    )


def main(stdin: TextIO | None = None, stderr: TextIO | None = None) -> int:
    """Read the hook JSON, return the exit code (0 allow, 2 block, 1 unreadable input)."""
    source = stdin if stdin is not None else sys.stdin
    sink = stderr if stderr is not None else sys.stderr
    try:
        event = json.loads(source.read())
        if not isinstance(event, dict):
            raise ValueError("the hook input is not a JSON object")
        tool_input = event.get("tool_input", {})
        command = tool_input.get("command", "") if isinstance(tool_input, dict) else ""
        if not isinstance(command, str):
            raise ValueError("tool_input.command is not text")
    except ValueError as exc:  # includes JSONDecodeError
        print(f"guard_gate.py could not read its input: {exc}", file=sink)
        return 1
    reasons = check_command(command)
    if reasons:
        print(_message(reasons), file=sink)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
