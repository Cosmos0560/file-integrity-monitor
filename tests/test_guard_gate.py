"""scripts/hooks/guard_gate.py: the hook that keeps the gate output unpiped and unredirected."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import REPO_ROOT
from hooks import guard_gate

ALLOWED = [
    "python scripts/gate.py",
    "python scripts/gate.py --full",
    "python scripts/gate.py --log gate.log",
    "python scripts/gate.py --full --log out/gate-full.log",
    ".venv/Scripts/python.exe scripts/gate.py",
    r".venv\Scripts\python.exe scripts\gate.py --log gate.log",
    'python scripts/gate.py && git commit -m "fix: handle the pipe | and > in messages"',
    "python scripts/gate.py && git commit -m 'head and tail and tee are only words here'",
    'python scripts/gate.py && git commit -m "keep 2>&1 | tail out of the gate; || true is bad"',
    "python scripts/gate.py && git commit -m \"$(cat <<'EOF'\nfeat: a | b > c\nEOF\n)\"",
    "python scripts/gate.py; if ($LASTEXITCODE -eq 0) { git commit -m 'x' }",
    "git add a b && python scripts/gate.py && git commit -m 'x'",
    "python scripts/gate.py --log gate-tail.log",
    "python scripts/gate.py --log head.txt",
    # Other files whose names merely end in gate.py are not the gate.
    "python -m pytest tests/test_gate.py | tail -3",
    "python -m pytest tests/test_guard_gate.py -q 2>&1 | tail -30",
    "python scripts/hooks/guard_gate.py < event.json > out.txt",
    # Not the gate: pipes and redirects are fine there.
    "git log --oneline | head -15",
    "pytest -q | tail -3",
    "echo hello > out.txt",
    "git status --short 2>&1 | grep M",
    "",
]

BLOCKED = [
    ("python scripts/gate.py | tail -20", "pipe"),
    ("python scripts/gate.py --full | tee gate.txt", "pipe"),
    ("python scripts/gate.py |& head", "pipe"),
    ("python scripts/gate.py > out.txt", "redirect"),
    ("python scripts/gate.py >> out.txt", "redirect"),
    ("python scripts/gate.py 2>&1", "redirect"),
    ("python scripts/gate.py &> out.txt", "redirect"),
    ("python scripts/gate.py 2>/dev/null", "redirect"),
    ("python scripts/gate.py >/dev/null", "redirect"),
    ("python scripts/gate.py || true", "pipe"),
    ("python scripts/gate.py; true", "swallows"),
    ("python scripts/gate.py ; true", "swallows"),
    ("python scripts/gate.py && true", "swallows"),
    ("python scripts/gate.py; exit 0", "swallows"),
    ("python scripts/gate.py; git status | cat", "pipe"),
    ("python scripts/gate.py --log gate.log | tail -5", "pipe"),
    ("python scripts/gate.py | Select-String FAIL", "pipe"),
    ("python scripts/gate.py | sls FAIL", "pipe"),
    ("python scripts/gate.py | findstr FAIL", "pipe"),
    ("python scripts/gate.py | Out-File x.txt", "pipe"),
    ("python scripts/gate.py --log=a.log | tee", "pipe"),
    ("cd /tmp && python scripts/gate.py 2>&1 | tail -3", "pipe"),
    (r".venv\Scripts\python.exe scripts\gate.py | tail", "pipe"),
    ("python scripts/gate.py $(echo | head)", "pipe"),
    ('bash -c "python scripts/gate.py | tail"', "pipe"),
    ("sh -c 'python scripts/gate.py > /dev/null'", "redirect"),
    ('bash -c "bash -c \\"python scripts/gate.py | tail\\""', "pipe"),
    ("python scripts/gate.py tail", "filter"),
    ("python scripts/gate.py head", "filter"),
    ("python scripts/gate.py tee", "filter"),
    ("python scripts/gate.py TAIL", "filter"),
    ("python scripts/gate.py Select-String", "filter"),
    ("python scripts/gate.py && git commit -m 'x' | tail", "pipe"),
    ("python scripts/gate.py && git commit -m 'x' > /dev/null", "redirect"),
]


@pytest.mark.parametrize("command", ALLOWED)
def test_allowed_commands_pass(command: str) -> None:
    assert guard_gate.check_command(command) == []


@pytest.mark.parametrize(("command", "reason"), BLOCKED)
def test_blocked_commands_are_blocked_with_a_reason(command: str, reason: str) -> None:
    reasons = guard_gate.check_command(command)
    assert reasons, command
    assert any(reason in item for item in reasons), reasons


def test_an_escaped_operator_is_literal_not_a_pipe() -> None:
    assert guard_gate.check_command(r"python scripts/gate.py --log a\|b.log") == []


def test_quotes_hide_syntax_but_not_a_nested_gate_command() -> None:
    plain, quoted = guard_gate.skeleton("a 'b | c' \"d > e\" f")
    assert plain == "a '' \"\" f"
    assert quoted == ["b | c", "d > e"]
    assert guard_gate.check_command("echo 'python scripts/gate.py' | tail") != []
    assert guard_gate.check_command("echo 'not it' | tail") == []


def test_an_unterminated_quote_is_treated_as_quoted() -> None:
    assert guard_gate.check_command("python scripts/gate.py --log 'a | b") == []
    assert guard_gate.check_command("python scripts/gate.py | tail 'x") != []


def test_deep_nesting_terminates() -> None:
    command = "python scripts/gate.py"
    for _ in range(10):
        command = 'bash -c "' + command.replace('"', '\\"') + '"'
    guard_gate.check_command(command)


# ---- the hook protocol ---------------------------------------------------------------------------


def run_hook(payload: object) -> tuple[int, str]:
    stdin = io.StringIO(payload if isinstance(payload, str) else json.dumps(payload))
    stderr = io.StringIO()
    return guard_gate.main(stdin, stderr), stderr.getvalue()


def bash(command: str) -> dict[str, object]:
    return {"tool_name": "Bash", "tool_input": {"command": command}}


def test_main_allows_a_plain_gate_run() -> None:
    assert run_hook(bash("python scripts/gate.py --full")) == (0, "")


def test_main_blocks_with_exit_2_and_a_clear_message() -> None:
    code, message = run_hook(bash("python scripts/gate.py 2>&1 | tail -5"))
    assert code == 2
    assert "BLOCKED" in message
    assert "a pipe" in message
    assert "an output redirect" in message
    assert "the filter 'tail'" in message
    assert "--log FILE" in message
    assert "CLAUDE.md section 3" in message


def test_main_ignores_commands_without_the_gate() -> None:
    assert run_hook(bash("git log --oneline | head -15")) == (0, "")


def test_main_allows_input_without_a_command() -> None:
    assert run_hook({"tool_name": "Bash", "tool_input": {}}) == (0, "")
    assert run_hook({"tool_name": "Bash"}) == (0, "")
    assert run_hook({"tool_name": "Bash", "tool_input": "text"}) == (0, "")


@pytest.mark.parametrize("payload", ["", "not json", "[]", "3", '{"tool_input": {"command": 5}}'])
def test_unreadable_input_is_a_non_blocking_error(payload: str) -> None:
    code, message = run_hook(payload)
    assert code == 1  # not 2: a broken hook must never block every command
    assert "could not read its input" in message


@pytest.mark.slow
def test_the_script_runs_as_the_settings_file_runs_it(tmp_path: Path) -> None:
    script = REPO_ROOT / "scripts" / "hooks" / "guard_gate.py"

    def hook(command: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(script)],
            input=json.dumps(bash(command)),
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=False,
        )

    assert hook("python scripts/gate.py --log x.log").returncode == 0
    blocked = hook("python scripts/gate.py | tail")
    assert blocked.returncode == 2
    assert "BLOCKED" in blocked.stderr


# ---- the settings file ---------------------------------------------------------------------------


def test_the_project_settings_register_the_hook_for_bash() -> None:
    settings = json.loads((REPO_ROOT / ".claude" / "settings.json").read_text(encoding="utf-8"))
    entries = settings["hooks"]["PreToolUse"]
    assert [entry["matcher"] for entry in entries] == ["Bash"]
    commands = [hook["command"] for hook in entries[0]["hooks"]]
    assert commands == ['python "$CLAUDE_PROJECT_DIR/scripts/hooks/guard_gate.py"']
    assert entries[0]["hooks"][0]["type"] == "command"
    assert (REPO_ROOT / "scripts" / "hooks" / "guard_gate.py").is_file()
