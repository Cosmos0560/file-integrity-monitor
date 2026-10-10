"""scripts/gate.py: step order, summary parsing and the keep-going-and-fail behaviour."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

import gate

PY = sys.executable


def _step(name: str, code: str) -> gate.Step:
    return gate.Step(name, (PY, "-c", code))


def test_steps_are_in_the_documented_order() -> None:
    names = [step.name for step in gate.build_steps(full=False)]
    assert names == [
        "ruff check",
        "ruff format --check",
        "mypy --platform linux",
        "mypy --platform win32",
        "architecture",
        "pytest (fast)",
    ]


def test_fast_gate_excludes_slow_tests_and_full_gate_does_not() -> None:
    fast = gate.build_steps(full=False)[-1].command
    full = gate.build_steps(full=True)[-1].command
    assert "not slow" in fast
    assert "not slow" not in full
    assert gate.build_steps(full=True)[-1].name == "pytest (full)"


@pytest.mark.parametrize("full", [False, True])
def test_pytest_step_enforces_branch_coverage_threshold(full: bool) -> None:
    command = gate.build_steps(full=full)[-1].command
    assert "--cov-branch" in command
    assert "--cov-fail-under=85" in command
    assert gate.COVERAGE_MIN == 85


def test_both_mypy_platforms_are_checked() -> None:
    commands = [s.command for s in gate.build_steps(full=False) if s.name.startswith("mypy")]
    assert [c[c.index("--platform") + 1] for c in commands] == ["linux", "win32"]


def test_extract_coverage_returns_the_printed_number() -> None:
    lines = [
        "Name  Stmts",
        "TOTAL  10  1  90%",
        "Required test coverage of 85% reached. Total coverage: 97.55%",
    ]
    assert gate.extract_coverage(lines) == "97.55"
    assert gate.extract_coverage(["nothing here"]) is None


def test_extract_test_summary() -> None:
    lines = ["....", "120 passed, 3 deselected in 9.10s"]
    assert gate.extract_test_summary(lines) == "120 passed, 3 deselected in 9.10s"
    assert gate.extract_test_summary(["no summary"]) is None


def test_failing_step_does_not_stop_later_steps_and_fails_the_gate(tmp_path: Path) -> None:
    steps = [
        _step("first", "print('one')"),
        _step("broken", "import sys; print('bad'); sys.exit(3)"),
        _step("last", "print('three')"),
    ]
    log = tmp_path / "gate.log"
    with log.open("w", encoding="utf-8") as handle:
        status = gate.run_gate(steps, handle)
    text = log.read_text(encoding="utf-8")
    assert status == 1
    assert "three" in text  # the step after the failure still ran
    assert "FAIL  broken" in text
    assert "PASS  first" in text
    assert "RESULT: FAIL" in text


def test_the_last_step_runs_while_the_others_do_and_the_output_keeps_the_order(
    tmp_path: Path,
) -> None:
    """No wall-clock assertion: the first step can only succeed if the last one has started."""
    marker = tmp_path / "last-started"
    waits = (
        "import os, time\n"
        "for _ in range(600):\n"
        f"    if os.path.exists({str(marker)!r}):\n"
        "        print('saw the last step'); raise SystemExit(0)\n"
        "    time.sleep(0.05)\n"
        "raise SystemExit(9)\n"
    )
    steps = [
        _step("waits for the last", waits),
        _step("last", f"open({str(marker)!r}, 'w').close(); print('last output')"),
    ]
    log = tmp_path / "gate.log"
    with log.open("w", encoding="utf-8") as handle:
        status = gate.run_gate(steps, handle)
    text = log.read_text(encoding="utf-8")
    assert status == 0
    assert text.index("=== waits for the last ===") < text.index("=== last ===")
    assert text.index("saw the last step") < text.index("last output")
    assert "PASS  waits for the last" in text
    assert "PASS  last" in text


def test_a_failing_last_step_fails_the_gate_and_is_reported(
    capsys: pytest.CaptureFixture[str],
) -> None:
    steps = [_step("first", "print('one')"), _step("last", "import sys; sys.exit(4)")]
    assert gate.run_gate(steps, None) == 1
    out = capsys.readouterr().out
    assert "PASS  first" in out
    assert "FAIL  last" in out


def test_all_passing_steps_exit_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert gate.run_gate([_step("ok", "print('fine')")], None) == 0
    out = capsys.readouterr().out
    assert "RESULT: PASS" in out
    assert "fine" in out


def test_step_that_cannot_start_is_a_failure_not_a_crash() -> None:
    lines: list[str] = []
    result = gate.run_step(gate.Step("missing", ("this-program-does-not-exist-fim",)), lines.append)
    assert result.returncode == 127
    assert not result.passed
    assert any("could not start step" in line for line in lines)


def test_summary_reports_tests_and_coverage_from_the_pytest_step() -> None:
    result = gate.StepResult(
        "pytest (fast)",
        0,
        1.5,
        ["5 passed in 0.1s", "Required test coverage of 85% reached. Total coverage: 91.20%"],
    )
    summary = "\n".join(gate.format_summary([result], 2.0))
    assert "tests: 5 passed in 0.1s" in summary
    assert "coverage (branch): 91.20%" in summary


def test_main_writes_the_log_file_and_keeps_the_exit_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gate, "build_steps", lambda **_: [_step("bad", "raise SystemExit(5)")])
    log = tmp_path / "out.log"
    assert gate.main(["--log", str(log)]) == 1
    assert "FAIL  bad" in log.read_text(encoding="utf-8")
