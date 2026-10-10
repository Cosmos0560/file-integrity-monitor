"""The quality gate. Run: python scripts/gate.py [--full] [--log FILE]

Runs every step even when an earlier one fails, prints a summary and exits non-zero if any step
failed. Do not pipe or redirect its output; use --log, which writes the log itself and keeps the
exit status. The default run skips tests marked ``slow``; --full runs everything (as CI does).

The last step (pytest) takes several times as long as all the others together, so it is started
first and runs while the others do; its output is held back and printed after theirs. Every step
still runs, in the same order in the output and the summary.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

COVERAGE_MIN = 85

_COVERAGE_RE = re.compile(r"Total coverage:\s*([0-9]+(?:\.[0-9]+)?)%")
_TESTS_RE = re.compile(r"\b(\d+) (?:passed|failed|error)")


@dataclass(frozen=True, slots=True)
class Step:
    """One gate step: a name and the command that runs it."""

    name: str
    command: tuple[str, ...]


@dataclass(slots=True)
class StepResult:
    name: str
    returncode: int
    seconds: float
    lines: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.returncode == 0


def build_steps(*, full: bool, python: str | None = None) -> list[Step]:
    """The gate steps in their fixed order (CLAUDE.md section 3)."""
    py = python or sys.executable
    pytest = [
        py,
        "-m",
        "pytest",
        "-q",
        "--color=no",
        "--cov=fim",
        "--cov-branch",
        "--cov-report=term-missing:skip-covered",
        f"--cov-fail-under={COVERAGE_MIN}",
    ]
    if not full:
        pytest += ["-m", "not slow"]
    return [
        Step("ruff check", (py, "-m", "ruff", "check", "--no-cache", ".")),
        Step("ruff format --check", (py, "-m", "ruff", "format", "--check", "--no-cache", ".")),
        Step("mypy --platform linux", (py, "-m", "mypy", "--platform", "linux")),
        Step("mypy --platform win32", (py, "-m", "mypy", "--platform", "win32")),
        Step("architecture", (py, "scripts/check_architecture.py")),
        Step("pytest" + (" (full)" if full else " (fast)"), tuple(pytest)),
    ]


def child_environment() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["NO_COLOR"] = "1"
    return env


def extract_coverage(lines: Sequence[str]) -> str | None:
    """The coverage percentage exactly as pytest-cov printed it, or None."""
    for line in reversed(lines):
        match = _COVERAGE_RE.search(line)
        if match:
            return match.group(1)
    return None


def extract_test_summary(lines: Sequence[str]) -> str | None:
    """The pytest result line (for example '120 passed, 3 deselected in 9.10s'), or None."""
    for line in reversed(lines):
        if _TESTS_RE.search(line) and " in " in line:
            return line.strip().strip("=").strip()
    return None


def run_step(step: Step, emit: Callable[[str], None]) -> StepResult:
    """Run one step, streaming its output through ``emit``."""
    emit(f"\n=== {step.name} ===")
    emit("$ " + " ".join(step.command))
    started = time.perf_counter()
    result = StepResult(step.name, 1, 0.0)
    try:
        with subprocess.Popen(
            step.command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=child_environment(),
        ) as process:
            if process.stdout is None:  # cannot happen: PIPE was requested above
                raise OSError("no stdout pipe")
            for raw in process.stdout:
                line = raw.rstrip("\r\n")
                result.lines.append(line)
                emit(line)
            result.returncode = process.wait()
    except OSError as exc:
        emit(f"could not start step: {type(exc).__name__}: {exc}")
        result.returncode = 127
    result.seconds = time.perf_counter() - started
    return result


def format_summary(results: Sequence[StepResult], total_seconds: float) -> list[str]:
    width = max((len(r.name) for r in results), default=10)
    lines = ["", "=== gate summary ==="]
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        lines.append(f"{status}  {r.name.ljust(width)}  {r.seconds:6.1f}s")
    for r in results:
        if r.name.startswith("pytest"):
            tests = extract_test_summary(r.lines)
            coverage = extract_coverage(r.lines)
            if tests:
                lines.append(f"tests: {tests}")
            if coverage:
                lines.append(f"coverage (branch): {coverage}% (minimum {COVERAGE_MIN}%)")
    overall = "PASS" if all(r.passed for r in results) else "FAIL"
    lines.append(f"total: {total_seconds:.1f}s  RESULT: {overall}")
    return lines


def run_gate(steps: Sequence[Step], log: TextIO | None) -> int:
    """Run all steps, print the summary, return the process exit status."""

    def emit(line: str) -> None:
        print(line, flush=True)
        if log is not None:
            log.write(line + "\n")
            log.flush()

    started = time.perf_counter()
    *front, last = steps
    held: list[str] = []  # list.append is atomic, so the worker and this thread can share it
    background: list[StepResult] = []
    worker = threading.Thread(target=lambda: background.append(run_step(last, held.append)))
    worker.start()
    results = [run_step(step, emit) for step in front]
    sent = 0
    while worker.is_alive() or sent < len(held):
        while sent < len(held):
            emit(held[sent])
            sent += 1
        worker.join(timeout=0.05)
    results.append(background[0] if background else StepResult(last.name, 1, 0.0))
    for line in format_summary(results, time.perf_counter() - started):
        emit(line)
    return 0 if all(r.passed for r in results) else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the fim quality gate.")
    parser.add_argument("--full", action="store_true", help="include tests marked slow (CI mode)")
    parser.add_argument("--log", type=Path, metavar="FILE", help="also write the output to FILE")
    args = parser.parse_args(argv)
    # A console that cannot encode some character must not crash the gate.
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(errors="backslashreplace")
    steps = build_steps(full=args.full)
    if args.log is None:
        return run_gate(steps, None)
    with args.log.open("w", encoding="utf-8", newline="\n") as log:
        return run_gate(steps, log)


if __name__ == "__main__":
    sys.exit(main())
