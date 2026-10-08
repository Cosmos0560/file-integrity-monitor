"""The Phase 1 command line: only --version exists."""

from __future__ import annotations

import re
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

import fim
from fim.cli import main as cli


def test_version_flag_prints_name_and_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--version"]) == 0
    out = capsys.readouterr().out
    assert out.strip() == f"fim {fim.__version__}"


def test_version_constant_is_a_release_number() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", fim.__version__)


def test_no_arguments_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "usage: fim" in captured.err


def test_unknown_option_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--no-such-option"]) == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def test_help_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--help"]) == 0
    assert "usage: fim" in capsys.readouterr().out


def test_main_reads_sys_argv_when_called_without_arguments(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["fim", "--version"])
    assert cli.main() == 0
    assert capsys.readouterr().out.startswith("fim ")


def test_python_dash_m_entry_point_runs_main(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["fim", "--version"])
    with pytest.raises(SystemExit) as raised:
        runpy.run_module("fim", run_name="__main__")
    assert raised.value.code == 0
    assert capsys.readouterr().out.startswith("fim ")


@pytest.mark.slow
def test_subprocess_end_to_end_version(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "fim", "--version"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == f"fim {fim.__version__}"
