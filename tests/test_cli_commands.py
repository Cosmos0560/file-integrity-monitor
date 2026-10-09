"""The ``init-key`` and ``baseline`` commands, called in-process through ``main(argv)``."""

from __future__ import annotations

import io
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from app_helpers import Workspace, anchor_file, make_workspace, tree_state, write_config
from fim.cli import main as cli
from fim.core.errors import (
    BaselineIntegrityError,
    ConfigError,
    ExitCode,
    FileMissingError,
    LimitReachedError,
)
from fim.services import keystore


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    return make_workspace(tmp_path)


def init_key_args(ws: Workspace, *extra: str) -> list[str]:
    return ["init-key", "--key-file", str(ws.key_file), *extra]


def baseline_args(ws: Workspace, *extra: str) -> list[str]:
    return [
        "baseline",
        "--config",
        str(ws.config),
        "--baseline",
        str(ws.baseline),
        "--key-file",
        str(ws.key_file),
        *extra,
    ]


def key_hex(ws: Workspace) -> str:
    return keystore.load_key(str(ws.key_file)).secret.hex()


# ---- init-key ------------------------------------------------------------------------------------


def test_init_key_creates_a_key_prints_its_id_and_never_the_key(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(init_key_args(ws)) == 0
    out, err = capsys.readouterr()
    key = keystore.load_key(str(ws.key_file))
    assert f"key id: {key.key_id}" in out
    assert "key file written:" in out
    assert key.secret.hex() not in out + err
    assert err == ""


def test_init_key_twice_is_exit_2_until_force(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(init_key_args(ws)) == 0
    first = ws.key_file.read_bytes()
    capsys.readouterr()
    assert cli.main(init_key_args(ws)) == 2
    out, err = capsys.readouterr()
    assert out == ""
    assert "fim: error:" in err
    assert "already exists; use --force" in err
    assert ws.key_file.read_bytes() == first
    assert cli.main(init_key_args(ws, "--force")) == 0
    assert ws.key_file.read_bytes() != first


def test_init_key_with_config_refuses_a_key_inside_a_monitored_path(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    args = ["init-key", "--key-file", str(ws.watched / "fim.key"), "--config", str(ws.config)]
    assert cli.main(args) == 2
    assert "must not be inside a monitored path" in capsys.readouterr().err
    assert not (ws.watched / "fim.key").exists()


def test_init_key_requires_a_key_file(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["init-key"]) == 2
    assert "--key-file" in capsys.readouterr().err


# ---- baseline ------------------------------------------------------------------------------------


def test_baseline_end_to_end(ws: Workspace, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(init_key_args(ws)) == 0
    capsys.readouterr()
    before = tree_state(ws.watched)
    assert cli.main(baseline_args(ws)) == 0
    out, err = capsys.readouterr()
    assert err == ""
    assert "baseline written:" in out
    assert "  records: 6" in out
    assert "  sequence: 1" in out
    assert "  complete: yes" in out
    assert "rollback anchor created:" in out
    assert ws.baseline.exists()
    assert anchor_file(ws).exists()
    assert tree_state(ws.watched) == before

    assert cli.main(baseline_args(ws)) == 2  # exists
    assert "already exists; use --force" in capsys.readouterr().err
    assert cli.main(baseline_args(ws, "--force")) == 0
    out, _ = capsys.readouterr()
    assert "  sequence: 2" in out
    assert "rollback anchor updated:" in out


def test_baseline_output_never_contains_the_key(
    ws: Workspace, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    cli.main(init_key_args(ws))
    secret = key_hex(ws)
    cli.main(baseline_args(ws))
    cli.main(baseline_args(ws))  # exists: an error path
    cli.main(baseline_args(ws, "--force"))
    ws.baseline.write_bytes(b"damaged")
    cli.main(baseline_args(ws, "--force"))
    out, err = capsys.readouterr()
    assert secret not in out + err + caplog.text
    assert caplog.records == []


def test_baseline_with_the_key_in_the_configuration(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    cli.main(init_key_args(ws))
    write_config(ws.config, [ws.watched], key_file=ws.key_file)
    args = ["baseline", "--config", str(ws.config), "--baseline", str(ws.baseline)]
    assert cli.main(args) == 0


def test_baseline_without_any_key_is_exit_2(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    args = ["baseline", "--config", str(ws.config), "--baseline", str(ws.baseline)]
    assert cli.main(args) == 2
    assert "no key file" in capsys.readouterr().err
    assert not ws.baseline.exists()


def test_baseline_with_a_missing_key_file_is_exit_2(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(baseline_args(ws)) == 2
    assert "key file" in capsys.readouterr().err
    assert not ws.baseline.exists()


def test_baseline_that_hits_a_limit_exits_4_and_writes_nothing(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    cli.main(init_key_args(ws))
    write_config(ws.config, [ws.watched], limits={"max_files": 3})
    capsys.readouterr()
    assert cli.main(baseline_args(ws)) == 4
    out, err = capsys.readouterr()
    assert out == ""
    assert "fim: error: the scan was incomplete" in err
    assert "nothing was written" in err
    assert "--allow-incomplete" in err
    assert not ws.baseline.exists()
    assert not anchor_file(ws).exists()


def test_baseline_allow_incomplete_writes_the_baseline_and_still_exits_4(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    cli.main(init_key_args(ws))
    write_config(ws.config, [ws.watched], limits={"max_files": 3})
    capsys.readouterr()
    assert cli.main(baseline_args(ws, "--allow-incomplete")) == 4
    out, err = capsys.readouterr()
    assert "  complete: no" in out
    assert "scan was incomplete" in err
    assert "limit_reached" in err
    assert ws.baseline.exists()


def test_allow_incomplete_is_an_option_of_baseline_only(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["init-key", "--key-file", "x", "--allow-incomplete"]) == 2
    assert "unrecognized arguments: --allow-incomplete" in capsys.readouterr().err


def test_baseline_of_an_unavailable_path_is_exit_2(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    cli.main(init_key_args(ws))
    write_config(ws.config, [ws.base / "gone"])
    capsys.readouterr()
    assert cli.main(baseline_args(ws)) == 2
    assert "monitored path is unavailable" in capsys.readouterr().err
    assert not ws.baseline.exists()


def test_baseline_shows_scan_issues_as_warnings_and_caps_them(
    ws: Workspace, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from fim.app.baseline import BaselineOutcome
    from fim.core.models import IssueKind, ScanIssue

    issues = tuple(
        ScanIssue(path=f"/x/f{i}", kind=IssueKind.UNREADABLE, detail="cannot be read (EACCES)")
        for i in range(25)
    )
    outcome = BaselineOutcome(
        baseline_path=str(ws.baseline),
        anchor_path=str(anchor_file(ws)),
        key_id="0" * 16,
        sequence=1,
        records=1,
        complete=True,
        issues=issues,
        size_bytes=1,
        anchor_existed=True,
    )
    monkeypatch.setattr(cli, "run_baseline", lambda *_a, **_k: outcome)
    assert cli.main(baseline_args(ws)) == 0
    err = capsys.readouterr().err
    assert err.count("warning: unreadable:") == 20
    assert "... and 5 more scan issues" in err


# ---- errors become exit codes --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (ConfigError("bad config"), 2),
        (FileMissingError("gone"), 2),
        (BaselineIntegrityError("tampered"), 3),
        (LimitReachedError("too big"), 4),
    ],
)
def test_a_fim_error_is_one_line_on_stderr_and_its_exit_code(
    ws: Workspace,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    code: int,
) -> None:
    def fail(*_a: Any, **_k: Any) -> None:
        raise error

    monkeypatch.setattr(cli, "run_baseline", fail)
    assert cli.main(baseline_args(ws)) == code
    out, err = capsys.readouterr()
    assert out == ""
    assert err == f"fim: error: {error}\n"


def test_exit_codes_match_the_documented_values() -> None:
    assert (ExitCode.OK, ExitCode.FINDINGS, ExitCode.ERROR) == (0, 1, 2)
    assert (ExitCode.INTEGRITY, ExitCode.INCOMPLETE) == (3, 4)


def test_a_hostile_message_is_clean_on_the_terminal(
    ws: Workspace, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*_a: Any, **_k: Any) -> None:
        raise ConfigError("path 'a\x1b[31mb\u202ec' is odd\nsecond line")

    monkeypatch.setattr(cli, "run_baseline", fail)
    assert cli.main(baseline_args(ws)) == 2
    err = capsys.readouterr().err
    assert "\x1b" not in err
    assert "\u202e" not in err
    assert err.count("\n") == 1


def test_a_console_that_cannot_encode_a_character_does_not_crash(
    ws: Workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw_out, raw_err = io.BytesIO(), io.BytesIO()
    stdout = io.TextIOWrapper(raw_out, encoding="cp1252", errors="strict")
    stderr = io.TextIOWrapper(raw_err, encoding="cp1252", errors="strict")
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", stderr)

    def fail(*_a: Any, **_k: Any) -> None:
        raise ConfigError("name \u0416\u0443\u043a is not allowed")

    monkeypatch.setattr(cli, "run_baseline", fail)
    assert cli.main(baseline_args(ws)) == 2
    stderr.flush()
    text = raw_err.getvalue().decode("cp1252")
    assert "\\u0416" in text


def test_help_for_every_command_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    for command in ("init-key", "baseline"):
        assert cli.main([command, "--help"]) == 0
        assert "--force" in capsys.readouterr().out


# ---- the key never travels in argv or the environment --------------------------------------------


def all_option_strings() -> list[str]:
    parser = cli.build_parser()
    options = [string for action in parser._actions for string in action.option_strings]
    for action in parser._actions:
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict):
            for sub in choices.values():
                options.extend(s for a in sub._actions for s in a.option_strings)
    return options


def test_no_option_takes_a_key_value() -> None:
    options = all_option_strings()
    assert "--key-file" in options
    for option in options:
        assert option in {
            "-h",
            "--help",
            "--version",
            "--key-file",
            "--config",
            "--force",
            "--baseline",
            "--allow-incomplete",
        }


def test_a_key_value_on_the_command_line_is_not_accepted(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = "ab" * 32
    for flag in ("--key", "--secret", "--hmac-key", "--password"):
        assert (
            cli.main(["baseline", "--config", str(ws.config), "--baseline", "x", flag, secret]) == 2
        )
    assert cli.main(["init-key", "--key", secret]) == 2  # no abbreviation of --key-file either
    assert "unrecognized arguments" in capsys.readouterr().err


def test_no_environment_variable_supplies_the_key(
    ws: Workspace, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = "ab" * 32
    for name in ("FIM_KEY", "FIM_HMAC_KEY", "FIM_SECRET", "HMAC_KEY"):
        monkeypatch.setenv(name, secret)
    args = ["baseline", "--config", str(ws.config), "--baseline", str(ws.baseline)]
    assert cli.main(args) == 2
    assert "no key file" in capsys.readouterr().err


# ---- general behaviour ---------------------------------------------------------------------------


def test_no_command_is_a_usage_error() -> None:
    assert cli.main([]) == 2


def test_unknown_command_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["frobnicate"]) == 2
    assert "invalid choice" in capsys.readouterr().err


@pytest.mark.slow
def test_subprocess_end_to_end(ws: Workspace) -> None:
    def fim(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "fim", *args],
            cwd=ws.base,
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "PYTHONUTF8": "1"},
        )

    created = fim("init-key", "--key-file", str(ws.key_file))
    assert created.returncode == 0, created.stderr
    made = fim(
        "baseline", "--config", str(ws.config), "--baseline", str(ws.baseline),
        "--key-file", str(ws.key_file),
    )  # fmt: skip
    assert made.returncode == 0, made.stderr
    assert "sequence: 1" in made.stdout
    again = fim(
        "baseline", "--config", str(ws.config), "--baseline", str(ws.baseline),
        "--key-file", str(ws.key_file),
    )  # fmt: skip
    assert again.returncode == 2
    assert key_hex(ws) not in made.stdout + made.stderr + again.stdout + again.stderr


def test_streams_without_reconfigure_are_left_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    class Plain:
        def write(self, _text: str) -> int:
            return 0

    monkeypatch.setattr(sys, "stdout", Plain())
    monkeypatch.setattr(sys, "stderr", Plain())
    cli._configure_streams()  # must not raise


def test_a_tampered_anchor_makes_baseline_exit_3_with_a_clear_message(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    cli.main(init_key_args(ws))
    assert cli.main(baseline_args(ws)) == 0
    anchor = anchor_file(ws)
    anchor.write_bytes(anchor.read_bytes().replace(b"sequence 1", b"sequence 7"))
    before = ws.baseline.read_bytes()
    capsys.readouterr()
    assert cli.main(baseline_args(ws, "--force")) == 3
    out, err = capsys.readouterr()
    assert out == ""
    assert err.startswith("fim: error: the rollback anchor is not trustworthy: ")
    assert "MAC does not verify" in err
    assert ws.baseline.read_bytes() == before
