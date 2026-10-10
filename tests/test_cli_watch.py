"""`fim watch` and the jsonl/csv formats of `fim check`, called in-process (CLAUDE.md section 6)."""

from __future__ import annotations

import csv
import io
import json
import os
import stat
from pathlib import Path
from typing import ClassVar

import pytest

from app_helpers import Workspace, make_workspace
from fim.cli import main as cli


# Slow, by decision of the owner (PLAN.md changelog v0.3.8): every test marked slow in this file
# runs `fim watch` or `fim check --format jsonl|csv` end to end on a real tree, key and signed
# baseline, 0.1 to 0.15 s each on Windows. The default gate keeps the help text and the interval
# refusals, which exit before anything is read; --full and CI run all of them.
class NoSleep:
    """Stands in for ``SystemSleeper``: records the pauses, never waits."""

    pauses: ClassVar[list[float]] = []

    def sleep(self, seconds: float) -> None:
        NoSleep.pauses.append(seconds)


@pytest.fixture(autouse=True)
def no_real_sleeping(monkeypatch: pytest.MonkeyPatch) -> None:
    NoSleep.pauses = []
    monkeypatch.setattr(cli, "SystemSleeper", NoSleep)


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    work = make_workspace(tmp_path)
    assert cli.main(["init-key", "--key-file", str(work.key_file)]) == 0
    assert (
        cli.main(
            [
                "baseline",
                "--config",
                str(work.config),
                "--baseline",
                str(work.baseline),
                "--key-file",
                str(work.key_file),
            ]
        )
        == 0
    )
    return work


def change(ws: Workspace) -> None:
    (ws.watched / "file0.txt").write_bytes(b"changed\n")
    (ws.watched / "planted.txt").write_bytes(b"new\n")
    os.chmod(ws.watched / "file1.txt", stat.S_IREAD)


def watch_args(ws: Workspace, *extra: str) -> list[str]:
    return [
        "watch",
        "--baseline",
        str(ws.baseline),
        "--key-file",
        str(ws.key_file),
        "--max-cycles",
        "2",
        "--interval",
        "10",
        *extra,
    ]


def run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    capsys.readouterr()
    code = cli.main(args)
    out, err = capsys.readouterr()
    return code, out, err


# ---- watch ---------------------------------------------------------------------------------------


@pytest.mark.slow
def test_watch_prints_jsonl_events_and_exits_1_when_something_was_reported(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    change(ws)
    code, out, err = run(watch_args(ws), capsys)
    assert code == 1
    events = [json.loads(line) for line in out.splitlines()]
    assert sorted(e["fim"]["kind"] for e in events) == [
        "created",
        "modified",
        "permission_changed",
    ]
    assert all(e["fim"]["schema"] == "fim-event/1" for e in events)
    assert "finished: 2 cycles, 3 events written" in err
    assert NoSleep.pauses == [10.0]


@pytest.mark.slow
def test_a_clean_watch_prints_nothing_and_exits_0(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = run(watch_args(ws), capsys)
    assert code == 0
    assert out == ""
    assert "2 cycles, 0 events" in err


@pytest.mark.slow
def test_watch_output_writes_an_append_log_and_prints_no_events(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    change(ws)
    log = ws.base / "events.jsonl"
    code, out, _ = run(watch_args(ws, "--output", str(log)), capsys)
    assert code == 1
    assert out == ""
    assert len(log.read_text(encoding="ascii").splitlines()) == 3


@pytest.mark.slow
def test_watch_will_not_replace_a_log_without_force(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    log = ws.base / "events.jsonl"
    log.write_bytes(b"old\n")
    code, _, err = run(watch_args(ws, "--output", str(log)), capsys)
    assert code == 2
    assert "already exists; use --force" in err
    assert log.read_bytes() == b"old\n"
    code, _, _ = run(watch_args(ws, "--output", str(log), "--force"), capsys)
    assert code == 0
    assert log.read_bytes() == b""


@pytest.mark.slow
def test_watch_csv_has_a_header_and_rows(ws: Workspace, capsys: pytest.CaptureFixture[str]) -> None:
    change(ws)
    code, out, _ = run(watch_args(ws, "--format", "csv"), capsys)
    assert code == 1
    rows = list(csv.reader(io.StringIO(out, newline="")))
    assert rows[0][:3] == ["timestamp", "host", "kind"]
    assert len(rows) == 4


@pytest.mark.slow
def test_watch_repeat_reports_everything_every_cycle(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    change(ws)
    _, out, _ = run(watch_args(ws, "--repeat"), capsys)
    assert len(out.splitlines()) == 6


@pytest.mark.parametrize("interval", ["9", "0", "86401", "-1"])
def test_watch_refuses_an_interval_outside_the_limits_with_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], interval: str
) -> None:
    """The check comes before any file is read, so no workspace is needed."""
    code, out, err = run(
        ["watch", "--baseline", str(tmp_path / "none"), "--key-file", str(tmp_path / "k"),
         "--interval", interval],
        capsys,
    )  # fmt: skip
    assert code == 2
    assert out == ""
    assert "--interval must be between 10 and 86400" in err
    assert NoSleep.pauses == []


def test_watch_help_names_the_defaults_and_the_exit_codes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["watch", "--help"])
    text = capsys.readouterr().out
    assert "default: 300" in text
    assert "10 to 86400" in text
    assert "Ctrl-C" in text


@pytest.mark.slow
def test_a_tampered_baseline_at_the_start_is_exit_3_with_no_events(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    data = bytearray(ws.baseline.read_bytes())
    data[-20] ^= 0x01
    ws.baseline.write_bytes(bytes(data))
    code, out, err = run(watch_args(ws), capsys)
    assert code == 3
    assert out == ""
    assert "not trustworthy" in err


@pytest.mark.slow
def test_a_baseline_tampered_during_the_watch_is_exit_3_through_the_cli(
    ws: Workspace, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    good = ws.baseline.read_bytes()

    class Tamper(NoSleep):
        def sleep(self, seconds: float) -> None:
            data = bytearray(good)
            data[-20] ^= 0x01
            ws.baseline.write_bytes(bytes(data))

    monkeypatch.setattr(cli, "SystemSleeper", Tamper)
    code, out, err = run(watch_args(ws), capsys)
    assert code == 3
    event = json.loads(out.splitlines()[0])
    assert event["fim"]["kind"] == "baseline_integrity"
    assert event["fim"]["severity"] == "critical"
    assert "no longer verifies" in err


@pytest.mark.slow
def test_ctrl_c_stops_the_watch_with_the_state_so_far(
    ws: Workspace, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    change(ws)

    class Interrupted(NoSleep):
        def sleep(self, seconds: float) -> None:
            raise KeyboardInterrupt

    monkeypatch.setattr(cli, "SystemSleeper", Interrupted)
    code, out, err = run(watch_args(ws, "--max-cycles", "9"), capsys)
    assert code == 1
    assert len(out.splitlines()) == 3
    assert "interrupted: 1 cycles" in err


# ---- check --format jsonl and csv ----------------------------------------------------------


@pytest.mark.slow
def test_check_jsonl_is_one_line_per_finding_and_exit_1(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    change(ws)
    code, out, err = run(
        ["check", "--baseline", str(ws.baseline), "--key-file", str(ws.key_file),
         "--format", "jsonl"],
        capsys,
    )  # fmt: skip
    assert code == 1
    events = [json.loads(line) for line in out.splitlines()]
    assert len(events) == 3
    assert {e["event_type"] for e in events} == {
        "fim.created",
        "fim.modified",
        "fim.permission_changed",
    }
    assert err == ""


@pytest.mark.slow
def test_check_csv_and_the_notes_on_stderr(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    from app_helpers import anchor_file

    change(ws)
    anchor_file(ws).unlink()
    code, out, err = run(
        ["check", "--baseline", str(ws.baseline), "--key-file", str(ws.key_file),
         "--format", "csv"],
        capsys,
    )  # fmt: skip
    assert code == 1
    rows = list(csv.reader(io.StringIO(out, newline="")))
    assert rows[0][2] == "kind"
    assert len(rows) == 4
    assert "no rollback anchor" in err  # not mixed into the data stream
    assert "no rollback anchor" not in out


@pytest.mark.slow
def test_check_jsonl_to_a_file_is_atomic_and_summarised(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    change(ws)
    target = ws.base / "findings.jsonl"
    code, out, _ = run(
        ["check", "--baseline", str(ws.baseline), "--key-file", str(ws.key_file),
         "--format", "jsonl", "--output", str(target)],
        capsys,
    )  # fmt: skip
    assert code == 1
    assert f"report written: {target}" in out
    assert len(target.read_text(encoding="ascii").splitlines()) == 3


@pytest.mark.slow
def test_check_clean_jsonl_is_empty(ws: Workspace, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(
        ["check", "--baseline", str(ws.baseline), "--key-file", str(ws.key_file),
         "--format", "jsonl"],
        capsys,
    )  # fmt: skip
    assert code == 0
    assert out == ""


@pytest.mark.slow
def test_check_says_on_stderr_when_the_list_is_cut_and_keeps_the_data_clean(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from app_helpers import write_config

    work = make_workspace(tmp_path)
    write_config(work.config, [work.watched], limits={"max_findings_reported": 1})
    assert cli.main(["init-key", "--key-file", str(work.key_file)]) == 0
    assert (
        cli.main(
            ["baseline", "--config", str(work.config), "--baseline", str(work.baseline),
             "--key-file", str(work.key_file)]
        )
        == 0
    )  # fmt: skip
    for index in range(3):
        (work.watched / f"new{index}.txt").write_bytes(b"x")
    code, out, err = run(
        ["check", "--baseline", str(work.baseline), "--key-file", str(work.key_file),
         "--format", "jsonl"],
        capsys,
    )  # fmt: skip
    assert code == 1
    assert len(out.splitlines()) == 1
    assert "only the first 1 findings are listed" in err
