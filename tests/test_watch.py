"""app/watch.py: ``check`` on an interval with delta output (PLAN.md D9), on a fake clock and a
fake sleeper, with the world changed in the pauses between cycles."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable, Sequence
from datetime import datetime
from itertools import pairwise
from pathlib import Path
from typing import Any

import pytest

from app_helpers import Workspace, anchor_file, make_workspace, write_config
from fakes import FakeClock, FakeSleeper
from fim.app.watch import WATCH_FORMATS, WatchOutcome, WatchRequest, run_watch
from fim.cli import main as cli
from fim.core.errors import BaselineIntegrityError, ExitCode, FileAccessError, UsageError
from fim.core.limits import (
    WATCH_INTERVAL_DEFAULT_SECONDS,
    WATCH_INTERVAL_MAX_SECONDS,
    WATCH_INTERVAL_MIN_SECONDS,
)
from fim.core.models import Severity


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    return make_workspace(tmp_path)


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


def make_baseline(ws: Workspace, *extra: str) -> None:
    if not ws.key_file.exists():
        assert cli.main(["init-key", "--key-file", str(ws.key_file)]) == 0
    assert cli.main(baseline_args(ws, *extra)) == 0


class Script(FakeSleeper):
    """A sleeper whose pauses are the test's chance to change the world between cycles."""

    def __init__(self, clock: FakeClock, actions: Sequence[Callable[[], object]] = ()) -> None:
        super().__init__(clock)
        self.actions = list(actions)

    def sleep(self, seconds: float) -> None:
        super().sleep(seconds)
        index = len(self.sleeps) - 1
        if index < len(self.actions):
            self.actions[index]()


class Run:
    def __init__(self, outcome: WatchOutcome, out: list[str], notes: list[str], sleeper: Script):
        self.outcome = outcome
        self.out = out
        self.notes = notes
        self.sleeper = sleeper

    @property
    def lines(self) -> list[str]:
        return [line for text in self.out for line in text.splitlines()]

    @property
    def events(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.lines]

    def kinds(self) -> list[str]:
        return [event["fim"]["kind"] for event in self.events]

    def names(self) -> list[tuple[str, str]]:
        return [
            (event["fim"]["kind"], os.path.basename(event["fim"].get("path", "")))
            for event in self.events
        ]


def watch(
    ws: Workspace,
    *,
    actions: Sequence[Callable[[], object]] = (),
    clock: FakeClock | None = None,
    **fields: Any,
) -> Run:
    clock = clock or FakeClock()
    sleeper = Script(clock, actions)
    out: list[str] = []
    notes: list[str] = []
    request = WatchRequest(
        baseline_path=str(ws.baseline),
        **(
            {"key_file": str(ws.key_file), "config_path": None}
            | {"max_cycles": 2, "interval_seconds": 30}
            | fields
        ),
    )
    outcome = run_watch(request, clock, sleeper, emit=out.append, notify=notes.append)
    return Run(outcome, out, notes, sleeper)


def modify(ws: Workspace, name: str, content: bytes) -> Callable[[], object]:
    return lambda: (ws.watched / name).write_bytes(content)


# ---- delta output --------------------------------------------------------------------------------


def test_a_clean_tree_emits_nothing_and_exits_0(ws: Workspace) -> None:
    make_baseline(ws)
    run = watch(ws, max_cycles=3)
    assert run.out == []
    assert run.outcome.cycles == 3
    assert run.outcome.exit_code is ExitCode.OK
    assert run.sleeper.sleeps == [30, 30]


def test_the_first_cycle_reports_every_finding_and_later_cycles_only_new_ones(
    ws: Workspace,
) -> None:
    make_baseline(ws)
    (ws.watched / "file0.txt").write_bytes(b"changed before the watch\n")
    run = watch(
        ws,
        max_cycles=3,
        actions=[modify(ws, "new.txt", b"planted during the watch\n")],
    )
    assert run.names() == [("modified", "file0.txt"), ("created", "new.txt")]
    assert run.outcome.findings_reported == 2
    assert run.outcome.exit_code is ExitCode.FINDINGS


def test_a_finding_that_goes_away_is_reported_resolved_with_the_same_id(ws: Workspace) -> None:
    make_baseline(ws)
    original = (ws.watched / "file0.txt").read_bytes()
    (ws.watched / "file0.txt").write_bytes(b"tampered\n")
    run = watch(ws, max_cycles=3, actions=[modify(ws, "file0.txt", original)])
    assert run.kinds() == ["modified", "resolved"]
    first, second = run.events
    assert second["fim"]["finding_id"] == first["fim"]["finding_id"]
    assert second["fim"]["path"] == first["fim"]["path"]
    assert second["fim"]["severity"] == "info"
    assert second["event_type"] == "fim.resolved"
    assert "no longer reported: modified" in second["fim"]["evidence"]


def test_a_file_changed_again_is_a_new_finding_and_the_old_one_resolves(ws: Workspace) -> None:
    make_baseline(ws)
    (ws.watched / "file0.txt").write_bytes(b"first change\n")
    run = watch(ws, actions=[modify(ws, "file0.txt", b"second change\n")])
    assert run.kinds() == ["modified", "modified", "resolved"]
    ids = [event["fim"]["finding_id"] for event in run.events]
    assert ids[0] != ids[1]
    assert ids[2] == ids[0]


def test_repeat_reports_every_finding_in_every_cycle(ws: Workspace) -> None:
    make_baseline(ws)
    (ws.watched / "file0.txt").write_bytes(b"changed\n")
    run = watch(ws, max_cycles=3, repeat=True)
    assert run.kinds() == ["modified", "modified", "modified"]
    assert run.outcome.findings_reported == 3


def test_min_severity_hides_lower_findings_in_every_cycle(ws: Workspace) -> None:
    make_baseline(ws)
    os.chmod(ws.watched / "file0.txt", stat.S_IREAD)
    shown = watch(ws, min_severity=Severity.INFO)
    hidden = watch(ws, min_severity=Severity.CRITICAL)
    assert "permission_changed" in shown.kinds()
    assert hidden.out == []
    assert hidden.outcome.exit_code is ExitCode.OK


# ---- timing --------------------------------------------------------------------------------------


def test_cycles_are_one_interval_apart_and_never_overlap(ws: Workspace) -> None:
    make_baseline(ws)
    (ws.watched / "file0.txt").write_bytes(b"changed\n")
    clock = FakeClock()
    run = watch(ws, clock=clock, max_cycles=4, interval_seconds=45, repeat=True)
    stamps = [event["timestamp"] for event in run.events]
    assert len(stamps) == 4
    parsed = [datetime.fromisoformat(stamp.replace("Z", "+00:00")) for stamp in stamps]
    gaps = [(later - earlier).total_seconds() for earlier, later in pairwise(parsed)]
    assert gaps == [45, 45, 45]
    assert run.sleeper.sleeps == [45, 45, 45]  # no sleep after the last cycle


def test_the_default_interval_is_the_documented_one(ws: Workspace) -> None:
    make_baseline(ws)
    sleeper_run = watch(ws, interval_seconds=WATCH_INTERVAL_DEFAULT_SECONDS)
    assert sleeper_run.sleeper.sleeps == [300]
    assert WatchRequest(baseline_path="b", key_file=None, config_path=None).interval_seconds == 300


@pytest.mark.parametrize(
    "interval",
    [WATCH_INTERVAL_MIN_SECONDS - 1, 0, -5, WATCH_INTERVAL_MAX_SECONDS + 1],
)
def test_an_interval_outside_the_limits_is_a_usage_error_before_anything_is_read(
    ws: Workspace, interval: float
) -> None:
    with pytest.raises(UsageError, match="--interval must be between 10 and 86400"):
        watch(ws, interval_seconds=interval)


def test_the_limits_themselves_are_accepted(ws: Workspace) -> None:
    make_baseline(ws)
    for interval in (WATCH_INTERVAL_MIN_SECONDS, WATCH_INTERVAL_MAX_SECONDS):
        assert watch(ws, interval_seconds=interval, max_cycles=1).outcome.cycles == 1


def test_max_cycles_must_be_positive_and_the_format_known(ws: Workspace) -> None:
    with pytest.raises(UsageError, match="--max-cycles"):
        watch(ws, max_cycles=0)
    with pytest.raises(UsageError, match="--format"):
        watch(ws, output_format="table")
    assert WATCH_FORMATS == ("jsonl", "csv")


# ---- the baseline is verified every cycle --------------------------------------------------------


def test_a_tampered_baseline_mid_watch_is_one_critical_event_and_exit_3(ws: Workspace) -> None:
    make_baseline(ws)
    good = ws.baseline.read_bytes()

    def tamper() -> None:
        data = bytearray(good)
        data[-20] ^= 0x01
        ws.baseline.write_bytes(bytes(data))

    run = watch(
        ws,
        max_cycles=4,
        actions=[tamper, modify(ws, "new.txt", b"still seen against the last good baseline\n")],
    )
    kinds = run.kinds()
    assert kinds.count("baseline_integrity") == 1  # said once, not every cycle
    assert "created" in kinds  # the checks went on with the last verified baseline
    integrity = next(e for e in run.events if e["fim"]["kind"] == "baseline_integrity")
    assert integrity["fim"]["severity"] == "critical"
    assert integrity["event_type"] == "fim.baseline_integrity"
    assert run.outcome.baseline_failed
    assert run.outcome.exit_code is ExitCode.INTEGRITY
    assert any("no longer verifies" in note for note in run.notes)


def test_a_deleted_baseline_mid_watch_is_the_same_event_and_exit_3(ws: Workspace) -> None:
    make_baseline(ws)
    run = watch(ws, max_cycles=3, actions=[lambda: ws.baseline.unlink()])
    assert run.kinds().count("baseline_integrity") == 1
    assert run.outcome.exit_code is ExitCode.INTEGRITY


def test_a_baseline_that_verifies_again_resolves_the_event_but_the_exit_stays_3(
    ws: Workspace,
) -> None:
    make_baseline(ws)
    good = ws.baseline.read_bytes()
    run = watch(
        ws,
        max_cycles=4,
        actions=[lambda: ws.baseline.unlink(), lambda: ws.baseline.write_bytes(good)],
    )
    assert run.kinds() == ["baseline_integrity", "resolved"]
    assert run.events[1]["fim"]["finding_id"] == run.events[0]["fim"]["finding_id"]
    assert run.outcome.exit_code is ExitCode.INTEGRITY


def test_an_older_signed_baseline_put_back_mid_watch_is_a_rollback_event(ws: Workspace) -> None:
    make_baseline(ws)
    old = ws.baseline.read_bytes()
    assert cli.main(baseline_args(ws, "--force")) == 0  # sequence 2, anchor moves on

    run = watch(ws, max_cycles=2, actions=[lambda: ws.baseline.write_bytes(old)])
    assert run.kinds() == ["baseline_integrity"]
    assert run.outcome.exit_code is ExitCode.INTEGRITY


def test_a_new_valid_baseline_mid_watch_is_adopted(ws: Workspace) -> None:
    make_baseline(ws)
    (ws.watched / "file0.txt").write_bytes(b"a change the owner accepts\n")

    def rebaseline() -> None:
        assert cli.main(baseline_args(ws, "--force")) == 0

    run = watch(ws, max_cycles=3, actions=[rebaseline])
    assert run.kinds() == ["modified", "resolved"]
    assert [event["fim"]["baseline_sequence"] for event in run.events] == [1, 2]
    assert not run.outcome.baseline_failed
    assert run.outcome.exit_code is ExitCode.FINDINGS  # the first cycle did report something


def test_a_baseline_that_never_verified_is_exit_3_before_any_cycle_or_output(
    ws: Workspace,
) -> None:
    make_baseline(ws)
    data = bytearray(ws.baseline.read_bytes())
    data[-20] ^= 0x01
    ws.baseline.write_bytes(bytes(data))
    log = ws.base / "events.jsonl"
    with pytest.raises(BaselineIntegrityError):
        watch(ws, output_path=str(log))
    assert not log.exists()


def test_a_missing_anchor_is_one_warning_not_one_per_cycle(ws: Workspace) -> None:
    make_baseline(ws)
    anchor_file(ws).unlink()
    run = watch(ws, max_cycles=3)
    assert len([note for note in run.notes if "no rollback anchor" in note]) == 1


# ---- incomplete scans ----------------------------------------------------------------------------


def test_an_incomplete_scan_reports_no_resolved_events_and_exits_4(
    ws: Workspace, tmp_path: Path
) -> None:
    write_config(ws.config, [ws.watched], limits={"max_files": 3})
    assert cli.main(["init-key", "--key-file", str(ws.key_file)]) == 0
    assert cli.main(baseline_args(ws, "--allow-incomplete")) == ExitCode.INCOMPLETE
    run = watch(ws, max_cycles=3)
    assert "resolved" not in run.kinds()
    assert run.outcome.incomplete
    assert run.outcome.exit_code is ExitCode.INCOMPLETE
    assert any("incomplete" in note or "stopped early" in note for note in run.notes)


# ---- stopping ------------------------------------------------------------------------------------


def test_ctrl_c_during_the_pause_stops_cleanly_with_the_state_so_far(ws: Workspace) -> None:
    make_baseline(ws)
    (ws.watched / "file0.txt").write_bytes(b"changed\n")

    def interrupt() -> None:
        raise KeyboardInterrupt

    run = watch(ws, max_cycles=5, actions=[interrupt])
    assert run.outcome.interrupted
    assert run.outcome.cycles == 1
    assert run.outcome.exit_code is ExitCode.FINDINGS
    assert run.kinds() == ["modified"]


def test_ctrl_c_in_the_middle_of_a_scan_stops_cleanly_and_closes_the_log(
    ws: Workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_baseline(ws)
    calls = {"n": 0}
    from fim.services.scanner import scan as real_scan

    def interrupting_scan(*args: Any, **kwargs: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 2:
            raise KeyboardInterrupt
        return real_scan(*args, **kwargs)

    monkeypatch.setattr("fim.app.watch.scan", interrupting_scan)
    log = ws.base / "events.jsonl"
    run = watch(ws, max_cycles=5, output_path=str(log))
    assert run.outcome.interrupted
    assert run.outcome.cycles == 1
    assert log.exists()
    log.unlink()  # on Windows this fails if the log was left open


# ---- output --------------------------------------------------------------------------------------


def test_events_go_to_an_append_log_not_to_stdout(ws: Workspace) -> None:
    make_baseline(ws)
    (ws.watched / "file0.txt").write_bytes(b"changed\n")
    log = ws.base / "events.jsonl"
    run = watch(
        ws, max_cycles=3, output_path=str(log), actions=[modify(ws, "new.txt", b"planted\n")]
    )
    assert run.out == []
    lines = log.read_text(encoding="ascii").splitlines()
    assert [json.loads(line)["fim"]["kind"] for line in lines] == ["modified", "created"]
    assert run.outcome.events == 2


def test_an_existing_log_is_not_replaced_without_force(ws: Workspace) -> None:
    make_baseline(ws)
    log = ws.base / "events.jsonl"
    log.write_bytes(b"old\n")
    with pytest.raises(FileAccessError, match="already exists; use --force"):
        watch(ws, output_path=str(log))
    assert log.read_bytes() == b"old\n"
    (ws.watched / "file0.txt").write_bytes(b"changed\n")
    watch(ws, output_path=str(log), force=True, max_cycles=1)
    assert not log.read_bytes().startswith(b"old")
    assert b'"kind":"modified"' in log.read_bytes()


def test_a_log_inside_a_monitored_path_is_refused(ws: Workspace) -> None:
    make_baseline(ws)
    with pytest.raises(Exception, match="must not be inside a monitored path"):
        watch(ws, output_path=str(ws.watched / "events.jsonl"))
    assert not (ws.watched / "events.jsonl").exists()


def test_csv_has_one_header_and_rows_for_the_events(ws: Workspace) -> None:
    make_baseline(ws)
    (ws.watched / "file0.txt").write_bytes(b"changed\n")
    run = watch(
        ws,
        max_cycles=3,
        output_format="csv",
        actions=[modify(ws, "new.txt", b"planted\n")],
    )
    rows = [line for text in run.out for line in text.splitlines()]
    assert rows[0].startswith('"timestamp","host","kind"')
    assert sum(1 for row in rows if row.startswith('"timestamp"')) == 1
    assert len(rows) == 3
    assert '"modified"' in rows[1]
    assert '"created"' in rows[2]


def test_a_hostile_file_name_is_one_escaped_line_per_event(ws: Workspace) -> None:
    make_baseline(ws)
    name = "evil\u202e\u200bname.txt" if os.name == "nt" else "evil\n\x1b[2Jname\u202e.txt"
    (ws.watched / name).write_bytes(b"x\n")
    run = watch(ws, max_cycles=1)
    assert len(run.lines) == 1
    text = "".join(run.out)
    assert text.isascii()
    assert "\x1b" not in text
    assert json.loads(run.lines[0])["fim"]["kind"] == "created"


def test_the_host_and_baseline_sequence_come_from_the_baseline(ws: Workspace) -> None:
    make_baseline(ws)
    (ws.watched / "file0.txt").write_bytes(b"changed\n")
    event = watch(ws, max_cycles=1).events[0]
    assert event["host"] == "lab-01"
    assert event["fim"]["baseline_sequence"] == 1
    assert event["fim"]["schema"] == "fim-event/1"


def test_the_watch_never_changes_a_monitored_file(ws: Workspace) -> None:
    from app_helpers import tree_state

    make_baseline(ws)
    (ws.watched / "file0.txt").write_bytes(b"changed\n")
    before = tree_state(ws.watched)
    watch(ws, max_cycles=3, repeat=True)
    assert tree_state(ws.watched) == before


def test_a_second_independent_copy_of_the_tree_gives_the_same_events(
    ws: Workspace, tmp_path: Path
) -> None:
    """Same state, same fake clock: the output is deterministic."""
    make_baseline(ws)
    (ws.watched / "file0.txt").write_bytes(b"changed\n")
    first = watch(ws, max_cycles=2).lines
    second = watch(ws, max_cycles=2).lines
    assert first == second


# ---- the less common branches --------------------------------------------------------------------


def test_a_complete_baseline_and_a_scan_that_hits_a_limit_is_exit_4_with_a_note(
    ws: Workspace,
) -> None:
    write_config(ws.config, [ws.watched], limits={"max_files": 8})
    make_baseline(ws)
    for index in range(6):
        (ws.watched / f"extra{index}.txt").write_bytes(b"x")
    run = watch(ws, max_cycles=2)
    assert run.outcome.incomplete
    assert run.outcome.exit_code is ExitCode.INCOMPLETE
    assert any("stopped early" in note for note in run.notes)
    assert not any("made from an incomplete scan" in note for note in run.notes)


def test_a_valid_older_baseline_without_an_anchor_is_still_a_rollback(ws: Workspace) -> None:
    make_baseline(ws)
    old = ws.baseline.read_bytes()
    assert cli.main(baseline_args(ws, "--force")) == 0  # sequence 2

    def put_back_the_old_one() -> None:
        ws.baseline.write_bytes(old)
        anchor_file(ws).unlink()  # no anchor to catch it: the sequence check must

    run = watch(ws, max_cycles=2, actions=[put_back_the_old_one])
    assert run.kinds() == ["baseline_integrity"]
    assert any("older than" in e["fim"]["evidence"] for e in run.events)
    assert run.outcome.exit_code is ExitCode.INTEGRITY


def test_more_findings_than_the_report_limit_is_said_once(ws: Workspace) -> None:
    write_config(ws.config, [ws.watched], limits={"max_findings_reported": 1})
    make_baseline(ws)
    for index in range(3):
        (ws.watched / f"new{index}.txt").write_bytes(b"x")
    run = watch(ws, max_cycles=3, repeat=True)
    assert len([note for note in run.notes if "can be listed" in note]) == 1
    assert run.outcome.findings_reported == 3  # one per cycle: the list is cut at the limit


def test_a_configuration_that_differs_from_the_baseline_is_a_policy_drift_event(
    ws: Workspace,
) -> None:
    make_baseline(ws)
    write_config(ws.config, [ws.watched], extra="exclude: ['*.log']", key_file=ws.key_file)
    run = watch(ws, max_cycles=2, config_path=str(ws.config))
    assert run.kinds() == ["policy_drift"]
    assert run.events[0]["fim"]["severity"] == "low"
    assert "path" not in run.events[0]["fim"]
    assert run.outcome.exit_code is ExitCode.FINDINGS
