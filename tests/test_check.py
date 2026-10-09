"""`fim check`: the full flow init-key -> baseline -> change files -> check, called in-process,
plus the integrity failures (exit 3), incomplete runs (exit 4), output files and hostile names."""

from __future__ import annotations

import io
import json
import os
import shutil
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

import winhelp
from app_helpers import Workspace, anchor_file, make_workspace, tree_state, write_config
from fakes import FakeClock, TickingClock
from fim.app import baseline as baseline_app
from fim.app import check as check_app
from fim.app.check import CheckRequest
from fim.cli import main as cli
from fim.core.errors import ExitCode, UsageError
from fim.core.models import Severity
from fim.services import keystore


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


def check_args(ws: Workspace, *extra: str) -> list[str]:
    return ["check", "--baseline", str(ws.baseline), "--key-file", str(ws.key_file), *extra]


def make_baseline(ws: Workspace) -> None:
    assert cli.main(["init-key", "--key-file", str(ws.key_file)]) == 0
    assert cli.main(baseline_args(ws)) == 0


def run_check(
    ws: Workspace, capsys: pytest.CaptureFixture[str], *extra: str
) -> tuple[int, str, str]:
    capsys.readouterr()
    code = cli.main(check_args(ws, *extra))
    out, err = capsys.readouterr()
    return code, out, err


def json_report(ws: Workspace, capsys: pytest.CaptureFixture[str], *extra: str) -> tuple[int, Any]:
    code, out, _ = run_check(ws, capsys, "--format", "json", *extra)
    return code, json.loads(out)


def pairs(report: Any) -> list[tuple[str, str]]:
    return sorted((item["kind"], item["path"]) for item in report["findings"])


def change_files(ws: Workspace) -> None:
    """One of each: modified, deleted, created, permission changed."""
    (ws.watched / "file0.txt").write_bytes(b"this content is different now\n")
    (ws.watched / "file1.txt").unlink()
    (ws.watched / "new.txt").write_bytes(b"planted\n")
    os.chmod(ws.watched / "file2.txt", stat.S_IREAD)


# ---- the full flow ------------------------------------------------------------------------------


def test_a_fresh_baseline_checks_clean(ws: Workspace, capsys: pytest.CaptureFixture[str]) -> None:
    make_baseline(ws)
    code, out, err = run_check(ws, capsys)
    assert code == 0
    assert err == ""
    assert "no changes found" in out
    assert "0 findings" in out
    assert "complete: yes" in out
    assert "baseline sequence 1" in out


def test_init_key_baseline_change_check_reports_each_change_and_exits_1(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    change_files(ws)
    code, report = json_report(ws, capsys)
    assert code == 1
    root = str(ws.watched)
    sep = os.sep
    assert pairs(report) == [
        ("created", root + sep + "new.txt"),
        ("deleted", root + sep + "file1.txt"),
        ("modified", root + sep + "file0.txt"),
        ("permission_changed", root + sep + "file2.txt"),
    ]
    by_kind = {item["kind"]: item for item in report["findings"]}
    assert by_kind["modified"]["severity"] == "high"  # the root's rule in the config
    assert by_kind["modified"]["confidence"] == "high"
    assert "sha256 differs" in by_kind["modified"]["evidence"]
    assert by_kind["deleted"]["confidence"] == "high"
    assert report["summary"]["findings"] == 4
    assert report["complete"] is True
    assert report["truncated"] is False
    assert report["baseline"]["sequence"] == 1
    assert report["summary"]["by_kind"] == {
        "created": 1,
        "modified": 1,
        "deleted": 1,
        "permission_changed": 1,
    }


def test_the_table_shows_the_same_findings(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    change_files(ws)
    code, out, _ = run_check(ws, capsys)
    assert code == 1
    assert "SEVERITY" in out
    for name in ("file0.txt", "file1.txt", "new.txt", "file2.txt"):
        assert name in out
    assert "4 findings" in out
    assert "by kind: created 1, modified 1, deleted 1, permission_changed 1" in out
    assert "file3.txt" not in out
    assert "nested.txt" not in out  # untouched files are not mentioned


def test_after_a_new_baseline_the_same_state_is_clean_again(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    change_files(ws)
    assert cli.main(baseline_args(ws, "--force")) == 0
    code, out, _ = run_check(ws, capsys)
    assert code == 0
    assert "baseline sequence 2" in out


def test_a_second_run_of_the_same_check_gives_the_same_finding_ids(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    change_files(ws)
    first = json_report(ws, capsys)[1]["findings"]
    second = json_report(ws, capsys)[1]["findings"]
    assert [x["finding_id"] for x in first] == [x["finding_id"] for x in second]


def test_check_never_changes_a_monitored_file_or_adds_one(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    change_files(ws)
    before = tree_state(ws.watched)
    listing = sorted(entry.name for entry in ws.watched.iterdir())
    run_check(ws, capsys)
    run_check(ws, capsys, "--format", "json")
    assert tree_state(ws.watched) == before
    assert sorted(entry.name for entry in ws.watched.iterdir()) == listing


def test_a_file_replaced_by_a_symlink_is_a_type_change(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    if not winhelp_symlinks():
        pytest.skip("requires_symlinks: this process cannot create symlinks")
    make_baseline(ws)
    target = ws.base / "elsewhere.txt"
    target.write_bytes(b"x")
    (ws.watched / "file0.txt").unlink()
    os.symlink(target, ws.watched / "file0.txt")
    code, report = json_report(ws, capsys)
    assert code == 1
    assert [x["kind"] for x in report["findings"]] == ["type_changed"]
    assert report["findings"][0]["severity"] == "critical"  # high rule, one step worse


def winhelp_symlinks() -> bool:
    from conftest import symlinks_supported

    return symlinks_supported()


def test_a_missing_monitored_path_is_one_critical_finding_not_a_flood_of_deletions(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    hidden = ws.base / "watched-moved"
    ws.watched.rename(hidden)
    code, report = json_report(ws, capsys)
    assert code == 1
    assert [x["kind"] for x in report["findings"]] == ["root_unavailable"]
    assert report["findings"][0]["severity"] == "critical"
    assert report["summary"]["suppressed"] == {
        "deleted files under an unavailable monitored path": 6
    }


def test_a_hard_link_count_change_is_low_severity(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    try:
        os.link(ws.watched / "file0.txt", ws.base / "alias.txt")
    except OSError:
        pytest.skip("this file system has no hard links")
    code, report = json_report(ws, capsys)
    assert code == 1
    assert [(x["kind"], x["severity"]) for x in report["findings"]] == [("links_changed", "low")]


# ---- policy: the baseline's, never the configuration's ------------------------------------------


def test_a_configuration_that_adds_an_exclude_does_not_hide_changes_and_reports_drift(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    write_config(ws.config, [ws.watched], extra="exclude:\n  - 'new*'")
    (ws.watched / "new.txt").write_bytes(b"planted\n")
    code, report = json_report(ws, capsys, "--config", str(ws.config))
    assert code == 1
    kinds = sorted(x["kind"] for x in report["findings"])
    assert kinds == ["created", "policy_drift"]  # the exclude in the file did not hide new.txt
    drift = next(x for x in report["findings"] if x["kind"] == "policy_drift")
    assert drift["severity"] == "low"
    assert "baseline's policy" in drift["evidence"]
    assert "fim baseline --force" in drift["evidence"]


def test_an_unchanged_configuration_gives_no_drift(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    code, report = json_report(ws, capsys, "--config", str(ws.config))
    assert code == 0
    assert report["findings"] == []


def test_the_key_can_come_from_the_configuration(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    write_config(ws.config, [ws.watched], key_file=ws.key_file)
    capsys.readouterr()
    code = cli.main(["check", "--baseline", str(ws.baseline), "--config", str(ws.config)])
    assert code == 0  # key_file is not part of the policy, so the digest is unchanged: no drift
    assert "policy_drift" not in capsys.readouterr().out


def test_no_key_anywhere_is_exit_2(ws: Workspace, capsys: pytest.CaptureFixture[str]) -> None:
    make_baseline(ws)
    capsys.readouterr()
    assert cli.main(["check", "--baseline", str(ws.baseline)]) == 2
    assert "no key file" in capsys.readouterr().err


# ---- exit 3: the baseline does not verify -------------------------------------------------------


def expect_integrity_failure(
    ws: Workspace, capsys: pytest.CaptureFixture[str], message: str
) -> None:
    code, out, err = run_check(ws, capsys)
    assert code == 3
    assert out == ""  # a failed check never prints a (misleading) report
    assert err.startswith("fim: error: ")
    assert message in err


def test_a_tampered_baseline_is_exit_3_through_the_cli(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    data = ws.baseline.read_bytes()
    ws.baseline.write_bytes(data.replace(b"lab-01", b"lab-02"))
    expect_integrity_failure(ws, capsys, "the MAC does not verify")


@pytest.mark.parametrize(
    ("name", "tamper", "message"),
    [
        ("truncated", lambda d: d[:-1], "MAC does not verify"),
        ("trailing", lambda d: d + b"\n", "MAC does not verify"),
        ("version", lambda d: d.replace(b'"version":1', b'"version":2'), "unsupported version"),
        ("format", lambda d: d.replace(b"fim-baseline", b"fim-basel1ne"), "unknown format"),
        ("envelope", lambda d: d[:30], "no envelope line"),
        ("empty", lambda _d: b"", "no envelope line"),
        ("garbage", lambda _d: b"x" * 5000, "no envelope line"),
    ],
)
def test_every_kind_of_damage_is_exit_3_with_a_clear_message(
    ws: Workspace, capsys: pytest.CaptureFixture[str], name: str, tamper: Any, message: str
) -> None:
    make_baseline(ws)
    ws.baseline.write_bytes(tamper(ws.baseline.read_bytes()))
    expect_integrity_failure(ws, capsys, message)


def test_a_different_key_is_exit_3_wrong_key(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    other = ws.keys / "other.key"
    assert cli.main(["init-key", "--key-file", str(other)]) == 0
    capsys.readouterr()
    code = cli.main(["check", "--baseline", str(ws.baseline), "--key-file", str(other)])
    assert code == 3
    assert "wrong key file" in capsys.readouterr().err


def test_a_changed_key_id_in_the_envelope_is_exit_3(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    key_id = keystore.load_key(str(ws.key_file)).key_id.encode()
    ws.baseline.write_bytes(ws.baseline.read_bytes().replace(key_id, b"0" * 16, 1))
    expect_integrity_failure(ws, capsys, "wrong key file")


def test_an_oversize_baseline_is_exit_3_and_never_parsed(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    write_config(ws.config, [ws.watched], limits={"max_baseline_bytes": 1000})
    # The size cap comes from --config when given: a baseline larger than it is refused unread.
    capsys.readouterr()
    code = cli.main(check_args(ws, "--config", str(ws.config)))
    assert code == 3
    assert "larger than the 1000 byte limit" in capsys.readouterr().err


def test_an_older_validly_signed_baseline_put_back_is_exit_3_a_rollback(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    old = ws.baseline.read_bytes()
    assert cli.main(baseline_args(ws, "--force")) == 0  # sequence 2, anchor updated
    ws.baseline.write_bytes(old)  # the attacker restores the genuine sequence-1 file
    code, out, err = run_check(ws, capsys)
    assert code == 3
    assert out == ""
    assert "does not match the rollback anchor" in err
    assert "sequence 1" in err
    assert "sequence 2" in err


def test_a_tampered_anchor_is_exit_3(ws: Workspace, capsys: pytest.CaptureFixture[str]) -> None:
    make_baseline(ws)
    anchor = anchor_file(ws)
    anchor.write_bytes(anchor.read_bytes().replace(b"sequence 1", b"sequence 5"))
    expect_integrity_failure(ws, capsys, "rollback anchor is not trustworthy")


def test_a_deleted_anchor_is_only_a_warning_and_the_check_runs(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    anchor_file(ws).unlink()
    code, out, _ = run_check(ws, capsys)
    assert code == 0
    assert "note: no rollback anchor found for this baseline" in out
    assert "no changes found" in out
    code, report = json_report(ws, capsys)
    assert code == 0
    assert any("no rollback anchor found" in note for note in report["notes"])


def test_a_missing_anchor_is_a_warning_on_stderr_when_the_report_goes_to_a_file(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    anchor_file(ws).unlink()
    capsys.readouterr()
    out_file = ws.base / "report.json"
    assert cli.main(check_args(ws, "--format", "json", "--output", str(out_file))) == 0
    out, err = capsys.readouterr()
    assert "report written:" in out
    assert "warning: no rollback anchor found" in err


def test_a_missing_baseline_is_exit_2_never_no_changes(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    ws.baseline.unlink()
    code, out, err = run_check(ws, capsys)
    assert code == 2
    assert out == ""
    assert "baseline file" in err
    assert "does not exist" in err


def test_a_baseline_that_is_a_symlink_is_refused(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    if not winhelp_symlinks():
        pytest.skip("requires_symlinks: this process cannot create symlinks")
    make_baseline(ws)
    link = ws.baseline.parent / "link.baseline"
    os.symlink(ws.baseline, link)
    capsys.readouterr()
    code = cli.main(["check", "--baseline", str(link), "--key-file", str(ws.key_file)])
    assert code == 2
    assert "symbolic link or reparse point" in capsys.readouterr().err


def test_a_key_inside_a_monitored_path_is_refused_once_the_baseline_is_verified(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    inside = ws.watched / "copy.key"
    shutil.copyfile(ws.key_file, inside)
    os.chmod(inside, stat.S_IREAD | stat.S_IWRITE)
    capsys.readouterr()
    code = cli.main(["check", "--baseline", str(ws.baseline), "--key-file", str(inside)])
    assert code == 2
    assert "must not be inside a monitored path" in capsys.readouterr().err


def test_the_key_never_appears_in_any_output(
    ws: Workspace, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    make_baseline(ws)
    secret = keystore.load_key(str(ws.key_file)).secret.hex()
    change_files(ws)
    seen = [run_check(ws, capsys)[1:], run_check(ws, capsys, "--format", "json")[1:]]
    ws.baseline.write_bytes(ws.baseline.read_bytes()[:-1])
    seen.append(run_check(ws, capsys)[1:])
    for out, err in seen:
        assert secret not in out + err
    assert secret not in caplog.text
    assert caplog.records == []


# ---- exit 4: incomplete -------------------------------------------------------------------------


def test_a_scan_that_hits_a_limit_is_exit_4_and_says_so(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    # The limit is part of the baseline's policy: make a baseline that already has it.
    write_config(ws.config, [ws.watched], limits={"max_files": 4})
    assert cli.main(baseline_args(ws, "--force", "--allow-incomplete")) == 4
    capsys.readouterr()
    code, report = json_report(ws, capsys)
    assert code == 4
    assert report["complete"] is False
    assert any("scan stopped early" in note for note in report["notes"])
    assert any("incomplete scan" in note for note in report["notes"])


def test_findings_and_incompleteness_together_exit_4_because_it_outranks_1(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    write_config(ws.config, [ws.watched], limits={"max_files": 4})
    assert cli.main(baseline_args(ws, "--force", "--allow-incomplete")) == 4
    (ws.watched / "file0.txt").write_bytes(b"changed")
    capsys.readouterr()
    code, report = json_report(ws, capsys)
    assert code == 4
    assert any(x["kind"] == "modified" for x in report["findings"]) or report["findings"] == []


def test_a_baseline_made_from_an_incomplete_scan_can_never_check_clean(ws: Workspace) -> None:
    config = ws.config
    write_config(config, [ws.watched], limits={"max_run_seconds": 1})
    keystore.init_key(str(ws.key_file), force=False)
    request = baseline_app.BaselineRequest(
        config_path=str(config),
        baseline_path=str(ws.baseline),
        key_file=str(ws.key_file),
        force=False,
        allow_incomplete=True,
    )
    made = baseline_app.run_baseline(request, TickingClock(step=10))
    assert made.complete is False
    outcome = check_app.run_check(
        CheckRequest(baseline_path=str(ws.baseline), key_file=str(ws.key_file), config_path=None),
        FakeClock(),
    )
    assert outcome.report.complete is False  # this scan was complete, the baseline was not
    assert outcome.exit_code == ExitCode.INCOMPLETE
    assert any("baseline was made from an incomplete scan" in note for note in outcome.notes)


# ---- output options -----------------------------------------------------------------------------


def test_min_severity_hides_lower_findings_and_the_exit_code_follows_what_is_shown(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    os.chmod(ws.watched / "file2.txt", stat.S_IREAD)  # permission change: the rule's own severity
    code, report = json_report(ws, capsys, "--min-severity", "critical")
    assert code == 0
    assert report["findings"] == []
    assert report["summary"]["suppressed"] == {"findings below the minimum severity": 1}
    code, report = json_report(ws, capsys, "--min-severity", "high")
    assert code == 1
    assert len(report["findings"]) == 1


def test_the_list_is_cut_at_the_baselines_limit_with_exact_counts(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    write_config(ws.config, [ws.watched], limits={"max_findings_reported": 2})
    make_baseline(ws)
    for index in range(5):
        (ws.watched / f"extra{index}.txt").write_bytes(b"x")
    code, report = json_report(ws, capsys)
    assert code == 1
    assert report["truncated"] is True
    assert len(report["findings"]) == 2
    assert report["summary"]["findings"] == 5
    assert report["summary"]["by_kind"] == {"created": 5}
    code, out, _ = run_check(ws, capsys)
    assert "showing the first 2 of 5 findings" in out


def test_output_writes_a_new_file_and_refuses_to_replace_one_without_force(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    change_files(ws)
    target = ws.base / "out" / "report.json"
    capsys.readouterr()
    assert cli.main(check_args(ws, "--format", "json", "--output", str(target))) == 1
    out, _ = capsys.readouterr()
    assert out.startswith("report written:")
    assert "(4 findings)" in out
    assert json.loads(target.read_text(encoding="utf-8"))["summary"]["findings"] == 4
    assert sorted(entry.name for entry in target.parent.iterdir()) == [
        "fim.baseline",
        "report.json",
    ]

    first = target.read_bytes()
    assert cli.main(check_args(ws, "--format", "json", "--output", str(target))) == 2
    assert "already exists; use --force" in capsys.readouterr().err
    assert target.read_bytes() == first
    assert cli.main(check_args(ws, "--output", str(target), "--force")) == 1
    assert target.read_text(encoding="utf-8").startswith("fim check:")  # replaced, now a table


def test_output_inside_a_monitored_path_is_refused_before_the_scan(
    ws: Workspace, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    make_baseline(ws)
    monkeypatch.setattr(
        check_app, "scan", lambda *_a, **_k: pytest.fail("scanned before the output check")
    )
    capsys.readouterr()
    code = cli.main(check_args(ws, "--output", str(ws.watched / "report.txt")))
    assert code == 2
    assert "must not be inside a monitored path" in capsys.readouterr().err
    assert not (ws.watched / "report.txt").exists()


def test_an_unknown_format_or_severity_is_a_usage_error(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(check_args(ws, "--format", "xml")) == 2
    assert "invalid choice" in capsys.readouterr().err
    assert cli.main(check_args(ws, "--min-severity", "urgent")) == 2
    assert cli.main(["check"]) == 2
    assert "--baseline" in capsys.readouterr().err


def test_check_has_no_abbreviated_options(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["check", "--base", str(ws.baseline), "--key", "x"]) == 2


def test_check_help_lists_the_options(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["check", "--help"]) == 0
    out = capsys.readouterr().out
    for option in ("--baseline", "--key-file", "--config", "--format", "--output", "--force"):
        assert option in out
    assert "--min-severity" in out


# ---- hostile names and consoles -----------------------------------------------------------------

HOSTILE = "evil\u202egnp.exe"  # a bidi control: allowed in file names on NTFS and ext4


def test_a_hostile_file_name_is_escaped_in_the_table_and_the_json(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    (ws.watched / HOSTILE).write_bytes(b"x")
    code, out, _ = run_check(ws, capsys)
    assert code == 1
    assert "\u202e" not in out
    assert "evil\\u202egnp.exe" in out
    code, out, _ = run_check(ws, capsys, "--format", "json")
    assert "\u202e" not in out
    out.encode("ascii")
    path = json.loads(out)["findings"][0]["path"]
    assert path.endswith("evil\\u202egnp.exe")


@pytest.mark.posix_only
def test_a_file_name_with_a_newline_and_an_escape_is_escaped(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    (ws.watched / "a\nb\x1b[31m").write_bytes(b"x")
    code, out, _ = run_check(ws, capsys)
    assert code == 1
    assert "\x1b" not in out
    assert "a\\x0ab\\x1b[31m" in out
    row = [line for line in out.splitlines() if "a\\x0ab" in line]
    assert len(row) == 1


@pytest.mark.posix_only
def test_an_undecodable_posix_file_name_is_reported_not_a_crash(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    raw = os.fsencode(str(ws.watched)) + b"/bad\xffname"
    with open(raw, "wb") as handle:
        handle.write(b"x")
    code, out, _ = run_check(ws, capsys)
    assert code == 1
    assert "bad\\yffname" in out or "\\y" in out


@pytest.mark.windows_only
def test_a_windows_path_never_shows_doubled_backslashes_in_the_table(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    """PLAN.md D10 amendment, through the real command on a real Windows path."""
    make_baseline(ws)
    (ws.watched / "sub" / "new.txt").write_bytes(b"x")
    code, out, _ = run_check(ws, capsys)
    assert code == 1
    assert str(ws.watched / "sub" / "new.txt") in out
    assert "\\\\" not in out


def test_a_console_that_cannot_encode_a_letter_does_not_crash_the_report(
    ws: Workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_baseline(ws)
    (ws.watched / "\u0416\u0443\u043a.txt").write_bytes(b"x")
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252", errors="strict")
    monkeypatch.setattr(sys, "stdout", stream)
    assert cli.main(check_args(ws)) == 1
    stream.flush()
    text = raw.getvalue().decode("cp1252")
    assert "\\u0416\\u0443\\u043a.txt" in text


@pytest.mark.windows_only
def test_a_junction_is_reported_without_being_entered(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    outside = ws.base / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_bytes(b"x")
    winhelp.make_junction(ws.watched / "junction", outside)
    code, report = json_report(ws, capsys)
    assert code == 1
    assert [x["kind"] for x in report["findings"]] == ["created"]
    assert report["findings"][0]["path"].endswith("junction")


# ---- exit code table ----------------------------------------------------------------------------


def test_exit_code_for_follows_the_precedence_table() -> None:
    import factories as make
    from fim.core.diff import DiffResult, build_report

    def report(findings: bool, complete: bool) -> Any:
        items = (make.finding(),) if findings else ()
        return build_report(
            DiffResult(items, 0, ()),
            header=make.header(),
            key_id="0123456789abcdef",
            generated_at=make.WHEN,
            tool_version="0.1.0",
            complete=complete,
            min_severity=Severity.INFO,
        )

    assert check_app.exit_code_for(report(False, True)) == ExitCode.OK
    assert check_app.exit_code_for(report(True, True)) == ExitCode.FINDINGS
    assert check_app.exit_code_for(report(False, False)) == ExitCode.INCOMPLETE
    assert check_app.exit_code_for(report(True, False)) == ExitCode.INCOMPLETE


def test_an_unknown_format_given_to_the_use_case_is_a_usage_error(ws: Workspace) -> None:
    make_baseline(ws)
    request = CheckRequest(
        baseline_path=str(ws.baseline),
        key_file=str(ws.key_file),
        config_path=None,
        output_format="xml",
    )
    with pytest.raises(UsageError, match="--format must be one of: table, json"):
        check_app.run_check(request, FakeClock())


def test_an_incomplete_check_written_to_a_file_warns_on_stderr(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    make_baseline(ws)
    write_config(ws.config, [ws.watched], limits={"max_files": 4})
    assert cli.main(baseline_args(ws, "--force", "--allow-incomplete")) == 4
    capsys.readouterr()
    out_file = ws.base / "report.txt"
    assert cli.main(check_args(ws, "--output", str(out_file))) == 4
    out, err = capsys.readouterr()
    assert out.startswith("report written:")
    assert "the check was incomplete" in err
    assert "complete: NO" in out_file.read_text(encoding="utf-8")
