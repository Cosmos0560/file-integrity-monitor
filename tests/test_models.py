"""core/models.py: vocabularies match PLAN.md, objects are immutable and refuse bad states."""

from __future__ import annotations

import dataclasses
import re
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

import factories as make
from fim.core import models
from fim.core.errors import ModelError
from fim.core.limits import DEFAULT_LIMITS, MAX_FINDINGS_REPORTED_CEILING
from fim.core.models import (
    Confidence,
    EntryType,
    FindingKind,
    HashStatus,
    IssueKind,
    ScanIssue,
    ScanStats,
    Severity,
    SymlinkPolicy,
)
from plan_doc import section


def values(enum_class: Any) -> list[str]:
    return [member.value for member in enum_class]


# ---- drift against PLAN.md section 2, D6 and D8 -------------------------------------------------


def _plan_row(label: str) -> str:
    for line in section("## 2. Data model").splitlines():
        if line.startswith(f"| `{label}` |"):
            return line
    raise LookupError(label)


def _ticks(text: str) -> list[str]:
    return re.findall(r"`([a-z_0-9]+)`", text)


def _row_cells(label: str) -> list[str]:
    return [cell.strip() for cell in _plan_row(label).strip().strip("|").split("|")]


@pytest.mark.parametrize(
    ("label", "enum_class"),
    [
        ("EntryType", EntryType),
        ("HashStatus", HashStatus),
        ("FindingKind", FindingKind),
    ],
)
def test_vocabularies_match_the_plan_table(label: str, enum_class: Any) -> None:
    assert _ticks(_row_cells(label)[1]) == values(enum_class)


def test_scan_issue_kinds_match_the_plan_table() -> None:
    group = re.search(r"`kind` \(([^)]*)\)", _row_cells("ScanIssue")[1])
    assert group is not None
    assert _ticks(group.group(1)) == values(IssueKind)


@pytest.mark.parametrize(
    ("label", "cls", "skip"),
    [
        ("FileRecord", models.FileRecord, set()),
        ("ScanIssue", models.ScanIssue, set()),
        ("ScanResult", models.ScanResult, set()),
        ("BaselineHeader", models.BaselineHeader, set()),
        ("Finding", models.Finding, {"field", "old", "new"}),  # these three belong to Change
    ],
)
def test_dataclass_fields_match_the_plan_table(label: str, cls: type, skip: set[str]) -> None:
    without_parentheses = re.sub(r"\([^)]*\)", "", _row_cells(label)[1])
    documented = [t for t in _ticks(without_parentheses) if t not in skip]
    assert documented == [f.name for f in dataclasses.fields(cls)]


def test_change_fields_match_the_plan() -> None:
    assert [f.name for f in dataclasses.fields(models.Change)] == ["field", "old", "new"]


def test_severity_and_confidence_orders_match_decision_d8() -> None:
    text = section("### D8")
    severity_line = re.search(r"\*\*Severity\*\* \(([^)]*)\)", text)
    assert severity_line is not None
    assert _ticks(severity_line.group(1)) == [s.label for s in Severity]
    confidence_line = re.search(r"\*\*Confidence\*\* \(([^)]*)\)", text)
    assert confidence_line is not None
    assert sorted(_ticks(confidence_line.group(1))) == sorted(c.label for c in Confidence)


def test_symlink_policies_match_decision_d6() -> None:
    text = section("### D6")
    assert re.search(r"Policy `never` \(default\)", text)
    assert re.search(r"Policy `files` \(opt-in\)", text)
    assert values(SymlinkPolicy) == ["never", "files"]


# ---- severity and confidence --------------------------------------------------------------------


def test_severity_is_ordered_and_has_labels() -> None:
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert [s.label for s in Severity] == ["info", "low", "medium", "high", "critical"]
    assert max(Severity.LOW, Severity.HIGH) is Severity.HIGH


@pytest.mark.parametrize("severity", list(Severity))
def test_severity_label_round_trip(severity: Severity) -> None:
    assert Severity.from_label(severity.label) is severity
    assert Severity.from_label(severity.label.upper()) is severity


def test_unknown_severity_label_is_refused_with_a_clean_message() -> None:
    with pytest.raises(ModelError) as raised:
        Severity.from_label("urgent\x1b[31m")
    assert "\x1b" not in str(raised.value)


def test_confidence_is_ordered() -> None:
    assert Confidence.LOW < Confidence.MEDIUM < Confidence.HIGH
    assert [c.label for c in Confidence] == ["low", "medium", "high"]


def test_string_enums_compare_and_serialise_as_their_values() -> None:
    assert str(EntryType.FILE) == "file"
    assert f"{FindingKind.POLICY_DRIFT}" == "policy_drift"
    assert HashStatus("skipped_too_large") is HashStatus.SKIPPED_TOO_LARGE


# ---- immutability -------------------------------------------------------------------------------

BUILDERS = [
    make.record,
    make.directory,
    make.root,
    make.policy,
    make.header,
    make.scan_result,
    make.finding,
    make.report,
]


@pytest.mark.parametrize("build", BUILDERS)
def test_models_are_frozen_and_slotted(build: Any) -> None:
    obj = build()
    first_field = dataclasses.fields(obj)[0].name
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(obj, first_field, None)
    assert not hasattr(obj, "__dict__")


@pytest.mark.parametrize("build", BUILDERS)
def test_equal_objects_compare_equal(build: Any) -> None:
    assert build() == build()


# ---- FileRecord invariants ----------------------------------------------------------------------


def test_a_valid_record_and_directory_build() -> None:
    assert make.record().type is EntryType.FILE
    assert make.directory().hash_status is HashStatus.NOT_APPLICABLE


@pytest.mark.parametrize(
    "overrides",
    [
        {"sha256": None},  # ok status needs a hash
        {"hash_status": HashStatus.SKIPPED_TOO_LARGE},  # a hash with a skipped status
        {"hash_status": HashStatus.UNSTABLE},  # a hash with an unstable status
        {"sha256": "AB" * 32},  # upper case
        {"sha256": "ab" * 31},  # too short
        {"sha256": "zz" * 32},  # not hex
        {"size": -1},
        {"root_index": -1},
        {"nlink": -1},
        {"uid": -1},
        {"mode": -1},
        {"mode": 0o200000},
        {"win_attrs": 0x20},  # both mode and win_attrs
        {"size": True},
        {"size": 1.5},
        {
            "hash_status": HashStatus.NOT_APPLICABLE,
            "sha256": None,
        },  # a file is always hashed or has a reason
        {"link_target": "x"},  # only symlinks have targets
        {"reparse_tag": 5},  # only reparse points and symlinks
        {"path": "a\nb"},  # raw newline
        {"path": "a" + chr(0x202E) + "b"},
        {
            "link_target": "\x1b",
            "type": EntryType.SYMLINK,
            "hash_status": HashStatus.NOT_APPLICABLE,
            "sha256": None,
        },
        {"error": "bad\x00"},
    ],
)
def test_record_invariants(overrides: dict[str, Any]) -> None:
    with pytest.raises(ModelError):
        make.record(**overrides)


@pytest.mark.parametrize(
    "entry_type",
    [
        EntryType.DIR,
        EntryType.REPARSE,
        EntryType.FIFO,
        EntryType.SOCKET,
        EntryType.DEVICE,
        EntryType.OTHER,
    ],
)
def test_non_files_are_never_hashed(entry_type: EntryType) -> None:
    ok = make.record(type=entry_type, sha256=None, hash_status=HashStatus.NOT_APPLICABLE)
    assert ok.sha256 is None
    with pytest.raises(ModelError, match="never hashed"):
        make.record(type=entry_type)  # still carries a hash and status ok


def test_a_symlink_may_carry_a_target_and_a_hash_of_what_it_points_to() -> None:
    link = make.record(
        type=EntryType.SYMLINK, link_target="../real.txt", reparse_tag=0xA000000C, win_attrs=None
    )
    assert link.link_target == "../real.txt"
    assert link.sha256 is not None


def test_record_with_every_legitimate_skip_status() -> None:
    for status in (
        HashStatus.SKIPPED_TOO_LARGE,
        HashStatus.SKIPPED_OFFLINE,
        HashStatus.UNREADABLE,
        HashStatus.VANISHED,
        HashStatus.UNSTABLE,
    ):
        assert make.record(sha256=None, hash_status=status, error="EACCES").hash_status is status


def test_windows_attributes_without_posix_mode() -> None:
    record = make.record(mode=None, uid=None, gid=None, win_attrs=0x01)
    assert (record.mode, record.win_attrs) == (None, 0x01)


def test_a_raw_backslash_in_an_escaped_path_is_fine_because_escape_doubles_it() -> None:
    assert make.record(path="dir/a\\\\b").path == "dir/a\\\\b"


def test_record_error_messages_never_echo_the_hostile_value() -> None:
    with pytest.raises(ModelError) as raised:
        make.record(path="evil\x1b[31m")
    assert "\x1b" not in str(raised.value)


# ---- scan issue, stats, result ------------------------------------------------------------------


def test_scan_issue_text_must_be_escaped() -> None:
    assert (
        ScanIssue(path="a", kind=IssueKind.UNREADABLE, detail="EACCES").kind is IssueKind.UNREADABLE
    )
    with pytest.raises(ModelError):
        ScanIssue(path="a\nb", kind=IssueKind.UNREADABLE, detail="x")
    with pytest.raises(ModelError):
        ScanIssue(path="a", kind=IssueKind.UNREADABLE, detail="x\x1b")


def test_scan_stats_are_non_negative() -> None:
    assert ScanStats().files == 0
    with pytest.raises(ModelError):
        ScanStats(files=-1)
    with pytest.raises(ModelError):
        ScanStats(bytes_hashed=-5)


def test_scan_result_dates_must_be_utc_and_ordered() -> None:
    naive = datetime(2026, 1, 1, 12, 0, 0)
    with pytest.raises(ModelError, match="UTC"):
        make.scan_result(started_at=naive)
    plus_two = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone(timedelta(hours=2)))
    with pytest.raises(ModelError, match="UTC"):
        make.scan_result(finished_at=plus_two)
    with pytest.raises(ModelError, match="before it started"):
        make.scan_result(finished_at=make.WHEN - timedelta(seconds=1))
    assert make.scan_result(finished_at=make.WHEN + timedelta(seconds=5)).complete


@pytest.mark.parametrize("kind", [IssueKind.LIMIT_REACHED, IssueKind.TIME_BUDGET])
def test_a_scan_that_hit_a_limit_cannot_claim_to_be_complete(kind: IssueKind) -> None:
    issue = ScanIssue(path="", kind=kind, detail="stopped")
    with pytest.raises(ModelError, match="cannot be marked complete"):
        make.scan_result(issues=(issue,), complete=True)
    assert make.scan_result(issues=(issue,), complete=False).complete is False


@pytest.mark.parametrize(
    "kind",
    [IssueKind.UNREADABLE, IssueKind.UNSTABLE, IssueKind.VANISHED, IssueKind.ROOT_UNAVAILABLE],
)
def test_other_issues_do_not_by_themselves_make_a_scan_incomplete(kind: IssueKind) -> None:
    issue = ScanIssue(path="x", kind=kind, detail="d")
    assert make.scan_result(issues=(issue,), complete=True).complete


# ---- policy and baseline ------------------------------------------------------------------------


def test_policy_needs_roots_a_valid_digest_and_a_sane_root_count() -> None:
    assert make.policy().symlinks is SymlinkPolicy.NEVER
    with pytest.raises(ModelError, match="at least one root"):
        make.policy(roots=())
    with pytest.raises(ModelError):
        make.policy(digest="not-hex")
    with pytest.raises(ModelError):
        make.policy(digest="AB" * 32)
    two = (make.root("/a"), make.root("/b"))
    with pytest.raises(ModelError, match="more roots"):
        make.policy(roots=two, limits=DEFAULT_LIMITS.with_overrides({"max_roots": 1}))


def test_a_root_must_be_absolute() -> None:
    with pytest.raises(ModelError, match="absolute"):
        make.root("relative/dir")
    assert make.root("/data").severity is Severity.MEDIUM
    assert make.root("/data").one_file_system is True


def test_header_checks() -> None:
    assert make.header().sequence == 1
    with pytest.raises(ModelError, match="starts at 1"):
        make.header(sequence=0)
    with pytest.raises(ModelError):
        make.header(sequence=-3)
    with pytest.raises(ModelError, match="UTC"):
        make.header(created_at=datetime(2026, 1, 1))
    with pytest.raises(ModelError):
        make.header(host="lab\n01")


def test_baseline_holds_header_and_records() -> None:
    baseline = models.Baseline(
        header=make.header(), records=(make.record(), make.directory(path="docs"))
    )
    assert len(baseline.records) == 2


# ---- findings and reports -----------------------------------------------------------------------


def test_finding_checks() -> None:
    assert make.finding().kind is FindingKind.MODIFIED
    with pytest.raises(ModelError):
        make.finding(finding_id="ABCDEF0123456789")
    with pytest.raises(ModelError):
        make.finding(finding_id="abc")
    with pytest.raises(ModelError):
        make.finding(evidence="line1\nline2")
    with pytest.raises(ModelError):
        make.finding(path="x" + chr(0x202E))
    with pytest.raises(ModelError, match="evidence limit"):
        make.finding(evidence="e" * 1025)
    assert len(make.finding(evidence="e" * 1024).evidence) == 1024


def test_change_text_must_be_escaped() -> None:
    assert models.Change(field="size", old="1", new=None).new is None
    with pytest.raises(ModelError):
        models.Change(field="size", old="a\nb", new="2")


def test_report_summary_checks() -> None:
    summary = models.ReportSummary(
        by_kind=((FindingKind.CREATED, 2),),
        by_severity=((Severity.HIGH, 2),),
        suppressed=(("deleted under unavailable root", 7),),
        mtime_only_changes=3,
    )
    assert summary.mtime_only_changes == 3
    with pytest.raises(ModelError):
        models.ReportSummary(mtime_only_changes=-1)
    with pytest.raises(ModelError):
        models.ReportSummary(by_kind=((FindingKind.CREATED, -1),))
    with pytest.raises(ModelError):
        models.ReportSummary(suppressed=(("bad\x1b", 1),))


def test_report_checks() -> None:
    assert make.report().baseline_sequence == 1
    with pytest.raises(ModelError):
        make.report(baseline_key_id="short")
    with pytest.raises(ModelError, match="UTC"):
        make.report(generated_at=datetime(2026, 1, 1))
    with pytest.raises(ModelError):
        make.report(baseline_sequence=-1)
    too_many = tuple(make.finding() for _ in range(MAX_FINDINGS_REPORTED_CEILING + 1))
    with pytest.raises(ModelError, match="reporting limit"):
        make.report(findings=too_many)
    assert len(make.report(findings=too_many[:-1]).findings) == MAX_FINDINGS_REPORTED_CEILING


def test_timezone_aware_non_utc_datetimes_are_refused_everywhere_utc_is_required() -> None:
    local = datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=1)))
    with pytest.raises(ModelError):
        make.report(baseline_created_at=local)
    assert make.report(baseline_created_at=datetime(2026, 1, 1, tzinfo=UTC)).complete


@pytest.mark.parametrize("bad", [5, b"bytes", ("a",), 1.5])
def test_text_fields_refuse_values_that_are_not_text(bad: Any) -> None:
    with pytest.raises(ModelError, match="must be text"):
        make.record(path=bad)
    with pytest.raises(ModelError, match="must be text"):
        make.finding(evidence=bad)
