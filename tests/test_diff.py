"""core/diff.py: every finding kind, the D8 severity and confidence rules, rename hints, unavailable
roots, finding ids and the report (truncation with exact counts)."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

import factories as make
from fim.core import diff as core_diff
from fim.core.diff import DiffResult, build_report, compare, policy_drift_finding
from fim.core.limits import MAX_EVIDENCE_CHARS_CEILING
from fim.core.models import (
    Baseline,
    Confidence,
    EntryType,
    FileRecord,
    Finding,
    FindingKind,
    HashStatus,
    IssueKind,
    RootPolicy,
    ScanIssue,
    ScanResult,
    Severity,
)
from fim.core.pathrules import Flavour, validate_user_path
from fim.core.perms import (
    FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_READONLY,
    FILE_ATTRIBUTE_SYSTEM,
    IO_REPARSE_TAG_MOUNT_POINT,
)

K = FindingKind
S = Severity
C = Confidence
SHA_1 = "11" * 32
SHA_2 = "22" * 32
SHA_3 = "33" * 32
NS = 1_700_000_000_000_000_000


def baseline_of(*records: FileRecord, severity: Severity = S.MEDIUM, roots: Any = None) -> Baseline:
    chosen = roots or (make.root("/data", severity=severity),)
    return Baseline(
        header=make.header(policy=make.policy(roots=tuple(chosen))), records=tuple(records)
    )


def scan_of(*records: FileRecord, issues: tuple[ScanIssue, ...] = (), complete: bool = True) -> Any:
    return make.scan_result(records=tuple(records), issues=issues, complete=complete)


def run(
    old: list[FileRecord],
    new: list[FileRecord],
    *,
    severity: Severity = S.MEDIUM,
    issues: tuple[ScanIssue, ...] = (),
    complete: bool = True,
    roots: Any = None,
) -> DiffResult:
    return compare(
        baseline_of(*old, severity=severity, roots=roots),
        scan_of(*new, issues=issues, complete=complete),
    )


def only(result: DiffResult, kind: FindingKind) -> Finding:
    found = [f for f in result.findings if f.kind is kind]
    assert len(found) == 1, [f.kind for f in result.findings]
    return found[0]


def kinds(result: DiffResult) -> list[FindingKind]:
    return sorted((f.kind for f in result.findings), key=lambda kind: kind.value)


def issue(kind: IssueKind, path: str, detail: str = "something happened") -> ScanIssue:
    return ScanIssue(path=path, kind=kind, detail=detail)


f = make.record
d = make.directory


# ---- created and deleted -------------------------------------------------------------------------


def test_nothing_changed_gives_no_findings() -> None:
    result = run([d(path=""), f()], [d(path=""), f()])
    assert result.findings == ()
    assert result.mtime_only_changes == 0
    assert result.suppressed == ()


def test_a_new_file_is_created_with_the_rules_severity_and_high_confidence() -> None:
    result = run([], [f(path="docs/new.txt", size=7, sha256=SHA_1)], severity=S.HIGH)
    finding = only(result, K.CREATED)
    assert finding.severity is S.HIGH
    assert finding.confidence is C.HIGH
    assert finding.path == "/data/docs/new.txt"
    assert finding.rule == "/data"
    assert "new file" in finding.evidence
    assert "7 bytes" in finding.evidence
    assert SHA_1[:16] in finding.evidence
    assert finding.changes[0].field == "type"


def test_a_new_directory_is_created_too() -> None:
    finding = only(run([], [d(path="newdir")]), K.CREATED)
    assert "new dir" in finding.evidence


def test_a_removed_file_is_deleted_with_high_confidence_in_a_complete_scan() -> None:
    result = run([f(path="gone.txt")], [], severity=S.CRITICAL)
    finding = only(result, K.DELETED)
    assert (finding.severity, finding.confidence) == (S.CRITICAL, C.HIGH)
    assert finding.path == "/data/gone.txt"
    assert "no longer present" in finding.evidence


def test_a_missing_file_in_an_incomplete_scan_has_low_confidence() -> None:
    finding = only(run([f(path="gone.txt")], [], complete=False), K.DELETED)
    assert finding.confidence is C.LOW
    assert "scan was incomplete" in finding.evidence


def test_a_missing_file_below_a_directory_that_could_not_be_read_has_low_confidence() -> None:
    problem = issue(IssueKind.UNREADABLE, "/data/locked", "directory cannot be read (EACCES)")
    result = run(
        [d(path="locked"), f(path="locked/inner/secret.txt"), f(path="other.txt")],
        [d(path="locked")],
        issues=(problem,),
    )
    deleted = {finding.path: finding for finding in result.findings if finding.kind is K.DELETED}
    assert set(deleted) == {"/data/locked/inner/secret.txt", "/data/other.txt"}
    assert deleted["/data/locked/inner/secret.txt"].confidence is C.LOW
    assert (
        "directory above it could not be read" in deleted["/data/locked/inner/secret.txt"].evidence
    )
    assert deleted["/data/other.txt"].confidence is C.HIGH


def test_a_file_that_vanished_during_the_scan_is_the_vanished_finding_not_deleted() -> None:
    problem = issue(IssueKind.VANISHED, "/data/a.txt", "disappeared during the scan (ENOENT)")
    result = run([f(path="a.txt")], [], issues=(problem,))
    assert kinds(result) == [K.VANISHED]


# ---- modified ------------------------------------------------------------------------------------


def test_a_different_hash_is_modified_with_high_confidence() -> None:
    new = f(sha256=SHA_2, size=5, mtime_ns=NS + 1)
    finding = only(run([f(sha256=SHA_1, size=3)], [new]), K.MODIFIED)
    assert (finding.severity, finding.confidence) == (S.MEDIUM, C.HIGH)
    fields = {change.field: (change.old, change.new) for change in finding.changes}
    assert fields["sha256"] == (SHA_1, SHA_2)
    assert fields["size"] == ("3", "5")
    assert "sha256 differs" in finding.evidence
    assert "size 3 -> 5" in finding.evidence


def test_the_same_hash_with_a_new_modification_time_is_counted_not_reported() -> None:
    result = run([f(mtime_ns=NS)], [f(mtime_ns=NS + 5)])
    assert result.findings == ()
    assert result.mtime_only_changes == 1


def test_mtime_only_changes_are_counted_per_file() -> None:
    old = [f(path=f"f{i}", mtime_ns=NS) for i in range(3)]
    new = [f(path=f"f{i}", mtime_ns=NS + i + 1) for i in range(3)]
    assert run(old, new).mtime_only_changes == 3


TOO_LARGE: dict[str, Any] = {"sha256": None, "hash_status": HashStatus.SKIPPED_TOO_LARGE}
OFFLINE: dict[str, Any] = {"sha256": None, "hash_status": HashStatus.SKIPPED_OFFLINE}


@pytest.mark.parametrize("status", [TOO_LARGE, OFFLINE])
def test_an_unhashed_file_is_compared_by_size_and_time_at_medium_confidence(
    status: dict[str, Any],
) -> None:
    old = f(size=10**10, mtime_ns=NS, **status)
    for changed in (
        f(size=10**10 + 1, mtime_ns=NS, **status),
        f(size=10**10, mtime_ns=NS + 1, **status),
    ):
        finding = only(run([old], [changed]), K.MODIFIED)
        assert finding.confidence is C.MEDIUM
        assert "not compared by hash" in finding.evidence
    assert run([old], [old]).findings == ()


def test_a_file_that_became_too_large_to_hash_is_compared_by_size_and_time() -> None:
    grown = f(size=10**10, mtime_ns=NS + 1, **TOO_LARGE)
    finding = only(run([f(size=3)], [grown]), K.MODIFIED)
    assert finding.confidence is C.MEDIUM


def test_a_file_that_could_not_be_hashed_before_is_compared_by_size_and_time() -> None:
    before = f(sha256=None, hash_status=HashStatus.UNREADABLE, error="EACCES", size=3)
    assert run([before], [f(size=3, mtime_ns=before.mtime_ns)]).findings == ()
    assert only(run([before], [f(size=4)]), K.MODIFIED).confidence is C.MEDIUM


@pytest.mark.parametrize(
    "status", [HashStatus.UNREADABLE, HashStatus.UNSTABLE, HashStatus.VANISHED]
)
def test_a_file_that_cannot_be_hashed_now_is_never_called_modified(status: HashStatus) -> None:
    broken = f(sha256=None, hash_status=status, size=99, error="EACCES")
    issue_kind = IssueKind(status.value)
    result = run([f()], [broken], issues=(issue(issue_kind, "/data/docs/a.txt"),))
    assert kinds(result) == [FindingKind(status.value)]


def test_a_permission_change_on_a_file_that_cannot_be_hashed_is_still_seen() -> None:
    broken = f(sha256=None, hash_status=HashStatus.UNREADABLE, mode=0o666, error="EACCES")
    result = run(
        [f(mode=0o644)], [broken], issues=(issue(IssueKind.UNREADABLE, "/data/docs/a.txt"),)
    )
    assert sorted(kinds(result), key=str) == sorted([K.PERMISSION_CHANGED, K.UNREADABLE], key=str)


# ---- symlinks, reparse points, directories, special files ---------------------------------------


def link(target: str, **extra: Any) -> FileRecord:
    fields: dict[str, Any] = {
        "path": "l",
        "type": EntryType.SYMLINK,
        "sha256": None,
        "hash_status": HashStatus.NOT_APPLICABLE,
        "link_target": target,
        "mode": 0o777,
    }
    fields.update(extra)
    return f(**fields)


def test_a_changed_link_target_is_modified_with_high_confidence() -> None:
    finding = only(run([link("a")], [link("b")]), K.MODIFIED)
    assert finding.confidence is C.HIGH
    assert finding.changes[0].field == "link_target"
    assert (finding.changes[0].old, finding.changes[0].new) == ("a", "b")
    assert "link target changed" in finding.evidence


def test_the_same_link_target_is_nothing_even_if_the_link_was_recreated() -> None:
    assert run([link("a", mtime_ns=NS)], [link("a", mtime_ns=NS + 9)]).findings == ()


def test_a_link_with_the_files_policy_reports_a_change_of_the_content_behind_it() -> None:
    old = link("a", sha256=SHA_1, hash_status=HashStatus.OK)
    new = link("a", sha256=SHA_2, hash_status=HashStatus.OK)
    finding = only(run([old], [new]), K.MODIFIED)
    assert "content behind the link changed" in finding.evidence


def test_link_targets_are_shown_without_the_windows_extended_prefix_but_still_compared_exact() -> (
    None
):
    root = RootPolicy(path=validate_user_path("C:\\data", Flavour.WINDOWS), severity=S.MEDIUM)
    old = link("\\\\?\\C:\\target.txt")
    new = link("C:\\target.txt")
    result = run([old], [new], roots=(root,))
    finding = only(result, K.MODIFIED)  # the stored text differs, so it is a change (D6 note)
    assert finding.changes[0].old == "C:\\target.txt"
    assert finding.changes[0].new == "C:\\target.txt"
    assert finding.path == "C:\\data\\l"


def test_a_changed_reparse_tag_is_modified() -> None:
    old = f(
        type=EntryType.REPARSE,
        sha256=None,
        hash_status=HashStatus.NOT_APPLICABLE,
        mode=None,
        win_attrs=0,
        reparse_tag=IO_REPARSE_TAG_MOUNT_POINT,
    )
    new = replace(old, reparse_tag=0xA000000C)
    assert only(run([old], [new]), K.MODIFIED).changes[0].field == "reparse_tag"
    assert run([old], [old]).findings == ()


def test_a_directory_is_compared_by_permissions_not_by_size_or_time() -> None:
    old = d(path="sub", mtime_ns=NS)
    assert run([old], [d(path="sub", mtime_ns=NS + 99)]).findings == ()
    assert kinds(run([old], [d(path="sub", mode=0o777)])) == [K.PERMISSION_CHANGED]


@pytest.mark.parametrize(
    "kind", [EntryType.FIFO, EntryType.SOCKET, EntryType.DEVICE, EntryType.OTHER]
)
def test_special_files_are_compared_by_type_and_permissions_only(kind: EntryType) -> None:
    fields: dict[str, Any] = {
        "path": "s",
        "type": kind,
        "sha256": None,
        "hash_status": HashStatus.NOT_APPLICABLE,
    }
    old = f(mtime_ns=NS, size=0, **fields)
    assert run([old], [replace(old, mtime_ns=NS + 5, size=9)]).findings == ()
    assert kinds(run([old], [replace(old, mode=0o600)])) == [K.PERMISSION_CHANGED]


# ---- type changes --------------------------------------------------------------------------------


def test_a_file_replaced_by_a_symlink_is_a_type_change_one_step_worse_and_nothing_else() -> None:
    new = link("/etc/shadow", path="docs/a.txt", mode=0o777, uid=0)
    result = run([f(sha256=SHA_1, mode=0o644)], [new], severity=S.MEDIUM)
    finding = only(result, K.TYPE_CHANGED)
    assert result.findings == (finding,)  # no modified, no permission_changed
    assert (finding.severity, finding.confidence) == (S.HIGH, C.HIGH)
    assert finding.changes[0] == make_change("type", "file", "symlink")
    assert "type changed from file to symlink" in finding.evidence


def make_change(field: str, old: str | None, new: str | None) -> Any:
    from fim.core.models import Change

    return Change(field=field, old=old, new=new)


@pytest.mark.parametrize(
    ("base", "expected"),
    [
        (S.INFO, S.LOW),
        (S.LOW, S.MEDIUM),
        (S.MEDIUM, S.HIGH),
        (S.HIGH, S.CRITICAL),
        (S.CRITICAL, S.CRITICAL),
    ],
)
def test_a_type_change_is_one_step_worse_and_capped_at_critical(
    base: Severity, expected: Severity
) -> None:
    result = run([f()], [d(path="docs/a.txt")], severity=base)
    assert only(result, K.TYPE_CHANGED).severity is expected


def test_a_directory_replaced_by_a_file_is_a_type_change() -> None:
    assert kinds(run([d(path="x")], [f(path="x")])) == [K.TYPE_CHANGED]


# ---- permissions ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("old_mode", "new_mode", "escalates"),
    [
        (0o644, 0o600, False),
        (0o755, 0o644, False),
        (0o644, 0o664, False),  # group write is not world write
        (0o644, 0o666, True),  # world-write added
        (0o644, 0o646, True),
        (0o644, 0o4755, True),  # setuid added
        (0o755, 0o2755, True),  # setgid added
        (0o755, 0o1755, False),  # sticky alone is not escalation
        (0o666, 0o666 | 0o4000, True),
        (0o4755, 0o755, False),  # setuid removed
        (0o666, 0o644, False),  # world-write removed
        (0o666, 0o667, False),  # world-write was already there
    ],
)
def test_posix_permission_changes_escalate_only_when_they_add_danger(
    old_mode: int, new_mode: int, escalates: bool
) -> None:
    result = run([f(mode=old_mode)], [f(mode=new_mode)], severity=S.MEDIUM)
    finding = only(result, K.PERMISSION_CHANGED)
    assert finding.severity is (S.HIGH if escalates else S.MEDIUM)
    assert finding.confidence is C.HIGH
    assert ("more dangerous than before" in finding.evidence) is escalates
    assert finding.changes[0].field == "mode"


def test_a_permission_escalation_is_capped_at_critical() -> None:
    result = run([f(mode=0o644)], [f(mode=0o666)], severity=S.CRITICAL)
    assert only(result, K.PERMISSION_CHANGED).severity is S.CRITICAL


def test_the_mode_is_shown_in_octal() -> None:
    finding = only(run([f(mode=0o644)], [f(mode=0o4755)]), K.PERMISSION_CHANGED)
    assert (finding.changes[0].old, finding.changes[0].new) == ("0644", "4755")


def test_owner_and_group_changes_are_permission_changes() -> None:
    result = run([f(uid=1000, gid=1000)], [f(uid=0, gid=1000)])
    finding = only(result, K.PERMISSION_CHANGED)
    assert [(c.field, c.old, c.new) for c in finding.changes] == [("uid", "1000", "0")]
    finding = only(run([f(uid=1000, gid=1000)], [f(uid=1000, gid=5)]), K.PERMISSION_CHANGED)
    assert [c.field for c in finding.changes] == ["gid"]


RO, HID, SYS = FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM


def win(attrs: int, **extra: Any) -> FileRecord:
    return f(mode=None, uid=None, gid=None, win_attrs=attrs, **extra)


@pytest.mark.parametrize(
    ("old_attrs", "new_attrs", "escalates"),
    [
        (RO | SYS, SYS, True),  # READONLY cleared on a SYSTEM file
        (RO | SYS | HID, SYS | HID, True),
        (RO, 0, False),  # READONLY cleared, but not a SYSTEM file
        (0, RO, False),  # READONLY set
        (SYS, SYS | HID, False),
        (HID, 0, False),
        (RO | SYS, RO, False),  # SYSTEM cleared: not the dangerous case
    ],
)
def test_windows_attribute_changes_escalate_only_for_a_system_file_losing_readonly(
    old_attrs: int, new_attrs: int, escalates: bool
) -> None:
    finding = only(run([win(old_attrs)], [win(new_attrs)]), K.PERMISSION_CHANGED)
    assert finding.severity is (S.HIGH if escalates else S.MEDIUM)
    assert finding.changes[0].field == "win_attrs"


def test_windows_attributes_are_shown_by_name() -> None:
    finding = only(run([win(RO | SYS)], [win(HID)]), K.PERMISSION_CHANGED)
    assert (finding.changes[0].old, finding.changes[0].new) == ("READONLY|SYSTEM", "HIDDEN")
    finding = only(run([win(HID)], [win(0)]), K.PERMISSION_CHANGED)
    assert finding.changes[0].new == "none"


def test_a_baseline_from_another_os_family_shows_the_missing_side_as_none() -> None:
    finding = only(run([f(mode=0o644)], [win(0)]), K.PERMISSION_CHANGED)
    fields = {c.field: (c.old, c.new) for c in finding.changes}
    assert fields["mode"] == ("0644", None)
    assert fields["win_attrs"] == (None, "none")
    assert finding.severity is S.MEDIUM  # nothing to compare, so no escalation


def test_modified_and_permission_changed_can_come_from_one_path() -> None:
    result = run([f(sha256=SHA_1, mode=0o644)], [f(sha256=SHA_2, mode=0o666)])
    assert kinds(result) == [K.MODIFIED, K.PERMISSION_CHANGED]
    assert len({finding.finding_id for finding in result.findings}) == 2
    assert {finding.path for finding in result.findings} == {"/data/docs/a.txt"}


# ---- hard links ----------------------------------------------------------------------------------


def test_a_new_hard_link_is_low_severity_at_medium_confidence_whatever_the_rule() -> None:
    finding = only(run([f(nlink=1)], [f(nlink=2)], severity=S.CRITICAL), K.LINKS_CHANGED)
    assert (finding.severity, finding.confidence) == (S.LOW, C.MEDIUM)
    assert finding.changes[0].field == "nlink"
    assert "hard link count 1 -> 2" in finding.evidence


def test_only_regular_files_report_link_count_changes() -> None:
    assert run([d(path="x", nlink=1)], [d(path="x", nlink=5)]).findings == ()


# ---- unavailable roots, scan problems ------------------------------------------------------------


def two_roots() -> tuple[RootPolicy, RootPolicy]:
    return make.root("/data", severity=S.HIGH), make.root("/etc", severity=S.CRITICAL)


def test_an_unavailable_root_is_one_critical_finding_and_its_files_are_not_called_deleted() -> None:
    old = [f(path="a", root_index=0), f(path="b", root_index=0), f(path="c", root_index=1)]
    problem = issue(IssueKind.ROOT_UNAVAILABLE, "/data", "the monitored path not found")
    result = run(old, [f(path="c", root_index=1)], issues=(problem,), roots=two_roots())
    finding = only(result, K.ROOT_UNAVAILABLE)
    assert (finding.severity, finding.confidence) == (S.CRITICAL, C.HIGH)
    assert finding.path == "/data"
    assert finding.rule == "/data"
    assert "not found" in finding.evidence
    assert kinds(result) == [K.ROOT_UNAVAILABLE]
    assert result.suppressed == (("deleted files under an unavailable monitored path", 2),)


def test_deleted_files_under_a_root_that_is_still_available_are_still_reported() -> None:
    problem = issue(IssueKind.ROOT_UNAVAILABLE, "/data", "the monitored path not found")
    old = [f(path="a", root_index=0), f(path="c", root_index=1)]
    result = run(old, [], issues=(problem,), roots=two_roots())
    assert kinds(result) == [K.DELETED, K.ROOT_UNAVAILABLE]
    assert only(result, K.DELETED).path == "/etc/c"
    assert only(result, K.DELETED).severity is S.CRITICAL  # the /etc rule


def test_each_root_applies_its_own_severity() -> None:
    result = run([], [f(path="a", root_index=0), f(path="b", root_index=1)], roots=two_roots())
    by_path = {finding.path: finding.severity for finding in result.findings}
    assert by_path == {"/data/a": S.HIGH, "/etc/b": S.CRITICAL}


@pytest.mark.parametrize(
    ("issue_kind", "finding_kind"),
    [
        (IssueKind.UNREADABLE, K.UNREADABLE),
        (IssueKind.UNSTABLE, K.UNSTABLE),
        (IssueKind.VANISHED, K.VANISHED),
    ],
)
def test_scan_problems_are_low_severity_low_confidence_findings(
    issue_kind: IssueKind, finding_kind: FindingKind
) -> None:
    problem = issue(issue_kind, "/data/docs/x.txt", "it was busy (EBUSY)")
    finding = only(run([], [], issues=(problem,), severity=S.CRITICAL), finding_kind)
    assert (finding.severity, finding.confidence) == (S.LOW, C.LOW)
    assert finding.path == "/data/docs/x.txt"
    assert finding.evidence == "it was busy (EBUSY)"
    assert finding.rule == "/data"


def test_a_problem_outside_every_root_name_has_no_rule() -> None:
    finding = only(run([], [], issues=(issue(IssueKind.UNREADABLE, "/elsewhere/x"),)), K.UNREADABLE)
    assert finding.rule == ""


def test_limit_issues_are_not_findings_they_make_the_run_incomplete() -> None:
    limits = (
        issue(IssueKind.LIMIT_REACHED, "", "more than max_files entries"),
        issue(IssueKind.TIME_BUDGET, "", "stopped after the time budget"),
    )
    assert run([], [], issues=limits, complete=False).findings == ()


# ---- rename hints --------------------------------------------------------------------------------


def test_a_deleted_and_a_created_file_with_the_same_hash_get_possible_rename_evidence() -> None:
    result = run([f(path="old.txt", sha256=SHA_1)], [f(path="new.txt", sha256=SHA_1)])
    deleted, created = only(result, K.DELETED), only(result, K.CREATED)
    assert "same content as /data/new.txt (possible rename)" in deleted.evidence
    assert "same content as /data/old.txt (possible rename)" in created.evidence
    assert deleted.confidence is C.LOW
    assert created.confidence is C.LOW


def test_the_rename_hint_does_not_change_the_finding_id() -> None:
    renamed = run([f(path="old.txt", sha256=SHA_1)], [f(path="new.txt", sha256=SHA_1)])
    plain = run([f(path="old.txt", sha256=SHA_1)], [f(path="new.txt", sha256=SHA_2)])
    assert only(renamed, K.DELETED).finding_id == only(plain, K.DELETED).finding_id


def test_different_content_gets_no_rename_hint() -> None:
    result = run([f(path="old.txt", sha256=SHA_1)], [f(path="new.txt", sha256=SHA_2)])
    for finding in result.findings:
        assert "possible rename" not in finding.evidence
        assert finding.confidence is C.HIGH


def test_several_candidates_are_named_once_and_counted() -> None:
    new = [f(path=f"copy{i}.txt", sha256=SHA_1) for i in range(3)]
    result = run([f(path="orig.txt", sha256=SHA_1)], new)
    deleted = only(result, K.DELETED)
    assert "same content as /data/copy0.txt and 2 more (possible rename)" in deleted.evidence


def test_directories_and_unhashed_files_get_no_rename_hint() -> None:
    result = run([d(path="a")], [d(path="b")])
    assert all("possible rename" not in finding.evidence for finding in result.findings)
    big = {"sha256": None, "hash_status": HashStatus.SKIPPED_TOO_LARGE}
    result = run([f(path="a", **big)], [f(path="b", **big)])
    assert all("possible rename" not in finding.evidence for finding in result.findings)


def test_rename_hints_work_across_roots() -> None:
    result = run(
        [f(path="a", root_index=0, sha256=SHA_1)],
        [f(path="b", root_index=1, sha256=SHA_1)],
        roots=two_roots(),
    )
    assert "same content as /etc/b" in only(result, K.DELETED).evidence


# ---- finding ids ---------------------------------------------------------------------------------


def test_finding_ids_are_16_hex_characters_and_repeatable() -> None:
    first = run([f(sha256=SHA_1)], [f(sha256=SHA_2)])
    second = run([f(sha256=SHA_1)], [f(sha256=SHA_2)])
    assert [x.finding_id for x in first.findings] == [x.finding_id for x in second.findings]
    assert all(len(x.finding_id) == 16 for x in first.findings)


def test_a_finding_id_depends_on_the_path_the_kind_and_the_old_and_new_facts() -> None:
    base = only(run([f(sha256=SHA_1)], [f(sha256=SHA_2)]), K.MODIFIED).finding_id
    other_new = only(run([f(sha256=SHA_1)], [f(sha256=SHA_3)]), K.MODIFIED).finding_id
    other_old = only(run([f(sha256=SHA_3)], [f(sha256=SHA_2)]), K.MODIFIED).finding_id
    other_path = only(
        run([f(path="b", sha256=SHA_1)], [f(path="b", sha256=SHA_2)]), K.MODIFIED
    ).finding_id
    assert len({base, other_new, other_old, other_path}) == 4


def test_a_finding_id_ignores_what_did_not_change_the_finding() -> None:
    """Watch reports a finding once: an unrelated mtime change on a hashed file keeps its id."""
    a = only(run([f(sha256=SHA_1)], [f(sha256=SHA_2, mtime_ns=NS + 1)]), K.MODIFIED).finding_id
    b = only(run([f(sha256=SHA_1)], [f(sha256=SHA_2, mtime_ns=NS + 2)]), K.MODIFIED).finding_id
    assert a == b


def test_ids_use_the_exact_path_not_its_escaped_form() -> None:
    odd = "d\udc80ir/\u202e.txt"
    result = run([], [f(path=odd)])
    other = run([], [f(path="d\udc81ir/\u202e.txt")])
    assert only(result, K.CREATED).finding_id != only(other, K.CREATED).finding_id


# ---- hostile names and display -------------------------------------------------------------------


def test_hostile_names_are_escaped_in_every_text_field() -> None:
    hostile = "dir\x1b[31m/na\nme\u202e.txt"
    result = run([f(path=hostile, sha256=SHA_1)], [f(path=hostile, sha256=SHA_2)])
    finding = only(result, K.MODIFIED)
    for text in (finding.path, finding.evidence, finding.rule):
        assert "\x1b" not in text
        assert "\n" not in text
        assert "\u202e" not in text
    assert "\\x1b" in finding.path
    assert "\\u202e" in finding.path


def test_an_undecodable_posix_name_is_a_finding_not_a_crash() -> None:
    finding = only(run([], [f(path="bad\udc80name")]), K.CREATED)
    assert "\\ydc80" in finding.path or "\\y80" in finding.path


def test_a_windows_path_has_single_backslashes_in_the_finding() -> None:
    root = RootPolicy(path=validate_user_path("C:\\Users\\lab", Flavour.WINDOWS))
    finding = only(run([], [f(path="docs/a.txt")], roots=(root,)), K.CREATED)
    assert finding.path == "C:\\Users\\lab\\docs\\a.txt"
    assert "\\\\" not in finding.path
    assert finding.rule == "C:\\Users\\lab"


def test_a_very_long_path_cannot_push_the_evidence_over_its_limit() -> None:
    long_name = "x" * 3000
    result = run([f(path=long_name, sha256=SHA_1)], [f(path=long_name + "y", sha256=SHA_1)])
    for finding in result.findings:
        assert len(finding.evidence) <= MAX_EVIDENCE_CHARS_CEILING
        assert finding.evidence.endswith("...")


def test_clipping_never_splits_an_escape_sequence() -> None:
    text = "ab" + "\\u202e" * 10
    for limit in range(5, len(text)):
        clipped = core_diff._clip(text, limit)
        assert len(clipped) <= limit
        body = clipped[: -len("...")] if clipped.endswith("...") else clipped
        assert not body.endswith(("\\", "\\u", "\\u2", "\\u20", "\\u202"))
    assert core_diff._clip("short", 100) == "short"


# ---- policy drift --------------------------------------------------------------------------------


def test_policy_drift_is_a_low_severity_notice_that_recommends_a_new_baseline() -> None:
    finding = policy_drift_finding("a" * 64, "b" * 64)
    assert finding.kind is K.POLICY_DRIFT
    assert (finding.severity, finding.confidence) == (S.LOW, C.HIGH)
    assert finding.changes[0].old == "a" * 16
    assert finding.changes[0].new == "b" * 16
    assert "fim baseline --force" in finding.evidence
    assert "baseline's policy" in finding.evidence
    assert policy_drift_finding("a" * 64, "b" * 64).finding_id == finding.finding_id
    assert policy_drift_finding("a" * 64, "c" * 64).finding_id != finding.finding_id


# ---- the report ----------------------------------------------------------------------------------

HEADER = make.header()


def report_of(findings: list[Finding], **overrides: Any) -> Any:
    fields: dict[str, Any] = {
        "header": HEADER,
        "key_id": "0123456789abcdef",
        "generated_at": make.WHEN,
        "tool_version": "0.1.0",
        "complete": True,
    }
    fields.update(overrides)
    extra = fields.pop("extra", ())
    return build_report(DiffResult(tuple(findings), 0, ()), extra=extra, **fields)


def fnd(
    path: str, kind: FindingKind = K.MODIFIED, severity: Severity = S.MEDIUM, n: int = 0
) -> Finding:
    return make.finding(path=path, kind=kind, severity=severity, finding_id=f"{n:016x}")


def test_findings_are_sorted_most_severe_first_then_by_path() -> None:
    items = [
        fnd("/b", severity=S.LOW, n=1),
        fnd("/a", severity=S.CRITICAL, n=2),
        fnd("/c", severity=S.MEDIUM, n=3),
        fnd("/a", severity=S.MEDIUM, n=4),
    ]
    report = report_of(items)
    assert [(x.path, x.severity) for x in report.findings] == [
        ("/a", S.CRITICAL),
        ("/a", S.MEDIUM),
        ("/c", S.MEDIUM),
        ("/b", S.LOW),
    ]


def test_the_report_is_the_same_whatever_order_the_findings_arrive_in() -> None:
    items = [fnd(f"/p{i}", severity=Severity(i % 5), n=i) for i in range(20)]
    assert report_of(items).findings == report_of(list(reversed(items))).findings


def test_the_summary_counts_by_kind_and_severity() -> None:
    items = [
        fnd("/a", K.MODIFIED, S.HIGH, 1),
        fnd("/b", K.MODIFIED, S.LOW, 2),
        fnd("/c", K.CREATED, S.HIGH, 3),
        fnd("/d", K.DELETED, S.CRITICAL, 4),
    ]
    summary = report_of(items).summary
    assert summary.by_kind == ((K.CREATED, 1), (K.MODIFIED, 2), (K.DELETED, 1))
    assert summary.by_severity == ((S.CRITICAL, 1), (S.HIGH, 2), (S.LOW, 1))


def test_min_severity_hides_lower_findings_and_counts_them_as_suppressed() -> None:
    items = [
        fnd("/a", severity=S.HIGH, n=1),
        fnd("/b", severity=S.LOW, n=2),
        fnd("/c", severity=S.INFO, n=3),
    ]
    report = report_of(items, min_severity=S.MEDIUM)
    assert [x.path for x in report.findings] == ["/a"]
    assert report.summary.by_severity == ((S.HIGH, 1),)
    assert ("findings below the minimum severity", 2) in report.summary.suppressed


def test_a_minimum_of_info_hides_nothing() -> None:
    report = report_of([fnd("/a", severity=S.INFO, n=1)])
    assert len(report.findings) == 1
    assert report.summary.suppressed == ()


def test_the_list_is_cut_at_the_maximum_but_the_counts_stay_exact() -> None:
    items = [fnd(f"/p{i:03d}", K.CREATED if i % 2 else K.MODIFIED, S.MEDIUM, i) for i in range(25)]
    report = report_of(items, max_findings=10)
    assert len(report.findings) == 10
    assert report.truncated is True
    assert sum(count for _, count in report.summary.by_kind) == 25
    assert sum(count for _, count in report.summary.by_severity) == 25


def test_the_cut_keeps_the_most_severe_findings() -> None:
    items = [fnd(f"/low{i}", severity=S.LOW, n=i) for i in range(5)]
    items.append(fnd("/crit", severity=S.CRITICAL, n=99))
    report = report_of(items, max_findings=2)
    assert report.findings[0].path == "/crit"


def test_exactly_the_maximum_is_not_truncated() -> None:
    report = report_of([fnd(f"/p{i}", n=i) for i in range(4)], max_findings=4)
    assert report.truncated is False


def test_the_default_maximum_is_the_documented_reporting_limit() -> None:
    from fim.core.limits import MAX_FINDINGS_REPORTED

    items = [fnd(f"/p{i:05d}", n=i) for i in range(MAX_FINDINGS_REPORTED + 5)]
    report = report_of(items)
    assert len(report.findings) == MAX_FINDINGS_REPORTED
    assert report.truncated is True
    assert sum(count for _, count in report.summary.by_kind) == MAX_FINDINGS_REPORTED + 5


def test_extra_findings_such_as_policy_drift_join_the_report() -> None:
    report = report_of([fnd("/a", n=1)], extra=[policy_drift_finding("a" * 64, "b" * 64)])
    assert {x.kind for x in report.findings} == {K.MODIFIED, K.POLICY_DRIFT}


def test_the_report_carries_the_baseline_facts_and_completeness() -> None:
    report = report_of([], complete=False)
    assert report.complete is False
    assert report.baseline_sequence == HEADER.sequence
    assert report.baseline_created_at == HEADER.created_at
    assert report.baseline_key_id == "0123456789abcdef"
    assert report.generated_at == make.WHEN
    assert report.findings == ()
    assert report.truncated is False


def test_mtime_only_changes_and_suppressed_counts_reach_the_summary() -> None:
    diff = DiffResult((), 4, (("deleted files under an unavailable monitored path", 3),))
    report = build_report(
        diff,
        header=HEADER,
        key_id="0123456789abcdef",
        generated_at=make.WHEN,
        tool_version="0.1.0",
        complete=True,
    )
    assert report.summary.mtime_only_changes == 4
    assert report.summary.suppressed == (("deleted files under an unavailable monitored path", 3),)


# ---- the whole comparison on a realistic tree ----------------------------------------------------


def test_a_realistic_mix_of_changes() -> None:
    old = [
        d(path=""),
        f(path="keep.txt", sha256=SHA_1),
        f(path="edit.txt", sha256=SHA_1, size=3),
        f(path="gone.txt", sha256=SHA_3),
        f(path="perm.txt", sha256=SHA_1, mode=0o600),
        f(path="swap", sha256=SHA_1),
    ]
    new = [
        d(path=""),
        f(path="keep.txt", sha256=SHA_1, mtime_ns=NS + 7),
        f(path="edit.txt", sha256=SHA_2, size=9),
        f(path="perm.txt", sha256=SHA_1, mode=0o666),
        link("/etc/passwd", path="swap"),
        f(path="planted.sh", sha256=SHA_2, mode=0o755),
    ]
    result = run(old, new)
    summary = sorted((x.kind.value, x.path) for x in result.findings)
    assert summary == [
        ("created", "/data/planted.sh"),
        ("deleted", "/data/gone.txt"),
        ("modified", "/data/edit.txt"),
        ("permission_changed", "/data/perm.txt"),
        ("type_changed", "/data/swap"),
    ]
    assert result.mtime_only_changes == 1
    escalated = only(
        run([f(path="perm.txt", mode=0o600)], [f(path="perm.txt", mode=0o666)]),
        K.PERMISSION_CHANGED,
    )
    assert escalated.severity is S.HIGH


def test_comparing_a_baseline_with_itself_is_always_clean() -> None:
    records = [d(path=""), f(path="a"), f(path="b/c"), link("t")]
    assert run(records, records).findings == ()


def test_the_scan_result_model_is_what_compare_expects() -> None:
    assert isinstance(scan_of(), ScanResult)


def test_a_link_whose_target_could_not_be_read_is_compared_by_what_is_known() -> None:
    unknown = link("x", link_target=None)
    result = run([unknown], [link("x")])
    finding = only(result, K.MODIFIED)
    assert (finding.changes[0].old, finding.changes[0].new) == (None, "x")
    assert run([unknown], [unknown]).findings == ()


# ---- the events only watch makes ----------------------------------------------------------------


def test_a_baseline_integrity_finding_is_critical_with_a_stable_id() -> None:
    first = core_diff.baseline_integrity_finding("the baseline no longer verifies: the MAC")
    again = core_diff.baseline_integrity_finding("the baseline no longer verifies: the MAC")
    other = core_diff.baseline_integrity_finding("the baseline is gone")
    assert first == again
    assert first.finding_id != other.finding_id
    assert first.kind is K.BASELINE_INTEGRITY
    assert first.severity is S.CRITICAL
    assert first.confidence is C.HIGH
    assert first.path == ""
    assert "the MAC" in first.evidence


def test_a_baseline_integrity_message_is_scrubbed_and_clipped() -> None:
    finding = core_diff.baseline_integrity_finding("bad\x1b[31m name\n" + "x" * 5000)
    assert "\x1b" not in finding.evidence
    assert "\n" not in finding.evidence
    assert len(finding.evidence) <= MAX_EVIDENCE_CHARS_CEILING
    assert finding.evidence.endswith("...")


def test_a_resolved_finding_keeps_the_id_path_and_rule_and_names_the_old_kind() -> None:
    original = make.finding(
        finding_id="feedfacefeedface",
        kind=K.DELETED,
        path="/data/a.txt",
        severity=S.HIGH,
        rule="/data",
    )
    resolved = core_diff.resolved_finding(original)
    assert resolved.finding_id == original.finding_id
    assert resolved.path == original.path
    assert resolved.rule == original.rule
    assert resolved.kind is K.RESOLVED
    assert resolved.severity is S.INFO
    assert resolved.evidence == "no longer reported: deleted"
    assert resolved.changes == ()
