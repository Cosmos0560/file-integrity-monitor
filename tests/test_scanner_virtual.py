"""services/scanner.py on a virtual tree: every branch, on every operating system."""

from __future__ import annotations

import hashlib
import stat
from typing import Any

import pytest

from fakefs import DENIED, NOT_FOUND, NS, FakeFs
from fakes import FakeClock, TickingClock
from fim.core.limits import DEFAULT_LIMITS, Limits
from fim.core.models import (
    EntryType,
    FileRecord,
    HashStatus,
    IssueKind,
    Policy,
    RootPolicy,
    ScanResult,
    Severity,
    SymlinkPolicy,
)
from fim.core.pathrules import Flavour, validate_user_path
from fim.core.perms import (
    FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_READONLY,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
    FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_SYSTEM,
    IO_REPARSE_TAG_MOUNT_POINT,
    IO_REPARSE_TAG_SYMLINK,
)
from fim.core.policy import build_policy
from fim.fs.observe import HashResult
from fim.services.scanner import scan

POSIX = Flavour.POSIX
WINDOWS = Flavour.WINDOWS
ARCHIVE = 0x20
DIRECTORY = 0x10


def root(raw: str = "/data", flavour: Flavour = POSIX, **overrides: Any) -> RootPolicy:
    return RootPolicy(path=validate_user_path(raw, flavour), **overrides)


def policy_for(
    *roots: RootPolicy,
    exclude: tuple[str, ...] = (),
    symlinks: SymlinkPolicy = SymlinkPolicy.NEVER,
    limits: Limits = DEFAULT_LIMITS,
) -> Policy:
    return build_policy(list(roots) or [root()], exclude, symlinks, limits)


def run(fs: FakeFs, policy: Policy | None = None, clock: Any = None) -> ScanResult:
    return scan(policy or policy_for(), clock or FakeClock(), view=fs)


def by_path(result: ScanResult) -> dict[str, FileRecord]:
    return {record.path: record for record in result.records}


def paths(result: ScanResult) -> list[str]:
    return [record.path for record in result.records]


def sample_tree() -> FakeFs:
    fs = FakeFs()
    fs.dir("/data")
    fs.file("/data/a.txt", b"alpha")
    fs.file("/data/b.txt", b"")
    fs.dir("/data/sub")
    fs.file("/data/sub/c.txt", b"charlie")
    fs.dir("/data/sub/deep")
    fs.file("/data/sub/deep/d.txt", b"delta")
    return fs


def hashed(status: HashStatus, size: int = 5, error: str | None = None, **extra: Any) -> HashResult:
    fields: dict[str, Any] = {
        "status": status,
        "sha256": None,
        "bytes_read": 0,
        "size": size,
        "mtime_ns": NS,
        "error": error,
        "detail": "something happened",
    }
    fields.update(extra)
    return HashResult(**fields)


# ---- the basic walk ------------------------------------------------------------------------------


def test_records_come_in_sorted_directory_order_with_exact_root_relative_paths() -> None:
    result = run(sample_tree())
    assert paths(result) == ["", "a.txt", "b.txt", "sub", "sub/c.txt", "sub/deep", "sub/deep/d.txt"]
    assert result.complete
    assert result.issues == ()
    assert result.stats.files == 4
    assert result.stats.dirs == 3
    assert result.stats.bytes_hashed == 5 + 0 + 7 + 5


def test_file_records_carry_the_observed_facts() -> None:
    fs = sample_tree()
    fs.nodes["/data/a.txt"].mode = 0o640
    fs.nodes["/data/a.txt"].uid = 7
    fs.nodes["/data/a.txt"].gid = 8
    fs.nodes["/data/a.txt"].nlink = 3
    fs.nodes["/data/a.txt"].mtime_ns = NS + 5
    record = by_path(run(fs))["a.txt"]
    assert record.type is EntryType.FILE
    assert record.sha256 == hashlib.sha256(b"alpha").hexdigest()
    assert record.hash_status is HashStatus.OK
    assert (record.size, record.mtime_ns) == (5, NS + 5)
    assert (record.mode, record.uid, record.gid, record.nlink) == (0o640, 7, 8, 3)
    assert (record.win_attrs, record.link_target, record.reparse_tag, record.error) == (
        None,
        None,
        None,
        None,
    )
    assert record.root_index == 0


def test_an_empty_file_is_hashed() -> None:
    record = by_path(run(sample_tree()))["b.txt"]
    assert record.sha256 == hashlib.sha256(b"").hexdigest()
    assert record.size == 0


def test_directories_are_recorded_with_permissions_but_no_hash_size_or_link_count() -> None:
    fs = sample_tree()
    fs.nodes["/data/sub"].mode = 0o750
    fs.nodes["/data/sub"].nlink = 7  # POSIX counts subdirectories here; it must not be recorded
    record = by_path(run(fs))["sub"]
    assert record.type is EntryType.DIR
    assert (record.size, record.sha256, record.hash_status) == (
        0,
        None,
        HashStatus.NOT_APPLICABLE,
    )
    assert (record.mode, record.uid, record.gid) == (0o750, 1000, 1000)
    assert record.nlink == 1


def test_the_root_directory_is_recorded_as_the_empty_path() -> None:
    record = run(sample_tree()).records[0]
    assert record.path == ""
    assert record.type is EntryType.DIR


def test_a_root_that_is_a_file_is_recorded_with_the_empty_path() -> None:
    fs = FakeFs()
    fs.file("/etc/hosts", b"127.0.0.1 localhost")
    result = run(fs, policy_for(root("/etc/hosts")))
    (record,) = result.records
    assert record.path == ""
    assert record.type is EntryType.FILE
    assert record.sha256 == hashlib.sha256(b"127.0.0.1 localhost").hexdigest()


def test_the_run_is_deterministic_and_independent_of_the_order_things_were_added() -> None:
    first = sample_tree()
    second = FakeFs()
    for path in reversed(list(first.nodes)):
        second.nodes[path] = first.nodes[path]
    assert run(first).records == run(second).records


def test_the_result_carries_the_clock_readings() -> None:
    clock = FakeClock()
    result = run(sample_tree(), clock=clock)
    assert result.started_at == clock.now() == result.finished_at


def test_a_filesystem_root_is_joined_without_doubled_separators() -> None:
    fs = FakeFs()
    fs.dir("/")
    fs.file("/etc", b"x")
    result = run(fs, policy_for(root("/")))
    assert paths(result) == ["", "etc"]
    assert fs.lstat_calls == ["/", "/etc"]


# ---- several roots, nested roots -----------------------------------------------------------------


def test_each_root_is_scanned_in_order_with_its_own_index_and_severity() -> None:
    fs = sample_tree()
    fs.dir("/other")
    fs.file("/other/o.txt", b"o")
    result = run(fs, policy_for(root("/data"), root("/other", severity=Severity.HIGH)))
    assert [(r.root_index, r.path) for r in result.records if r.path in ("", "o.txt")] == [
        (0, ""),
        (1, ""),
        (1, "o.txt"),
    ]


def test_a_nested_root_is_scanned_once_under_the_most_specific_root() -> None:
    fs = sample_tree()
    result = run(fs, policy_for(root("/data"), root("/data/sub")))
    outer = [r.path for r in result.records if r.root_index == 0]
    inner = [r.path for r in result.records if r.root_index == 1]
    assert outer == ["", "a.txt", "b.txt"]  # sub and everything below it belong to the inner root
    assert inner == ["", "c.txt", "deep", "deep/d.txt"]
    assert len(result.records) == 7  # the same seven paths as without nesting, none twice


def test_nesting_does_not_depend_on_the_order_of_the_roots() -> None:
    fs = sample_tree()
    a = run(fs, policy_for(root("/data/sub"), root("/data")))
    assert sorted((r.root_index, r.path) for r in a.records if r.root_index == 1) == [
        (1, ""),
        (1, "a.txt"),
        (1, "b.txt"),
    ]
    assert len(a.records) == 7


def test_windows_nested_roots_match_case_insensitively() -> None:
    fs = FakeFs(sep="\\")
    fs.dir("C:\\Data")
    fs.file("C:\\Data\\a.txt", b"a")
    fs.dir("C:\\Data\\Sub")
    fs.file("C:\\Data\\Sub\\b.txt", b"b")
    policy = policy_for(root("C:\\Data", WINDOWS), root("c:\\data\\sub", WINDOWS))
    fs.nodes["c:\\data\\sub"] = fs.nodes["C:\\Data\\Sub"]
    fs.nodes["c:\\data\\sub\\b.txt"] = fs.nodes["C:\\Data\\Sub\\b.txt"]
    result = run(fs, policy)
    assert [r.path for r in result.records if r.root_index == 0] == ["", "a.txt"]


# ---- excludes and includes -----------------------------------------------------------------------


def test_an_excluded_directory_is_not_recorded_and_not_even_listed() -> None:
    fs = sample_tree()
    result = run(fs, policy_for(root(exclude=("sub",))))
    assert paths(result) == ["", "a.txt", "b.txt"]
    assert "/data/sub" not in fs.list_calls


def test_global_and_root_excludes_both_apply_at_any_depth() -> None:
    fs = sample_tree()
    fs.file("/data/sub/deep/skip.tmp", b"t")
    fs.file("/data/skip.tmp", b"t")
    result = run(fs, policy_for(root(exclude=("c.txt",)), exclude=("*.tmp",)))
    assert "skip.tmp" not in paths(result)
    assert "sub/deep/skip.tmp" not in paths(result)
    assert "sub/c.txt" not in paths(result)
    assert "sub/deep/d.txt" in paths(result)


def test_a_double_star_exclude_prunes_a_whole_subtree() -> None:
    fs = sample_tree()
    fs.dir("/data/__pycache__")
    fs.file("/data/__pycache__/x.pyc", b"x")
    result = run(fs, policy_for(exclude=("**/__pycache__/**",)))
    assert not any("__pycache__" in path for path in paths(result))
    assert "/data/__pycache__" not in fs.list_calls


def test_includes_limit_files_but_directories_are_always_walked_and_recorded() -> None:
    fs = sample_tree()
    result = run(fs, policy_for(root(include=("*.txt",))))
    assert "a.txt" in paths(result)
    fs.file("/data/readme.md", b"m")
    result = run(fs, policy_for(root(include=("c.txt",))))
    assert paths(result) == ["", "sub", "sub/c.txt", "sub/deep"]


def test_excludes_win_over_includes() -> None:
    result = run(sample_tree(), policy_for(root(include=("*.txt",), exclude=("a.txt",))))
    assert "a.txt" not in paths(result)
    assert "b.txt" in paths(result)


def test_the_root_itself_is_never_excluded() -> None:
    result = run(sample_tree(), policy_for(exclude=("**",)))
    assert paths(result) == [""]


# ---- file hashing decisions ----------------------------------------------------------------------


def test_a_file_over_the_cap_is_recorded_unhashed_and_counted() -> None:
    fs = sample_tree()
    fs.nodes["/data/a.txt"].size = 5000
    limits = Limits(max_hash_file_bytes=1000)
    result = run(fs, policy_for(limits=limits))
    record = by_path(result)["a.txt"]
    assert (record.hash_status, record.sha256, record.size) == (
        HashStatus.SKIPPED_TOO_LARGE,
        None,
        5000,
    )
    assert result.stats.skipped_too_large == 1
    assert ("/data/a.txt", False) not in fs.hash_calls  # never opened
    assert result.complete  # skipping a big file is by design, not a limit hit


def test_a_file_exactly_at_the_cap_is_hashed() -> None:
    fs = sample_tree()
    limits = Limits(max_hash_file_bytes=5)
    record = by_path(run(fs, policy_for(limits=limits)))["a.txt"]
    assert record.hash_status is HashStatus.OK


def test_a_file_that_grows_past_the_cap_while_being_hashed_is_counted_once() -> None:
    fs = sample_tree()
    fs.hash_overrides["/data/a.txt"] = hashed(HashStatus.SKIPPED_TOO_LARGE, size=9999)
    result = run(fs)
    record = by_path(result)["a.txt"]
    assert (record.hash_status, record.size, record.sha256) == (
        HashStatus.SKIPPED_TOO_LARGE,
        9999,
        None,
    )
    assert result.stats.skipped_too_large == 1


@pytest.mark.parametrize(
    ("status", "error", "kind"),
    [
        (HashStatus.UNREADABLE, "EACCES", IssueKind.UNREADABLE),
        (HashStatus.UNSTABLE, None, IssueKind.UNSTABLE),
        (HashStatus.VANISHED, None, IssueKind.VANISHED),
    ],
)
def test_a_hash_failure_is_a_record_and_a_scan_issue_never_a_crash(
    status: HashStatus, error: str | None, kind: IssueKind
) -> None:
    fs = sample_tree()
    fs.hash_overrides["/data/a.txt"] = hashed(status, error=error)
    result = run(fs)
    record = by_path(result)["a.txt"]
    assert (record.hash_status, record.sha256, record.error) == (status, None, error)
    assert [(issue.kind, issue.path) for issue in result.issues] == [(kind, "/data/a.txt")]
    assert result.complete
    assert "sub/deep/d.txt" in paths(result)  # the scan went on


def test_an_unreadable_issue_names_the_errno() -> None:
    fs = sample_tree()
    fs.hash_overrides["/data/a.txt"] = hashed(HashStatus.UNREADABLE, error="EACCES")
    (issue,) = run(fs).issues
    assert "(EACCES)" in issue.detail


def test_a_run_that_hits_the_time_budget_while_hashing_records_nothing_for_that_file() -> None:
    fs = sample_tree()
    clock = FakeClock()
    fs.on_hash = lambda path: clock.advance(10_000) if path.endswith("a.txt") else None
    result = run(fs, policy_for(limits=Limits(max_run_seconds=5)), clock=clock)
    assert "a.txt" not in paths(result)
    assert not result.complete
    assert [i.kind for i in result.issues] == [IssueKind.TIME_BUDGET]
    assert "b.txt" not in paths(result)


# ---- Windows attributes --------------------------------------------------------------------------


def windows_tree(**file_fields: Any) -> FakeFs:
    fs = FakeFs(sep="\\")
    fs.dir("C:\\data", attributes=DIRECTORY, uid=None, gid=None)
    fs.file("C:\\data\\f.txt", b"win", attributes=ARCHIVE, uid=None, gid=None, **file_fields)
    return fs


def test_windows_records_keep_only_readonly_hidden_and_system() -> None:
    fs = windows_tree()
    fs.nodes["C:\\data\\f.txt"].attributes = (
        ARCHIVE | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
    )
    result = run(fs, policy_for(root("C:\\data", WINDOWS)))
    record = by_path(result)["f.txt"]
    assert record.win_attrs == 0x7
    assert (record.mode, record.uid, record.gid) == (None, None, None)
    assert by_path(result)[""].win_attrs == 0


def test_the_archive_bit_alone_is_not_recorded() -> None:
    result = run(windows_tree(), policy_for(root("C:\\data", WINDOWS)))
    assert by_path(result)["f.txt"].win_attrs == 0


def test_a_windows_issue_path_shows_single_backslashes() -> None:
    fs = windows_tree()
    fs.hash_overrides["C:\\data\\f.txt"] = hashed(HashStatus.UNREADABLE, error="EACCES")
    (issue,) = run(fs, policy_for(root("C:\\data", WINDOWS))).issues
    assert issue.path == "C:\\data\\f.txt"
    assert "\\\\" not in issue.path


@pytest.mark.parametrize("bit", [FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS])
def test_an_offline_placeholder_is_never_opened(bit: int) -> None:
    fs = windows_tree()
    fs.nodes["C:\\data\\f.txt"].attributes = ARCHIVE | bit
    result = run(fs, policy_for(root("C:\\data", WINDOWS)))
    record = by_path(result)["f.txt"]
    assert record.hash_status is HashStatus.SKIPPED_OFFLINE
    assert record.sha256 is None
    assert fs.hash_calls == []
    assert result.stats.skipped_offline == 1


def test_a_junction_is_recorded_as_a_reparse_point_and_never_entered() -> None:
    fs = windows_tree()
    fs.add(
        "C:\\data\\junction",
        "reparse",
        attributes=DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT,
        tag=IO_REPARSE_TAG_MOUNT_POINT,
        uid=None,
        gid=None,
    )
    fs.file("C:\\data\\junction\\inside.txt", b"x", attributes=ARCHIVE)
    result = run(fs, policy_for(root("C:\\data", WINDOWS)))
    record = by_path(result)["junction"]
    assert record.type is EntryType.REPARSE
    assert record.reparse_tag == IO_REPARSE_TAG_MOUNT_POINT
    assert (record.sha256, record.hash_status) == (None, HashStatus.NOT_APPLICABLE)
    assert "junction/inside.txt" not in paths(result)
    assert "C:\\data\\junction" not in fs.list_calls
    assert fs.target_calls == []  # not followed even to look


def test_a_windows_symlink_is_a_symlink_with_its_target_and_tag() -> None:
    fs = windows_tree()
    fs.add(
        "C:\\data\\link",
        "symlink",
        attributes=FILE_ATTRIBUTE_REPARSE_POINT,
        tag=IO_REPARSE_TAG_SYMLINK,
        target="f.txt",
        uid=None,
        gid=None,
    )
    record = by_path(run(fs, policy_for(root("C:\\data", WINDOWS))))["link"]
    assert record.type is EntryType.SYMLINK
    assert record.link_target == "f.txt"
    assert record.reparse_tag == IO_REPARSE_TAG_SYMLINK


# ---- symlinks (policy never / files) -------------------------------------------------------------


def link_tree() -> FakeFs:
    fs = sample_tree()
    fs.add("/data/link", "symlink", target="a.txt", points_to="/data/a.txt", mode=0o777)
    fs.add("/data/dirlink", "symlink", target="sub", points_to="/data/sub", mode=0o777)
    fs.add("/data/dangling", "symlink", target="nowhere", points_to=None, mode=0o777)
    return fs


def test_by_default_a_symlink_is_recorded_as_itself_with_its_target_text() -> None:
    fs = link_tree()
    result = run(fs)
    record = by_path(result)["link"]
    assert record.type is EntryType.SYMLINK
    assert record.link_target == "a.txt"
    assert (record.sha256, record.hash_status) == (None, HashStatus.NOT_APPLICABLE)
    assert (record.mode, record.uid) == (0o777, 1000)
    assert fs.target_calls == []  # never followed, not even to stat
    assert not any(call[0] == "/data/link" for call in fs.hash_calls)
    assert "/data/dirlink" not in fs.list_calls
    assert "dirlink/c.txt" not in paths(result)
    assert by_path(result)["dangling"].link_target == "nowhere"
    assert result.issues == ()


def test_the_files_policy_hashes_a_link_to_a_regular_file_through_the_link() -> None:
    fs = link_tree()
    result = run(fs, policy_for(symlinks=SymlinkPolicy.FILES))
    record = by_path(result)["link"]
    assert record.type is EntryType.SYMLINK
    assert record.hash_status is HashStatus.OK
    assert record.sha256 == hashlib.sha256(b"alpha").hexdigest()
    assert ("/data/link", True) in fs.hash_calls
    assert record.size == 0  # the size and time stay those of the link itself
    assert record.link_target == "a.txt"


def test_the_files_policy_does_not_traverse_a_link_to_a_directory_or_follow_a_dangling_one() -> (
    None
):
    fs = link_tree()
    result = run(fs, policy_for(symlinks=SymlinkPolicy.FILES))
    assert by_path(result)["dirlink"].hash_status is HashStatus.NOT_APPLICABLE
    assert by_path(result)["dangling"].hash_status is HashStatus.NOT_APPLICABLE
    assert "/data/dirlink" not in fs.list_calls
    assert result.issues == ()  # a dangling link is fine (D6)


def test_the_files_policy_respects_the_size_cap_for_the_target() -> None:
    fs = link_tree()
    fs.nodes["/data/a.txt"].size = 5000
    result = run(
        fs, policy_for(symlinks=SymlinkPolicy.FILES, limits=Limits(max_hash_file_bytes=10))
    )
    assert by_path(result)["link"].hash_status is HashStatus.SKIPPED_TOO_LARGE
    assert result.stats.skipped_too_large == 2  # the real file and the link to it


def test_the_files_policy_reports_a_target_that_cannot_be_read() -> None:
    fs = link_tree()
    fs.hash_overrides["/data/link"] = hashed(HashStatus.UNREADABLE, error="EACCES")
    result = run(fs, policy_for(symlinks=SymlinkPolicy.FILES))
    record = by_path(result)["link"]
    assert (record.hash_status, record.error) == (HashStatus.UNREADABLE, "EACCES")
    assert [i.kind for i in result.issues] == [IssueKind.UNREADABLE]


def test_the_files_policy_with_an_offline_target_does_not_read_it() -> None:
    fs = FakeFs(sep="\\")
    fs.dir("C:\\data", attributes=DIRECTORY)
    fs.file("C:\\data\\cloud.txt", b"x", attributes=ARCHIVE | FILE_ATTRIBUTE_OFFLINE)
    fs.add(
        "C:\\data\\link",
        "symlink",
        attributes=FILE_ATTRIBUTE_REPARSE_POINT,
        tag=IO_REPARSE_TAG_SYMLINK,
        target="cloud.txt",
        points_to="C:\\data\\cloud.txt",
    )
    result = run(fs, policy_for(root("C:\\data", WINDOWS), symlinks=SymlinkPolicy.FILES))
    assert by_path(result)["link"].hash_status is HashStatus.SKIPPED_OFFLINE
    assert fs.hash_calls == []


def test_a_link_whose_text_cannot_be_read_is_an_issue_but_still_a_record() -> None:
    fs = link_tree()
    fs.link_errors["/data/link"] = DENIED
    result = run(fs)
    record = by_path(result)["link"]
    assert record.link_target is None
    assert record.error == "EACCES"
    assert [(i.kind, i.path) for i in result.issues] == [(IssueKind.UNREADABLE, "/data/link")]
    fs.link_errors["/data/link"] = NOT_FOUND
    assert [i.kind for i in run(fs).issues] == [IssueKind.VANISHED]


def test_a_link_pointing_outside_the_root_is_just_text() -> None:
    fs = sample_tree()
    fs.add("/data/escape", "symlink", target="../../etc/passwd", mode=0o777)
    result = run(fs)
    assert by_path(result)["escape"].link_target == "../../etc/passwd"
    assert fs.target_calls == []


def test_hostile_link_targets_are_kept_exactly() -> None:
    fs = sample_tree()
    hostile = "x\ny" + chr(0x202E) + chr(0xDC80)
    fs.add("/data/evil", "symlink", target=hostile, mode=0o777)
    assert by_path(run(fs))["evil"].link_target == hostile


# ---- special files -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("fifo", EntryType.FIFO),
        ("socket", EntryType.SOCKET),
        ("device", EntryType.DEVICE),
        ("other", EntryType.OTHER),
    ],
)
def test_special_files_are_described_and_never_opened(kind: str, expected: EntryType) -> None:
    fs = sample_tree()
    fs.add("/data/special", kind, mode=0o600)
    result = run(fs)
    record = by_path(result)["special"]
    assert record.type is expected
    assert (record.sha256, record.hash_status) == (None, HashStatus.NOT_APPLICABLE)
    assert record.mode == 0o600
    assert not any(call[0] == "/data/special" for call in fs.hash_calls)
    assert "/data/special" not in fs.list_calls
    assert fs.target_calls == []
    assert result.issues == ()


# ---- problems at the roots -----------------------------------------------------------------------


def test_a_missing_root_is_a_root_unavailable_issue_and_the_others_are_scanned() -> None:
    fs = sample_tree()
    result = run(fs, policy_for(root("/gone"), root("/data")))
    assert [(i.kind, i.path) for i in result.issues] == [(IssueKind.ROOT_UNAVAILABLE, "/gone")]
    assert "not found" in result.issues[0].detail
    assert all(record.root_index == 1 for record in result.records)
    assert result.complete


def test_a_root_we_may_not_read_says_why() -> None:
    fs = sample_tree()
    fs.lstat_errors["/data"] = DENIED
    (issue,) = run(fs).issues
    assert issue.kind is IssueKind.ROOT_UNAVAILABLE
    assert "cannot be read (EACCES)" in issue.detail


@pytest.mark.parametrize("kind", ["symlink", "fifo", "socket", "device"])
def test_a_root_that_is_not_a_file_or_directory_is_refused(kind: str) -> None:
    fs = FakeFs()
    fs.add("/data", kind, mode=0o777)
    result = run(fs)
    assert result.records == ()
    (issue,) = result.issues
    assert issue.kind is IssueKind.ROOT_UNAVAILABLE
    if kind == "symlink":
        assert "configure the real path" in issue.detail
    else:
        assert "neither a file nor a directory" in issue.detail


def test_a_root_that_is_a_junction_is_refused() -> None:
    fs = FakeFs(sep="\\")
    fs.add(
        "C:\\data",
        "reparse",
        attributes=DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT,
        tag=IO_REPARSE_TAG_MOUNT_POINT,
    )
    (issue,) = run(fs, policy_for(root("C:\\data", WINDOWS))).issues
    assert issue.kind is IssueKind.ROOT_UNAVAILABLE
    assert "reparse point" in issue.detail


# ---- problems inside the tree --------------------------------------------------------------------


def test_an_entry_that_disappears_between_listing_and_stat_is_vanished() -> None:
    fs = sample_tree()
    fs.lstat_errors["/data/b.txt"] = NOT_FOUND
    result = run(fs)
    assert "b.txt" not in paths(result)
    assert [(i.kind, i.path) for i in result.issues] == [(IssueKind.VANISHED, "/data/b.txt")]
    assert "sub/c.txt" in paths(result)


def test_an_entry_that_cannot_be_examined_is_unreadable() -> None:
    fs = sample_tree()
    fs.lstat_errors["/data/b.txt"] = DENIED
    (issue,) = run(fs).issues
    assert issue.kind is IssueKind.UNREADABLE
    assert "(EACCES)" in issue.detail


def test_a_directory_that_cannot_be_listed_is_recorded_and_reported() -> None:
    fs = sample_tree()
    fs.list_errors["/data/sub"] = DENIED
    result = run(fs)
    assert "sub" in paths(result)
    assert "sub/c.txt" not in paths(result)
    assert [(i.kind, i.path) for i in result.issues] == [(IssueKind.UNREADABLE, "/data/sub")]
    fs.list_errors["/data/sub"] = NOT_FOUND
    assert [i.kind for i in run(fs).issues] == [IssueKind.VANISHED]


def test_a_name_that_cannot_be_stored_is_an_issue_not_a_crash() -> None:
    fs = sample_tree()
    fs.file("/data/odd", b"x")
    original = fs.children

    def with_bad_name(path: str) -> list[str]:
        names = original(path)
        return [*names, "bad/name"] if path == "/data" else names

    fs.children = with_bad_name  # type: ignore[method-assign]  # a deliberately broken listing
    fs.nodes["/data/bad/name"] = fs.nodes["/data/odd"]
    result = run(fs)
    assert any(i.detail == "name cannot be recorded" for i in result.issues)
    assert "odd" in paths(result)


# ---- mount points and loops ----------------------------------------------------------------------


def test_a_mount_point_is_recorded_but_not_entered_by_default() -> None:
    fs = sample_tree()
    fs.nodes["/data/sub"].dev = 2
    result = run(fs)
    assert "sub" in paths(result)
    assert "sub/c.txt" not in paths(result)
    assert "/data/sub" not in fs.list_calls
    assert result.complete


def test_one_file_system_false_enters_other_devices() -> None:
    fs = sample_tree()
    for path in ("/data/sub", "/data/sub/c.txt", "/data/sub/deep", "/data/sub/deep/d.txt"):
        fs.nodes[path].dev = 2
    result = run(fs, policy_for(root(one_file_system=False)))
    assert "sub/deep/d.txt" in paths(result)


def test_a_directory_reached_twice_is_entered_once_and_the_run_is_incomplete() -> None:
    fs = sample_tree()
    fs.dir("/data/zz", ino=fs.nodes["/data/sub"].ino, dev=fs.nodes["/data/sub"].dev)
    fs.file("/data/zz/loop.txt", b"x")
    result = run(fs)
    assert "zz" in paths(result)
    assert "zz/loop.txt" not in paths(result)
    assert not result.complete
    assert [i.kind for i in result.issues] == [IssueKind.LIMIT_REACHED]
    assert "twice" in result.issues[0].detail


def test_a_child_with_the_roots_identity_is_a_loop() -> None:
    fs = sample_tree()
    root_node = fs.nodes["/data"]
    fs.dir("/data/back", ino=root_node.ino, dev=root_node.dev)
    result = run(fs)
    assert not result.complete
    assert "back" in paths(result)


def test_filesystems_without_inode_numbers_are_not_treated_as_loops() -> None:
    fs = FakeFs()
    for path in ("/data", "/data/x", "/data/y"):
        fs.dir(path)
        fs.nodes[path].ino = 0
    fs.nodes["/data"].ino = 0
    for node in fs.nodes.values():
        node.ino = 0
    fs._next_ino = 100  # keep later additions unique
    fs.file("/data/x/f", b"1")
    fs.file("/data/y/g", b"2")
    for path in ("/data/x/f", "/data/y/g"):
        fs.nodes[path].ino = 0
    result = run(fs)
    assert {"x/f", "y/g"} <= set(paths(result))
    assert result.complete


# ---- limits --------------------------------------------------------------------------------------


def test_max_files_stops_the_run_and_marks_it_incomplete() -> None:
    result = run(sample_tree(), policy_for(limits=Limits(max_files=4)))
    assert len(result.records) == 4
    assert not result.complete
    limit_issues = [i for i in result.issues if i.kind is IssueKind.LIMIT_REACHED]
    assert len(limit_issues) == 1
    assert "max_files" in limit_issues[0].detail


def test_the_file_limit_is_noted_once_however_many_directories_meet_it() -> None:
    fs = FakeFs()
    fs.dir("/data")
    for name in ("one", "two"):
        fs.dir(f"/data/{name}")
        fs.file(f"/data/{name}/f", b"x")
    result = run(fs, policy_for(limits=Limits(max_files=3)))
    assert len(result.records) == 3
    assert [i.kind for i in result.issues] == [IssueKind.LIMIT_REACHED]
    assert not result.complete


def test_the_file_limit_is_enforced_even_if_a_listing_returns_more_than_asked() -> None:
    fs = sample_tree()
    fs.listing_limit_ignored = True
    result = run(fs, policy_for(limits=Limits(max_files=3)))
    assert len(result.records) == 3
    assert not result.complete


def test_a_root_whose_own_path_is_over_the_path_limit_is_not_scanned() -> None:
    result = run(sample_tree(), policy_for(limits=Limits(max_path_chars=3)))
    assert result.records == ()
    assert not result.complete
    assert [i.kind for i in result.issues] == [IssueKind.LIMIT_REACHED]


def test_a_budget_that_ends_between_directories_stops_before_the_next_listing() -> None:
    fs = sample_tree()
    clock = FakeClock()
    fs.on_lstat = lambda path: clock.advance(10_000) if path == "/data/sub" else None
    result = run(fs, policy_for(limits=Limits(max_run_seconds=5)), clock=clock)
    assert "/data/sub" not in fs.list_calls
    assert "sub" in paths(result)
    assert [i.kind for i in result.issues] == [IssueKind.TIME_BUDGET]
    assert not result.complete


def test_a_budget_that_ends_while_hashing_a_link_target_records_nothing_for_the_link() -> None:
    fs = link_tree()
    fs.hash_overrides["/data/link"] = hashed(HashStatus.UNSTABLE, stopped=True)
    result = run(fs, policy_for(symlinks=SymlinkPolicy.FILES))
    assert "link" not in paths(result)
    assert [i.kind for i in result.issues] == [IssueKind.TIME_BUDGET]


def test_exactly_max_files_entries_is_still_complete() -> None:
    result = run(sample_tree(), policy_for(limits=Limits(max_files=7)))
    assert len(result.records) == 7
    assert result.complete


def test_a_huge_directory_is_cut_by_the_listing_and_the_run_is_incomplete() -> None:
    fs = FakeFs()
    fs.dir("/data")
    for number in range(20):
        fs.file(f"/data/f{number:02d}", b"x")
    result = run(fs, policy_for(limits=Limits(max_files=6)))
    assert len(result.records) == 6
    assert not result.complete
    assert fs.list_calls == ["/data"]


def test_max_depth_leaves_deeper_directories_unentered_but_recorded() -> None:
    result = run(sample_tree(), policy_for(limits=Limits(max_depth=2)))
    assert "sub/deep" in paths(result)
    assert "sub/deep/d.txt" not in paths(result)
    assert not result.complete
    (issue,) = result.issues
    assert issue.kind is IssueKind.LIMIT_REACHED
    assert issue.path == "/data/sub/deep"
    assert "max_depth" in issue.detail


def test_a_depth_limit_does_not_stop_siblings() -> None:
    fs = sample_tree()
    fs.dir("/data/other")
    fs.file("/data/other/o.txt", b"o")
    result = run(fs, policy_for(limits=Limits(max_depth=2)))
    assert "other/o.txt" in paths(result)


def test_a_path_longer_than_the_limit_is_skipped_with_an_issue() -> None:
    fs = sample_tree()
    fs.file("/data/" + "n" * 40, b"x")
    result = run(fs, policy_for(limits=Limits(max_path_chars=20)))
    assert not any(path.startswith("nnn") for path in paths(result))
    assert not result.complete
    assert any("max_path_chars" in i.detail for i in result.issues)


def test_the_time_budget_stops_the_scan_with_one_issue() -> None:
    clock = TickingClock(step=100.0)
    result = run(sample_tree(), policy_for(limits=Limits(max_run_seconds=250)), clock=clock)
    assert not result.complete
    time_issues = [i for i in result.issues if i.kind is IssueKind.TIME_BUDGET]
    assert len(time_issues) == 1
    assert len(result.records) < 7


def test_a_budget_that_is_spent_before_the_first_root_scans_nothing() -> None:
    clock = TickingClock(step=1000.0)
    result = run(sample_tree(), policy_for(limits=Limits(max_run_seconds=1)), clock=clock)
    assert result.records == ()
    assert [i.kind for i in result.issues] == [IssueKind.TIME_BUDGET]
    assert not result.complete


def test_a_flood_of_problems_is_bounded_by_the_file_limit() -> None:
    fs = FakeFs(listing_limit_ignored=True)
    fs.dir("/data")
    for number in range(30):
        name = f"/data/f{number:02d}"
        fs.file(name, b"x")
        fs.lstat_errors[name] = DENIED
    result = run(fs, policy_for(limits=Limits(max_files=3)))
    assert len(result.issues) == 4  # three problems and the one limit notice
    assert result.issues[-1].kind is IssueKind.LIMIT_REACHED
    assert not result.complete


def test_hitting_a_limit_is_never_reported_as_complete_for_any_limit() -> None:
    for limits in (Limits(max_files=2), Limits(max_depth=1), Limits(max_path_chars=8)):
        assert not run(sample_tree(), policy_for(limits=limits)).complete


# ---- hostile names -------------------------------------------------------------------------------


def test_hostile_names_are_stored_exactly_and_escaped_in_issues() -> None:
    fs = FakeFs()
    fs.dir("/data")
    names = ["line\nbreak", "bidi" + chr(0x202E) + "gnp.exe", "esc\x1b[31m", "bad" + chr(0xDC80)]
    for name in names:
        fs.file("/data/" + name, b"x")
        fs.hash_overrides["/data/" + name] = hashed(HashStatus.UNREADABLE, error="EACCES")
    result = run(fs)
    assert set(paths(result)) >= {""} | set(names)  # exact text in the records
    for issue in result.issues:
        assert "\n" not in issue.path
        assert "\x1b" not in issue.path
        assert chr(0x202E) not in issue.path
    assert any("\\x0a" in issue.path for issue in result.issues)
    assert any("\\u202e" in issue.path for issue in result.issues)
    assert any("\\ydc" not in issue.path and "\\y80" in issue.path for issue in result.issues)


def test_a_record_for_every_file_type_validates_against_the_model() -> None:
    fs = link_tree()
    for kind in ("fifo", "socket", "device", "other"):
        fs.add(f"/data/{kind}", kind)
    for symlinks in (SymlinkPolicy.NEVER, SymlinkPolicy.FILES):
        result = run(fs, policy_for(symlinks=symlinks))
        assert {record.type for record in result.records} >= {
            EntryType.FILE,
            EntryType.DIR,
            EntryType.SYMLINK,
            EntryType.FIFO,
            EntryType.SOCKET,
            EntryType.DEVICE,
            EntryType.OTHER,
        }


def test_modes_are_recorded_without_the_file_type_bits() -> None:
    fs = sample_tree()
    fs.nodes["/data/a.txt"].mode = 0o4755
    record = by_path(run(fs))["a.txt"]
    assert record.mode == 0o4755
    assert not stat.S_ISREG(record.mode)


# ---- the definition of done: every status and issue kind has a scan that produces it -------------


def test_every_hash_status_and_every_issue_kind_is_produced_by_some_scan() -> None:
    mixed = sample_tree()
    mixed.nodes["/data/a.txt"].size = 5000
    mixed.hash_overrides["/data/b.txt"] = hashed(HashStatus.UNREADABLE, error="EACCES")
    mixed.hash_overrides["/data/sub/c.txt"] = hashed(HashStatus.UNSTABLE)
    mixed.hash_overrides["/data/sub/deep/d.txt"] = hashed(HashStatus.VANISHED)
    limited = Limits(max_hash_file_bytes=1000)
    scans = [
        run(mixed, policy_for(root(), root("/missing"), limits=limited)),
        run(sample_tree(), policy_for(limits=Limits(max_files=2))),
        run(
            sample_tree(),
            policy_for(limits=Limits(max_run_seconds=1)),
            clock=TickingClock(step=10.0),
        ),
    ]
    offline = windows_tree()
    offline.nodes["C:\\data\\f.txt"].attributes = ARCHIVE | FILE_ATTRIBUTE_OFFLINE
    scans.append(run(offline, policy_for(root(r"C:\data", WINDOWS))))

    statuses = {record.hash_status for result in scans for record in result.records}
    kinds = {issue.kind for result in scans for issue in result.issues}
    assert statuses == set(HashStatus)
    assert kinds == set(IssueKind)


# ---- the real view delegates to fs/observe.py at call time ---------------------------------------


def test_the_real_view_looks_every_function_up_on_the_observe_module_at_call_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """So the pytest path guard (which replaces those functions) is always in force."""
    from fim.fs import observe
    from fim.fs.observe import DirListing, RawStat
    from fim.services.scanner import ObservedFileSystem

    calls: list[tuple[str, tuple[Any, ...]]] = []
    stat_result = RawStat(stat.S_IFREG, 1, 2, 3, 4, 1, None, None, None, None)

    def recorder(name: str, result: Any) -> Any:
        def function(*args: Any, **kwargs: Any) -> Any:
            calls.append((name, (*args, *sorted(kwargs.items()))))
            return result

        return function

    monkeypatch.setattr(observe, "lstat", recorder("lstat", stat_result))
    monkeypatch.setattr(observe, "stat_target", recorder("stat_target", stat_result))
    monkeypatch.setattr(observe, "read_link", recorder("read_link", "target"))
    monkeypatch.setattr(observe, "list_dir", recorder("list_dir", DirListing(("a",), False)))
    sentinel = hashed(HashStatus.OK)
    monkeypatch.setattr(observe, "hash_file", recorder("hash_file", sentinel))

    view = ObservedFileSystem()
    assert view.lstat("p1") is stat_result
    assert view.stat_target("p2") is stat_result
    assert view.read_link("p3") == "target"
    assert view.list_dir("p4", 9) == DirListing(("a",), False)
    stop = lambda: False  # noqa: E731  # a throwaway callback
    assert view.hash_file("p5", stat_result, max_bytes=7, should_stop=stop, follow=True) is sentinel
    assert [name for name, _ in calls] == [
        "lstat",
        "stat_target",
        "read_link",
        "list_dir",
        "hash_file",
    ]
    assert calls[0][1] == ("p1",)
    assert calls[3][1] == ("p4", 9)
    assert dict(calls[4][1][2:]) == {"follow": True, "max_bytes": 7, "should_stop": stop}
