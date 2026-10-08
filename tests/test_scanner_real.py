"""services/scanner.py on real directory trees in tmp_path (the only place tests may scan)."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import path_guard
import winhelp
from conftest import REPO_ROOT
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
    SymlinkPolicy,
)
from fim.core.pathrules import Flavour, validate_user_path
from fim.core.perms import (
    FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_READONLY,
    FILE_ATTRIBUTE_SYSTEM,
    IO_REPARSE_TAG_MOUNT_POINT,
)
from fim.core.policy import build_policy
from fim.fs import observe
from fim.fs.observe import HashResult, RawStat, ReadOps
from fim.platform.clock import SystemClock
from fim.services.scanner import scan

FLAVOUR = Flavour.WINDOWS if sys.platform == "win32" else Flavour.POSIX
NS = 1_700_000_000_000_000_000


def root_for(path: Path, **overrides: Any) -> RootPolicy:
    return RootPolicy(path=validate_user_path(str(path), FLAVOUR), **overrides)


def policy_for(
    *roots: RootPolicy,
    exclude: tuple[str, ...] = (),
    symlinks: SymlinkPolicy = SymlinkPolicy.NEVER,
    limits: Limits = DEFAULT_LIMITS,
) -> Policy:
    return build_policy(list(roots), exclude, symlinks, limits)


def run(path: Path, *, clock: Any = None, **options: Any) -> ScanResult:
    root_options = options.pop("root_options", {})
    policy = policy_for(root_for(path, **root_options), **options)
    return scan(policy, clock or FakeClock())


def paths(result: ScanResult) -> list[str]:
    return [record.path for record in result.records]


def by_path(result: ScanResult) -> dict[str, FileRecord]:
    return {record.path: record for record in result.records}


def write(path: Path, content: bytes = b"data", mtime_ns: int = NS) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    os.utime(path, ns=(mtime_ns, mtime_ns))
    return path


def build_tree(base: Path) -> None:
    write(base / "a.txt", b"alpha")
    write(base / "empty.bin", b"")
    write(base / "sub" / "b.txt", b"bravo")
    write(base / "sub" / "deeper" / "c.txt", b"charlie")
    (base / "emptydir").mkdir()


def tree_state(base: Path) -> dict[str, tuple[Any, ...]]:
    """Everything about every entry that a read-only tool must leave alone."""
    state: dict[str, tuple[Any, ...]] = {}
    for entry in [base, *sorted(base.rglob("*"))]:
        info = entry.lstat()
        content = (
            hashlib.sha256(entry.read_bytes()).hexdigest() if stat.S_ISREG(info.st_mode) else None
        )
        state[str(entry.relative_to(base))] = (
            info.st_mode,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
            info.st_nlink,
            getattr(info, "st_file_attributes", None),
            content,
        )
    return state


# ---- an ordinary tree ----------------------------------------------------------------------------


def test_a_real_tree_is_recorded_with_the_facts_of_the_files(tmp_path: Path) -> None:
    build_tree(tmp_path)
    result = run(tmp_path)
    assert paths(result) == [
        "",
        "a.txt",
        "empty.bin",
        "emptydir",
        "sub",
        "sub/b.txt",
        "sub/deeper",
        "sub/deeper/c.txt",
    ]
    assert result.complete
    assert result.issues == ()
    record = by_path(result)["sub/deeper/c.txt"]
    assert record.type is EntryType.FILE
    assert record.sha256 == hashlib.sha256(b"charlie").hexdigest()
    assert (record.size, record.mtime_ns, record.nlink) == (7, NS, 1)
    assert by_path(result)["empty.bin"].sha256 == hashlib.sha256(b"").hexdigest()
    assert by_path(result)["emptydir"].type is EntryType.DIR
    assert (result.stats.files, result.stats.dirs) == (4, 4)
    assert result.stats.bytes_hashed == 5 + 0 + 5 + 7


def test_record_paths_use_forward_slashes_on_every_os(tmp_path: Path) -> None:
    build_tree(tmp_path)
    for record in run(tmp_path).records:
        assert "\\" not in record.path


def test_a_single_file_can_be_the_root(tmp_path: Path) -> None:
    target = write(tmp_path / "hosts", b"127.0.0.1 localhost")
    (record,) = run(target).records
    assert (record.path, record.type) == ("", EntryType.FILE)
    assert record.sha256 == hashlib.sha256(b"127.0.0.1 localhost").hexdigest()


def test_a_missing_root_is_reported_not_raised(tmp_path: Path) -> None:
    result = run(tmp_path / "nowhere")
    assert result.records == ()
    assert [i.kind for i in result.issues] == [IssueKind.ROOT_UNAVAILABLE]
    assert result.complete


def test_hard_links_record_the_link_count(tmp_path: Path) -> None:
    first = write(tmp_path / "one", b"same")
    os.link(first, tmp_path / "two")
    records = by_path(run(tmp_path))
    assert records["one"].nlink == records["two"].nlink == 2
    assert records["one"].sha256 == records["two"].sha256


def test_excludes_and_includes_work_on_real_names(tmp_path: Path) -> None:
    build_tree(tmp_path)
    write(tmp_path / "sub" / "skip.tmp", b"t")
    result = run(tmp_path, exclude=("*.tmp", "deeper"))
    assert "sub/skip.tmp" not in paths(result)
    assert "sub/deeper" not in paths(result)
    assert "sub/deeper/c.txt" not in paths(result)
    included = run(tmp_path, root_options={"include": ("b.txt",)})
    assert [p for p in paths(included) if "." in p] == ["sub/b.txt"]


def test_a_nested_root_is_recorded_once(tmp_path: Path) -> None:
    build_tree(tmp_path)
    policy = policy_for(root_for(tmp_path), root_for(tmp_path / "sub"))
    result = scan(policy, FakeClock())
    assert [r.path for r in result.records if r.root_index == 0] == [
        "",
        "a.txt",
        "empty.bin",
        "emptydir",
    ]
    assert "deeper/c.txt" in [r.path for r in result.records if r.root_index == 1]


def test_the_real_clock_and_the_default_view_work_together(tmp_path: Path) -> None:
    build_tree(tmp_path)
    result = scan(policy_for(root_for(tmp_path)), SystemClock())
    assert result.complete
    assert result.started_at <= result.finished_at
    assert len(result.records) == 8


# ---- hostile names -------------------------------------------------------------------------------


def test_hostile_names_are_recorded_exactly_and_issues_show_them_escaped(tmp_path: Path) -> None:
    hostile = "evil" + chr(0x202E) + "gnp.exe" + chr(0x200B)
    write(tmp_path / hostile, b"payload")
    result = run(tmp_path)
    assert by_path(result)[hostile].sha256 == hashlib.sha256(b"payload").hexdigest()
    assert result.issues == ()


def test_an_issue_about_a_hostile_name_shows_it_escaped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hostile = "evil" + chr(0x202E) + "gnp.exe"
    write(tmp_path / hostile, b"payload")
    monkeypatch.setattr(observe, "system_read_ops", faulty_ops("gnp.exe", "vanish"))
    result = run(tmp_path)
    (issue,) = result.issues
    assert chr(0x202E) not in issue.path
    assert issue.path.endswith("evil" + chr(0x5C) + "u202egnp.exe")  # chr(0x5C) is a backslash
    assert hostile in paths(result)  # the record keeps the exact name


@pytest.mark.posix_only
def test_a_name_with_a_newline_and_an_undecodable_byte(tmp_path: Path) -> None:
    raw = os.fsencode(str(tmp_path)) + b"/new\nline" + bytes([0xFF])
    os.close(os.open(raw, os.O_WRONLY | os.O_CREAT, 0o600))
    result = run(tmp_path)
    assert "new\nline" + chr(0xDCFF) in paths(result)


# ---- permissions ---------------------------------------------------------------------------------


@pytest.mark.posix_only
def test_posix_permission_bits_owner_and_group_are_recorded(tmp_path: Path) -> None:
    target = write(tmp_path / "tool")
    target.chmod(0o4755)
    info = target.stat()
    record = by_path(run(tmp_path))["tool"]
    assert record.mode == 0o4755
    assert (record.uid, record.gid) == (info.st_uid, info.st_gid)
    assert record.win_attrs is None


@pytest.mark.windows_only
def test_windows_readonly_hidden_and_system_are_recorded_and_archive_is_not(tmp_path: Path) -> None:
    plain = write(tmp_path / "plain.txt")
    flagged = write(tmp_path / "flagged.txt")
    winhelp.set_windows_attributes(
        flagged, FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
    )
    try:
        records = by_path(run(tmp_path))
        assert records["plain.txt"].win_attrs == 0  # ARCHIVE is set by the write; ignored
        assert records["flagged.txt"].win_attrs == 0x7
        assert (records["plain.txt"].mode, records["plain.txt"].uid) == (None, None)
    finally:
        winhelp.set_windows_attributes(flagged, winhelp.FILE_ATTRIBUTE_NORMAL)
    assert plain.exists()


@pytest.mark.windows_only
def test_a_junction_is_a_reparse_point_that_is_never_entered(tmp_path: Path) -> None:
    real = tmp_path / "real"
    write(real / "inside.txt", b"inside")
    watched = tmp_path / "watched"
    watched.mkdir()
    write(watched / "own.txt", b"own")
    winhelp.make_junction(watched / "junction", real)
    result = run(watched)
    assert paths(result) == ["", "junction", "own.txt"]
    record = by_path(result)["junction"]
    assert record.type is EntryType.REPARSE
    assert record.reparse_tag == IO_REPARSE_TAG_MOUNT_POINT
    assert record.sha256 is None


@pytest.mark.windows_only
def test_a_junction_as_a_root_is_refused_with_a_hint(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    junction = tmp_path / "junction"
    winhelp.make_junction(junction, real)
    result = run(junction)
    assert result.records == ()
    (issue,) = result.issues
    assert issue.kind is IssueKind.ROOT_UNAVAILABLE
    assert "configure the real path" in issue.detail


@pytest.mark.windows_only
def test_a_junction_to_a_directory_that_is_also_a_root_is_scanned_once(tmp_path: Path) -> None:
    real = tmp_path / "real"
    write(real / "f.txt", b"x")
    holder = tmp_path / "holder"
    holder.mkdir()
    winhelp.make_junction(holder / "alias", real)
    result = scan(policy_for(root_for(real), root_for(holder)), FakeClock())
    assert [r.path for r in result.records if r.path.endswith("f.txt")] == ["f.txt"]


# ---- links ---------------------------------------------------------------------------------------


@pytest.mark.requires_symlinks
def test_symlinks_are_recorded_as_links_and_never_entered(tmp_path: Path) -> None:
    watched = tmp_path / "watched"
    write(watched / "real.txt", b"real")
    outside = tmp_path / "outside"
    write(outside / "secret.txt", b"secret")
    os.symlink(watched / "real.txt", watched / "filelink")
    os.symlink(outside, watched / "dirlink", target_is_directory=True)
    os.symlink(watched / "gone", watched / "dangling")
    os.symlink(watched, watched / "loop", target_is_directory=True)
    result = run(watched)
    records = by_path(result)
    for name in ("filelink", "dirlink", "dangling", "loop"):
        assert records[name].type is EntryType.SYMLINK
        assert records[name].hash_status is HashStatus.NOT_APPLICABLE
    assert records["filelink"].link_target == str(watched / "real.txt")
    assert records["dangling"].link_target == str(watched / "gone")
    assert "dirlink/secret.txt" not in paths(result)
    assert not any(path.startswith("loop/") for path in paths(result))
    assert result.complete
    assert result.issues == ()


@pytest.mark.requires_symlinks
def test_the_files_policy_hashes_a_file_target_but_still_does_not_enter_directories(
    tmp_path: Path,
) -> None:
    watched = tmp_path / "watched"
    write(watched / "real.txt", b"real")
    outside = tmp_path / "outside"
    write(outside / "secret.txt", b"secret")
    os.symlink(watched / "real.txt", watched / "filelink")
    os.symlink(outside, watched / "dirlink", target_is_directory=True)
    os.symlink(watched / "gone", watched / "dangling")
    result = run(watched, symlinks=SymlinkPolicy.FILES)
    records = by_path(result)
    assert records["filelink"].sha256 == hashlib.sha256(b"real").hexdigest()
    assert records["dirlink"].hash_status is HashStatus.NOT_APPLICABLE
    assert records["dangling"].hash_status is HashStatus.NOT_APPLICABLE
    assert "dirlink/secret.txt" not in paths(result)
    assert result.issues == ()


@pytest.mark.requires_symlinks
def test_a_root_that_is_a_symlink_is_refused_with_a_hint(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    os.symlink(real, link, target_is_directory=True)
    result = run(link)
    (issue,) = result.issues
    assert issue.kind is IssueKind.ROOT_UNAVAILABLE
    assert "configure the real path" in issue.detail
    assert result.records == ()


# ---- special files and permissions ---------------------------------------------------------------


@pytest.mark.posix_only
def test_a_fifo_is_described_and_never_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if sys.platform != "win32":
        os.mkfifo(tmp_path / "pipe")
    write(tmp_path / "plain.txt", b"x")
    hashed: list[str] = []
    real = observe.hash_file

    def spy(path: str, expected: RawStat, **kwargs: Any) -> HashResult:
        hashed.append(path)
        return real(path, expected, **kwargs)

    monkeypatch.setattr(observe, "hash_file", spy)
    result = run(tmp_path)  # would hang here if the FIFO were opened
    record = by_path(result)["pipe"]
    assert record.type is EntryType.FIFO
    assert record.sha256 is None
    assert hashed == [str(tmp_path / "plain.txt")]


@pytest.mark.posix_only
@pytest.mark.requires_non_root
def test_an_unreadable_file_and_directory_are_issues_and_the_scan_goes_on(tmp_path: Path) -> None:
    secret = write(tmp_path / "secret.txt", b"s")
    locked = tmp_path / "locked"
    write(locked / "inner.txt", b"i")
    write(tmp_path / "ok.txt", b"ok")
    secret.chmod(0)
    locked.chmod(0)
    try:
        result = run(tmp_path)
    finally:
        secret.chmod(0o600)
        locked.chmod(0o700)
    records = by_path(result)
    assert records["secret.txt"].hash_status is HashStatus.UNREADABLE
    assert records["secret.txt"].error == "EACCES"
    assert "locked" in records
    assert "locked/inner.txt" not in records
    assert records["ok.txt"].hash_status is HashStatus.OK
    assert sorted((i.kind, i.path) for i in result.issues) == sorted(
        [
            (IssueKind.UNREADABLE, str(secret)),
            (IssueKind.UNREADABLE, str(locked)),
        ]
    )
    assert result.complete


# ---- failures injected into the real reader ------------------------------------------------------


def faulty_ops(victim: str, behaviour: str) -> Callable[[], ReadOps]:
    """Real operations, except that the file named ``victim`` vanishes or never stops changing."""
    real = observe.system_read_ops()
    names: dict[int, str] = {}
    changes = {"count": 0}

    def open_fd(path: str, follow: bool) -> int:
        if behaviour == "vanish" and path.endswith(victim):
            raise FileNotFoundError(2, "gone")
        descriptor = real.open_fd(path, follow)
        names[descriptor] = path
        return descriptor

    def fstat(descriptor: int) -> RawStat:
        result = real.fstat(descriptor)
        if behaviour == "shift" and names[descriptor].endswith(victim):
            changes["count"] += 1
            return replace(result, size=result.size + changes["count"])
        return result

    return lambda: ReadOps(open_fd=open_fd, fstat=fstat, read=real.read, close=real.close)


def test_a_file_that_vanishes_just_before_it_is_read_is_an_issue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build_tree(tmp_path)
    monkeypatch.setattr(observe, "system_read_ops", faulty_ops("a.txt", "vanish"))
    result = run(tmp_path)
    assert by_path(result)["a.txt"].hash_status is HashStatus.VANISHED
    assert [(i.kind, i.path) for i in result.issues] == [
        (IssueKind.VANISHED, str(tmp_path / "a.txt"))
    ]
    assert by_path(result)["sub/b.txt"].hash_status is HashStatus.OK


def test_a_file_that_keeps_changing_while_it_is_hashed_is_unstable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build_tree(tmp_path)
    monkeypatch.setattr(observe, "system_read_ops", faulty_ops("a.txt", "shift"))
    result = run(tmp_path)
    record = by_path(result)["a.txt"]
    assert record.hash_status is HashStatus.UNSTABLE
    assert record.sha256 is None
    assert IssueKind.UNSTABLE in {i.kind for i in result.issues}


# ---- limits on real trees ------------------------------------------------------------------------


def test_the_file_limit_on_a_real_tree(tmp_path: Path) -> None:
    build_tree(tmp_path)
    result = run(tmp_path, limits=Limits(max_files=3))
    assert len(result.records) == 3
    assert not result.complete


def test_the_time_budget_on_a_real_tree(tmp_path: Path) -> None:
    build_tree(tmp_path)
    result = run(tmp_path, limits=Limits(max_run_seconds=5), clock=TickingClock(step=2.0))
    assert not result.complete
    assert IssueKind.TIME_BUDGET in {i.kind for i in result.issues}


def test_a_big_file_over_the_cap_is_skipped_without_being_read(tmp_path: Path) -> None:
    write(tmp_path / "big.bin", b"x" * 5000)
    result = run(tmp_path, limits=Limits(max_hash_file_bytes=1000))
    record = by_path(result)["big.bin"]
    assert (record.hash_status, record.sha256, record.size) == (
        HashStatus.SKIPPED_TOO_LARGE,
        None,
        5000,
    )
    assert result.stats.skipped_too_large == 1


# ---- the invariants ------------------------------------------------------------------------------


def test_scanning_changes_nothing_about_any_file_or_directory(tmp_path: Path) -> None:
    """CLAUDE.md invariant 1: size, times, mode, attributes and content are the same after."""
    base = tmp_path / "tree"
    build_tree(base)
    readonly = write(base / "readonly.txt", b"ro")
    readonly.chmod(stat.S_IREAD)
    os.link(base / "a.txt", base / "hard.txt")
    if sys.platform != "win32":
        (base / "sub").chmod(0o750)
        (base / "a.txt").chmod(0o4644)
    before = tree_state(base)
    try:
        for symlinks in (SymlinkPolicy.NEVER, SymlinkPolicy.FILES):
            result = run(base, symlinks=symlinks)
            assert result.complete
            assert len(result.records) >= 9
            assert tree_state(base) == before
    finally:
        readonly.chmod(stat.S_IWRITE | stat.S_IREAD)


@pytest.mark.requires_symlinks
def test_scanning_changes_nothing_with_links_in_the_tree(tmp_path: Path) -> None:
    base = tmp_path / "tree"
    build_tree(base)
    os.symlink(base / "a.txt", base / "filelink")
    os.symlink(base / "sub", base / "dirlink", target_is_directory=True)
    os.symlink(base / "gone", base / "dangling")
    before = tree_state(base)
    for symlinks in (SymlinkPolicy.NEVER, SymlinkPolicy.FILES):
        run(base, symlinks=symlinks)
        assert tree_state(base) == before


def test_the_state_comparison_would_notice_a_change(tmp_path: Path) -> None:
    base = tmp_path / "tree"
    build_tree(base)
    before = tree_state(base)
    (base / "a.txt").write_bytes(b"alpha!")
    assert tree_state(base) != before
    os.utime(base / "a.txt", ns=(NS + 1, NS + 1))
    after_touch = tree_state(base)
    (base / "new").write_bytes(b"")
    assert tree_state(base) != after_touch


def test_the_test_guard_stops_a_scan_of_the_real_repository() -> None:
    with pytest.raises(path_guard.PathGuardError):
        scan(policy_for(root_for(REPO_ROOT)), FakeClock())


# ---- scale ---------------------------------------------------------------------------------------


@pytest.mark.slow
def test_twenty_thousand_files_are_scanned_within_the_limits(tmp_path: Path) -> None:
    base = tmp_path / "big"
    for directory in range(200):
        folder = base / f"d{directory:03d}"
        folder.mkdir(parents=True)
        for number in range(100):
            (folder / f"f{number:03d}.txt").write_bytes(b"%d-%d" % (directory, number))
    result = scan(policy_for(root_for(base)), FakeClock())
    assert result.complete
    assert result.issues == ()
    assert len(result.records) == 20_000 + 200 + 1
    assert result.stats.files == 20_000
    assert result.stats.dirs == 201
    assert len(result.records) <= DEFAULT_LIMITS.max_files
    assert {record.hash_status for record in result.records if record.type is EntryType.FILE} == {
        HashStatus.OK
    }
