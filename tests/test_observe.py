"""fs/observe.py: reading monitored files safely. Real files in tmp_path, plus scripted
descriptors for the failures that cannot be produced reliably on a real filesystem."""

from __future__ import annotations

import errno
import hashlib
import os
import random
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import winhelp
from fim.core.limits import HASH_CHUNK_BYTES
from fim.core.models import HashStatus
from fim.core.pathrules import Flavour, display_link_target
from fim.core.perms import FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT
from fim.fs import observe
from fim.fs.observe import (
    DirListing,
    FsProblem,
    HashResult,
    RawStat,
    ReadOps,
)

FLAVOUR = Flavour.WINDOWS if sys.platform == "win32" else Flavour.POSIX
NS = 1_700_000_000_123_456_700  # a multiple of 100 ns: NTFS keeps no finer time
BIG = 1 << 30


def never_stop() -> bool:
    return False


def write(path: Path, content: bytes, mtime_ns: int = NS) -> Path:
    path.write_bytes(content)
    os.utime(path, ns=(mtime_ns, mtime_ns))
    return path


def expect(path: Path) -> RawStat:
    result = observe.lstat(str(path))
    assert isinstance(result, RawStat)
    return result


def hash_real(path: Path, **overrides: Any) -> HashResult:
    arguments: dict[str, Any] = {"max_bytes": BIG, "should_stop": never_stop}
    arguments.update(overrides)
    return observe.hash_file(str(path), expect(path), **arguments)


# ---- lstat and stat_target -----------------------------------------------------------------------


def test_lstat_reports_the_plain_facts_of_a_file(tmp_path: Path) -> None:
    target = write(tmp_path / "a.txt", b"hello")
    result = expect(target)
    assert stat.S_ISREG(result.st_mode)
    assert (result.size, result.mtime_ns, result.nlink) == (5, NS, 1)
    assert result.ino != 0
    if sys.platform == "win32":
        assert result.uid is None
        assert result.gid is None
        assert result.file_attributes is not None
    else:
        assert result.uid is not None
        assert result.gid is not None
        assert result.file_attributes is None
        assert result.reparse_tag is None


def test_lstat_of_a_directory(tmp_path: Path) -> None:
    result = expect(tmp_path)
    assert stat.S_ISDIR(result.st_mode)


def test_lstat_of_a_missing_path_says_vanished(tmp_path: Path) -> None:
    result = observe.lstat(str(tmp_path / "nope"))
    assert result == FsProblem("ENOENT", vanished=True, denied=False)


def test_a_parent_that_is_a_file_counts_as_vanished_too(tmp_path: Path) -> None:
    write(tmp_path / "f", b"x")
    result = observe.lstat(str(tmp_path / "f" / "child"))
    assert isinstance(result, FsProblem)
    assert result.vanished


def test_a_path_with_a_nul_byte_is_a_problem_not_a_crash(tmp_path: Path) -> None:
    for function in (observe.lstat, observe.stat_target, observe.read_link):
        result = function(str(tmp_path / "a") + "\0b")
        assert result == FsProblem("EINVAL", vanished=False, denied=False)
    assert observe.list_dir(str(tmp_path) + "\0b", 10) == FsProblem("EINVAL", False, False)


def test_stat_target_of_a_missing_path(tmp_path: Path) -> None:
    result = observe.stat_target(str(tmp_path / "nope"))
    assert isinstance(result, FsProblem)
    assert result.vanished


def test_lstat_of_a_hard_link_counts_the_links(tmp_path: Path) -> None:
    first = write(tmp_path / "one", b"x")
    os.link(first, tmp_path / "two")
    assert expect(first).nlink == 2


@pytest.mark.requires_symlinks
def test_lstat_describes_the_link_and_stat_target_the_file(tmp_path: Path) -> None:
    target = write(tmp_path / "target.txt", b"12345")
    link = tmp_path / "link"
    os.symlink(target, link)
    described = expect(link)
    followed = observe.stat_target(str(link))
    assert isinstance(followed, RawStat)
    assert stat.S_ISREG(followed.st_mode)
    assert followed.size == 5
    assert described.size != 5 or not stat.S_ISREG(described.st_mode)
    assert observe.read_link(str(link)) == winhelp.readlink_text(target)  # raw, stored as is
    assert display_link_target(winhelp.readlink_text(target), FLAVOUR) == str(target)


@pytest.mark.requires_symlinks
def test_a_dangling_link_can_be_described_and_read_but_not_followed(tmp_path: Path) -> None:
    link = tmp_path / "dangling"
    os.symlink(tmp_path / "gone", link)
    assert isinstance(observe.lstat(str(link)), RawStat)
    assert observe.read_link(str(link)) == winhelp.readlink_text(tmp_path / "gone")
    assert display_link_target(winhelp.readlink_text(tmp_path / "gone"), FLAVOUR) == str(
        tmp_path / "gone"
    )
    followed = observe.stat_target(str(link))
    assert isinstance(followed, FsProblem)
    assert followed.vanished


def test_read_link_of_something_that_is_not_a_link(tmp_path: Path) -> None:
    write(tmp_path / "f", b"x")
    result = observe.read_link(str(tmp_path / "f"))
    assert isinstance(result, FsProblem)
    assert not result.vanished


@pytest.mark.windows_only
def test_windows_attributes_come_back_as_raw_integers(tmp_path: Path) -> None:
    target = write(tmp_path / "ro.txt", b"x")
    winhelp.set_windows_attributes(target, FILE_ATTRIBUTE_READONLY)
    try:
        attributes = expect(target).file_attributes
        assert attributes is not None
        assert attributes & FILE_ATTRIBUTE_READONLY
    finally:
        winhelp.set_windows_attributes(target, winhelp.FILE_ATTRIBUTE_NORMAL)


@pytest.mark.windows_only
def test_a_junction_is_a_reparse_point_with_its_tag(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    junction = tmp_path / "junction"
    winhelp.make_junction(junction, real)
    result = expect(junction)
    assert result.file_attributes is not None
    assert result.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT
    assert result.reparse_tag == 0xA0000003


# ---- the two branches of _raw, on every OS -------------------------------------------------------


def fake_stat_result(**extra: int) -> Any:
    fields: dict[str, int] = {
        "st_mode": stat.S_IFREG | 0o644,
        "st_size": 7,
        "st_mtime_ns": NS,
        "st_dev": 3,
        "st_ino": 9,
        "st_nlink": 2,
    }
    fields.update(extra)
    return SimpleNamespace(**fields)


def test_raw_on_posix_keeps_the_owner_and_no_windows_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("fim.fs.observe.sys.platform", "linux")
    raw = observe._raw(fake_stat_result(st_uid=1000, st_gid=100))
    assert (raw.uid, raw.gid, raw.file_attributes, raw.reparse_tag) == (1000, 100, None, None)
    assert (raw.size, raw.mtime_ns, raw.dev, raw.ino, raw.nlink) == (7, NS, 3, 9, 2)


def test_raw_on_windows_keeps_attributes_and_no_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("fim.fs.observe.sys.platform", "win32")
    raw = observe._raw(fake_stat_result(st_file_attributes=0x21, st_reparse_tag=0xA000000C))
    assert (raw.uid, raw.gid, raw.file_attributes, raw.reparse_tag) == (
        None,
        None,
        0x21,
        0xA000000C,
    )


# ---- list_dir ------------------------------------------------------------------------------------


def test_list_dir_returns_sorted_names(tmp_path: Path) -> None:
    for name in ("b", "a", "C", "_x", "aa"):
        write(tmp_path / name, b"")
    (tmp_path / "dir").mkdir()
    assert observe.list_dir(str(tmp_path), 100) == DirListing(
        ("C", "_x", "a", "aa", "b", "dir"), truncated=False
    )


def test_list_dir_of_an_empty_directory(tmp_path: Path) -> None:
    assert observe.list_dir(str(tmp_path), 10) == DirListing((), truncated=False)


def test_list_dir_stops_after_the_limit_and_says_so(tmp_path: Path) -> None:
    for number in range(10):
        write(tmp_path / f"f{number}", b"")
    listing = observe.list_dir(str(tmp_path), 4)
    assert isinstance(listing, DirListing)
    assert listing.truncated
    assert len(listing.names) == 4
    assert list(listing.names) == sorted(listing.names)


def test_list_dir_exactly_at_the_limit_is_not_truncated(tmp_path: Path) -> None:
    for number in range(4):
        write(tmp_path / f"f{number}", b"")
    assert observe.list_dir(str(tmp_path), 4) == DirListing(
        ("f0", "f1", "f2", "f3"), truncated=False
    )
    assert observe.list_dir(str(tmp_path), 0) == DirListing((), truncated=True)


def test_list_dir_of_a_missing_directory_and_of_a_file(tmp_path: Path) -> None:
    missing = observe.list_dir(str(tmp_path / "nope"), 10)
    assert isinstance(missing, FsProblem)
    assert missing.vanished
    write(tmp_path / "f", b"")
    not_a_directory = observe.list_dir(str(tmp_path / "f"), 10)
    assert isinstance(not_a_directory, FsProblem)


def test_list_dir_keeps_hostile_names_exactly(tmp_path: Path) -> None:
    name = "a" + chr(0x202E) + "b" + chr(0x200B) + "c"
    write(tmp_path / name, b"")
    listing = observe.list_dir(str(tmp_path), 10)
    assert isinstance(listing, DirListing)
    assert listing.names == (name,)


@pytest.mark.posix_only
def test_list_dir_keeps_a_name_with_an_undecodable_byte(tmp_path: Path) -> None:
    raw_name = os.fsencode(str(tmp_path)) + b"/bad" + bytes([0xFF]) + b"name"
    descriptor = os.open(raw_name, os.O_WRONLY | os.O_CREAT, 0o600)
    os.close(descriptor)
    listing = observe.list_dir(str(tmp_path), 10)
    assert isinstance(listing, DirListing)
    assert listing.names == ("bad" + chr(0xDCFF) + "name",)  # surrogateescape, lossless


@pytest.mark.posix_only
@pytest.mark.requires_non_root
def test_list_dir_of_a_directory_we_may_not_read_is_denied(tmp_path: Path) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0)
    try:
        result = observe.list_dir(str(locked), 10)
    finally:
        locked.chmod(0o700)
    assert result == FsProblem("EACCES", vanished=False, denied=True)


# ---- hash_file on real files ---------------------------------------------------------------------


def test_the_hash_of_a_small_file(tmp_path: Path) -> None:
    target = write(tmp_path / "a", b"hello world")
    result = hash_real(target)
    assert result.status is HashStatus.OK
    assert result.sha256 == hashlib.sha256(b"hello world").hexdigest()
    assert (result.size, result.bytes_read, result.mtime_ns) == (11, 11, NS)
    assert result.error is None
    assert not result.stopped


def test_the_hash_of_an_empty_file(tmp_path: Path) -> None:
    result = hash_real(write(tmp_path / "empty", b""))
    assert result.status is HashStatus.OK
    assert result.sha256 == hashlib.sha256(b"").hexdigest()
    assert result.size == 0


def test_a_file_larger_than_one_chunk_is_hashed_in_full(tmp_path: Path) -> None:
    rng = random.Random(7)
    content = rng.randbytes(2 * HASH_CHUNK_BYTES + 12345)
    result = hash_real(write(tmp_path / "big", content))
    assert result.status is HashStatus.OK
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert result.bytes_read == len(content)


def test_the_size_limit_is_inclusive(tmp_path: Path) -> None:
    target = write(tmp_path / "f", b"x" * 100)
    at_limit = hash_real(target, max_bytes=100)
    assert at_limit.status is HashStatus.OK
    over = hash_real(target, max_bytes=99)
    assert over.status is HashStatus.SKIPPED_TOO_LARGE
    assert over.sha256 is None
    assert over.size == 100
    assert over.bytes_read == 0  # decided from fstat, nothing was read


def test_the_budget_callback_is_asked_between_chunks(tmp_path: Path) -> None:
    content = b"y" * (3 * HASH_CHUNK_BYTES)
    target = write(tmp_path / "f", content)
    asked: list[int] = []

    def stop_after_first_chunk() -> bool:
        asked.append(1)
        return len(asked) > 1

    result = hash_real(target, should_stop=stop_after_first_chunk)
    assert result.stopped
    assert result.sha256 is None
    assert result.bytes_read == HASH_CHUNK_BYTES
    assert len(asked) == 2


def test_a_budget_that_is_already_over_reads_nothing(tmp_path: Path) -> None:
    result = hash_real(write(tmp_path / "f", b"data"), should_stop=lambda: True)
    assert result.stopped
    assert result.bytes_read == 0


def test_a_missing_file_is_vanished(tmp_path: Path) -> None:
    target = write(tmp_path / "f", b"data")
    expected = expect(target)
    target.unlink()
    result = observe.hash_file(str(target), expected, max_bytes=BIG, should_stop=never_stop)
    assert result.status is HashStatus.VANISHED
    assert result.sha256 is None
    assert result.size == expected.size


def test_a_nul_in_the_path_is_unreadable_not_a_crash(tmp_path: Path) -> None:
    expected = expect(write(tmp_path / "f", b"x"))
    result = observe.hash_file(
        str(tmp_path / "f") + "\0", expected, max_bytes=BIG, should_stop=never_stop
    )
    assert result.status is HashStatus.UNREADABLE
    assert result.error == "EINVAL"


def test_a_file_replaced_by_another_during_the_scan_is_unstable(tmp_path: Path) -> None:
    target = write(tmp_path / "f", b"original")
    expected = expect(target)
    replacement = write(tmp_path / "replacement", b"original")  # same size, same mtime
    os.replace(replacement, target)  # a different file now has the name
    result = observe.hash_file(str(target), expected, max_bytes=BIG, should_stop=never_stop)
    assert result.status is HashStatus.UNSTABLE
    assert result.sha256 is None
    assert "replaced" in result.detail


@pytest.mark.requires_symlinks
def test_a_file_replaced_by_a_link_is_unstable_and_the_link_is_not_followed(
    tmp_path: Path,
) -> None:
    target = write(tmp_path / "f", b"original")
    expected = expect(target)
    other = write(tmp_path / "other", b"secret outside")
    target.unlink()
    os.symlink(other, target)
    result = observe.hash_file(str(target), expected, max_bytes=BIG, should_stop=never_stop)
    assert result.status is HashStatus.UNSTABLE
    assert result.sha256 is None


@pytest.mark.requires_symlinks
def test_following_a_link_hashes_the_target_when_asked(tmp_path: Path) -> None:
    other = write(tmp_path / "other", b"through the link")
    link = tmp_path / "link"
    os.symlink(other, link)
    expected = observe.stat_target(str(link))
    assert isinstance(expected, RawStat)
    result = observe.hash_file(
        str(link), expected, max_bytes=BIG, should_stop=never_stop, follow=True
    )
    assert result.status is HashStatus.OK
    assert result.sha256 == hashlib.sha256(b"through the link").hexdigest()


@pytest.mark.posix_only
def test_a_fifo_swapped_in_is_not_read_and_does_not_block(tmp_path: Path) -> None:
    target = write(tmp_path / "f", b"x")
    expected = expect(target)
    target.unlink()
    if sys.platform != "win32":
        os.mkfifo(target)
    result = observe.hash_file(str(target), expected, max_bytes=BIG, should_stop=never_stop)
    assert result.status is HashStatus.UNSTABLE
    assert result.bytes_read == 0


@pytest.mark.posix_only
@pytest.mark.requires_non_root
def test_an_unreadable_file_is_reported_with_its_errno_name(tmp_path: Path) -> None:
    target = write(tmp_path / "secret", b"x")
    expected = expect(target)
    target.chmod(0)
    try:
        result = observe.hash_file(str(target), expected, max_bytes=BIG, should_stop=never_stop)
    finally:
        target.chmod(0o600)
    assert result.status is HashStatus.UNREADABLE
    assert result.error == "EACCES"
    assert result.sha256 is None


# ---- hash_file with scripted descriptors -------------------------------------------------------


class Virtual:
    """The path handed to scripted descriptors; a real name inside tmp_path so the guard passes."""

    path = ""


@pytest.fixture(autouse=True)
def _virtual_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Virtual, "path", str(tmp_path / "scripted-file"))


def raw(**overrides: Any) -> RawStat:
    fields: dict[str, Any] = {
        "st_mode": stat.S_IFREG | 0o644,
        "size": 6,
        "mtime_ns": NS,
        "dev": 1,
        "ino": 7,
        "nlink": 1,
        "uid": None,
        "gid": None,
        "file_attributes": None,
        "reparse_tag": None,
    }
    fields.update(overrides)
    return RawStat(**fields)


@dataclass
class Attempt:
    """What one open/fstat/read/fstat/close sequence returns."""

    content: bytes
    before: RawStat
    after: RawStat | None = None


@dataclass
class Script:
    attempts: list[Attempt]
    open_error: BaseException | None = None
    read_error: BaseException | None = None
    opened: list[tuple[str, bool]] = field(default_factory=list)
    closed: int = 0
    reads: int = 0
    _attempt: int = -1
    _position: int = 0
    _fstat_calls: int = 0

    def ops(self) -> ReadOps:
        return ReadOps(open_fd=self._open, fstat=self._fstat, read=self._read, close=self._close)

    def _open(self, path: str, follow: bool) -> int:
        self.opened.append((path, follow))
        if self.open_error is not None:
            raise self.open_error
        self._attempt += 1
        self._position = 0
        self._fstat_calls = 0
        return 100 + self._attempt

    def _fstat(self, descriptor: int) -> RawStat:
        current = self.attempts[min(self._attempt, len(self.attempts) - 1)]
        self._fstat_calls += 1
        if self._fstat_calls == 1:
            return current.before
        return current.after if current.after is not None else current.before

    def _read(self, descriptor: int, size: int) -> bytes:
        self.reads += 1
        if self.read_error is not None:
            raise self.read_error
        current = self.attempts[min(self._attempt, len(self.attempts) - 1)]
        chunk = current.content[self._position : self._position + min(size, 4)]
        self._position += len(chunk)
        return chunk

    def _close(self, descriptor: int) -> None:
        self.closed += 1


def run(script: Script, expected: RawStat | None = None, **overrides: Any) -> HashResult:
    arguments: dict[str, Any] = {"max_bytes": BIG, "should_stop": never_stop, "ops": script.ops()}
    arguments.update(overrides)
    return observe.hash_file(Virtual.path, expected if expected is not None else raw(), **arguments)


DIGEST = hashlib.sha256(b"abcdef").hexdigest()


def test_scripted_happy_path_reads_in_small_pieces_and_closes() -> None:
    script = Script([Attempt(b"abcdef", raw())])
    result = run(script)
    assert result.status is HashStatus.OK
    assert result.sha256 == DIGEST
    assert script.reads == 3  # "abcd", "ef", then the empty read that ends the file
    assert script.closed == 1
    assert script.opened == [(Virtual.path, False)]


def test_follow_is_passed_to_the_open() -> None:
    script = Script([Attempt(b"abcdef", raw())])
    run(script, follow=True)
    assert script.opened == [(Virtual.path, True)]


def test_a_change_during_the_read_is_retried_once_and_the_second_pass_wins() -> None:
    first = Attempt(b"abcdef", raw(), after=raw(size=9))
    second = Attempt(b"abcdef", raw())
    script = Script([first, second])
    result = run(script)
    assert result.status is HashStatus.OK
    assert result.sha256 == DIGEST
    assert len(script.opened) == 2
    assert script.closed == 2


def test_a_modification_time_change_alone_also_counts_as_a_change() -> None:
    first = Attempt(b"abcdef", raw(), after=raw(mtime_ns=NS + 1))
    second = Attempt(b"abcdef", raw())
    assert run(Script([first, second])).status is HashStatus.OK


def test_fewer_bytes_than_the_size_says_counts_as_a_change() -> None:
    truncated = Attempt(b"abc", raw())  # fstat says 6 bytes, only 3 can be read
    script = Script([truncated])
    result = run(script)
    assert result.status is HashStatus.UNSTABLE
    assert "changed while being hashed" in result.detail
    assert len(script.opened) == 2  # one retry
    assert script.closed == 2


def test_two_changed_passes_in_a_row_are_unstable_and_give_no_hash() -> None:
    changing = Attempt(b"abcdef", raw(), after=raw(size=7))
    script = Script([changing, changing])
    result = run(script)
    assert result.status is HashStatus.UNSTABLE
    assert result.sha256 is None
    assert len(script.opened) == 2


def test_a_file_that_is_a_different_inode_is_unstable_without_a_retry() -> None:
    script = Script([Attempt(b"abcdef", raw(ino=99))])
    result = run(script)
    assert result.status is HashStatus.UNSTABLE
    assert "replaced" in result.detail
    assert len(script.opened) == 1
    assert script.reads == 0
    assert script.closed == 1


def test_a_different_device_is_unstable() -> None:
    assert run(Script([Attempt(b"x", raw(dev=2))])).status is HashStatus.UNSTABLE


@pytest.mark.parametrize("mode", [stat.S_IFIFO | 0o600, stat.S_IFDIR | 0o755, stat.S_IFCHR | 0o600])
def test_a_descriptor_that_is_not_a_regular_file_is_never_read(mode: int) -> None:
    script = Script([Attempt(b"x", raw(st_mode=mode))])
    result = run(script)
    assert result.status is HashStatus.UNSTABLE
    assert script.reads == 0


def test_a_file_that_grew_past_the_limit_before_it_was_read_is_too_large() -> None:
    script = Script([Attempt(b"abcdef", raw(size=500))])
    result = run(script, max_bytes=100)
    assert result.status is HashStatus.SKIPPED_TOO_LARGE
    assert result.size == 500
    assert script.reads == 0


def test_a_file_that_grows_past_the_limit_while_reading_is_too_large_and_unhashed() -> None:
    script = Script([Attempt(b"abcdefghij", raw(size=6))])  # fstat claims 6, the file keeps going
    result = run(script, max_bytes=6)
    assert result.status is HashStatus.SKIPPED_TOO_LARGE
    assert result.sha256 is None
    assert result.size > 6
    assert "grew" in result.detail


def test_the_stop_callback_ends_a_scripted_read_without_a_hash() -> None:
    calls: list[int] = []

    def stop() -> bool:
        calls.append(1)
        return len(calls) == 2

    script = Script([Attempt(b"abcdef", raw())])
    result = run(script, should_stop=stop)
    assert result.stopped
    assert result.sha256 is None
    assert result.bytes_read == 4
    assert script.closed == 1


@pytest.mark.parametrize(
    ("error", "status", "errno_name"),
    [
        (FileNotFoundError(errno.ENOENT, "gone"), HashStatus.VANISHED, None),
        (PermissionError(errno.EACCES, "denied"), HashStatus.UNREADABLE, "EACCES"),
        (OSError(errno.ELOOP, "loop"), HashStatus.UNSTABLE, None),
        (OSError(errno.EIO, "io"), HashStatus.UNREADABLE, "EIO"),
        (OSError(), HashStatus.UNREADABLE, "UNKNOWN"),
        (ValueError("embedded null byte"), HashStatus.UNREADABLE, "EINVAL"),
    ],
)
def test_every_open_failure_becomes_a_status_never_an_exception(
    error: BaseException, status: HashStatus, errno_name: str | None
) -> None:
    script = Script([], open_error=error)
    result = run(script)
    assert result.status is status
    assert result.error == errno_name
    assert result.sha256 is None
    assert script.closed == 0  # nothing was opened, nothing to close


@pytest.mark.parametrize(
    ("error", "status", "errno_name"),
    [
        (FileNotFoundError(errno.ENOENT, "gone"), HashStatus.VANISHED, None),
        (OSError(errno.EIO, "io"), HashStatus.UNREADABLE, "EIO"),
        (PermissionError(errno.EACCES, "denied"), HashStatus.UNREADABLE, "EACCES"),
    ],
)
def test_a_failure_while_reading_becomes_a_status_and_the_descriptor_is_closed(
    error: BaseException, status: HashStatus, errno_name: str | None
) -> None:
    script = Script([Attempt(b"abcdef", raw())], read_error=error)
    result = run(script)
    assert result.status is status
    assert result.error == errno_name
    assert script.closed == 1


def test_the_scripted_result_carries_the_size_and_time_of_the_final_stat() -> None:
    result = run(Script([Attempt(b"abcdef", raw(size=6, mtime_ns=NS + 5))]), raw(mtime_ns=NS))
    assert result.mtime_ns == NS + 5
    assert result.size == 6


# ---- the real open flags, checked on every OS by substituting os.open ----------------------------


class _Opens:
    def __init__(self, refuse_noatime: bool = False) -> None:
        self.calls: list[int] = []
        self.refuse_noatime = refuse_noatime

    def __call__(self, path: str, flags: int) -> int:
        self.calls.append(flags)
        if self.refuse_noatime and flags & NOATIME:
            raise PermissionError(errno.EPERM, "not the owner")
        return 42


O_RDONLY, O_NONBLOCK, O_CLOEXEC, O_NOFOLLOW, NOATIME, O_BINARY = 0, 0x4, 0x8, 0x10, 0x20, 0x40


@pytest.fixture
def posix_flags(monkeypatch: pytest.MonkeyPatch) -> Callable[[str, bool], _Opens]:
    """Pretend to be a POSIX system with known flag values and a recording os.open."""

    def install(platform: str, refuse_noatime: bool) -> _Opens:
        opens = _Opens(refuse_noatime)
        monkeypatch.setattr("fim.fs.observe.sys.platform", platform)
        monkeypatch.setattr("fim.fs.observe.os.open", opens)
        for name, value in (
            ("O_RDONLY", O_RDONLY),
            ("O_NONBLOCK", O_NONBLOCK),
            ("O_CLOEXEC", O_CLOEXEC),
            ("O_NOFOLLOW", O_NOFOLLOW),
            ("O_NOATIME", NOATIME),
            ("O_BINARY", O_BINARY),
        ):
            monkeypatch.setattr(f"fim.fs.observe.os.{name}", value, raising=False)
        return opens

    return install


def test_linux_opens_read_only_without_following_links_and_without_touching_atime(
    posix_flags: Callable[[str, bool], _Opens],
) -> None:
    opens = posix_flags("linux", False)
    assert observe._open_readonly("p", False) == 42
    assert opens.calls == [O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW | NOATIME]


def test_following_links_drops_nofollow(posix_flags: Callable[[str, bool], _Opens]) -> None:
    opens = posix_flags("linux", False)
    observe._open_readonly("p", True)
    assert opens.calls == [O_RDONLY | O_NONBLOCK | O_CLOEXEC | NOATIME]


def test_noatime_that_is_refused_falls_back_to_a_plain_read_only_open(
    posix_flags: Callable[[str, bool], _Opens],
) -> None:
    opens = posix_flags("linux", True)
    assert observe._open_readonly("p", False) == 42
    assert opens.calls == [
        O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW | NOATIME,
        O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW,
    ]


def test_other_posix_systems_do_not_ask_for_noatime(
    posix_flags: Callable[[str, bool], _Opens],
) -> None:
    opens = posix_flags("darwin", False)
    observe._open_readonly("p", False)
    assert opens.calls == [O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW]


def test_windows_opens_binary_and_read_only(posix_flags: Callable[[str, bool], _Opens]) -> None:
    opens = posix_flags("win32", False)
    observe._open_readonly("p", False)
    assert opens.calls == [O_RDONLY | O_BINARY]


def test_no_open_flag_can_write() -> None:
    for name in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND", "O_EXCL"):
        assert name not in vars(observe)
    source = Path(observe.__file__).read_text(encoding="utf-8")
    for name in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND", "O_EXCL"):
        assert name not in source


def test_the_system_operations_are_the_real_ones(tmp_path: Path) -> None:
    ops = observe.system_read_ops()
    target = write(tmp_path / "f", b"abc")
    descriptor = ops.open_fd(str(target), False)
    try:
        assert ops.fstat(descriptor).size == 3
        assert ops.read(descriptor, 10) == b"abc"
        assert ops.read(descriptor, 10) == b""
    finally:
        ops.close(descriptor)
    ops.close(descriptor)  # closing twice is swallowed
    with pytest.raises(FileNotFoundError):
        ops.open_fd(str(tmp_path / "missing"), False)


def test_the_scripted_result_replace_helper_is_not_shared_state() -> None:
    first = raw()
    assert replace(first, size=1).size == 1
    assert first.size == 6
