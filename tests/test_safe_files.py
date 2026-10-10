"""fs/safe_files.py: the only module that reads and writes the tool's own files (CLAUDE.md
invariants 2 and 3, PLAN.md section 1.4).

The path guard (tests/path_guard.py) wraps the public functions, so a call with a path outside
the pytest temporary directory fails; refusals of hostile paths are tested through ``__wrapped__``,
which is the same function without the guard.
"""

from __future__ import annotations

import errno
import os
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import winhelp
from fim.core.errors import ExitCode, FileAccessError, FileMissingError, PathRuleError
from fim.fs import safe_files
from fim.fs.safe_files import FileTooLargeError

# Imported before any test runs, so these are the functions without the path guard.
RAW_READ = safe_files.read_own_file
RAW_WRITE = safe_files.write_own_file
RAW_ENSURE = safe_files.ensure_can_write


def read_file(*args: Any, **kwargs: Any) -> bytes:
    """Looked up at call time, so the path guard installed by conftest is in force."""
    return safe_files.read_own_file(*args, **kwargs)


def write_file(*args: Any, **kwargs: Any) -> None:
    safe_files.write_own_file(*args, **kwargs)


IS_WINDOWS = sys.platform == "win32"


def record_call(calls: list[str], name: str, real: Callable[..., Any]) -> Callable[..., Any]:
    """``real`` wrapped so that every call is noted in ``calls`` first."""

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        calls.append(name)
        return real(*args, **kwargs)

    return wrapper


def raising(error: BaseException) -> Callable[..., Any]:
    """A function that raises ``error`` whatever it is called with."""

    def fail(*_args: Any, **_kwargs: Any) -> Any:
        raise error

    return fail


def names(directory: Path) -> list[str]:
    return sorted(entry.name for entry in directory.iterdir())


class FakeStat:
    """A stat result with some fields replaced."""

    def __init__(self, real: os.stat_result, **overrides: Any) -> None:
        self._real = real
        self.__dict__.update(overrides)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


# ---- reading -------------------------------------------------------------------------------------


def test_reads_the_whole_file(tmp_path: Path) -> None:
    target = tmp_path / "k"
    target.write_bytes(b"abc\n")
    assert read_file(str(target), max_bytes=100) == b"abc\n"


def test_reads_an_empty_file(tmp_path: Path) -> None:
    target = tmp_path / "empty"
    target.write_bytes(b"")
    assert read_file(str(target), max_bytes=1) == b""


def test_reads_a_file_larger_than_one_chunk(tmp_path: Path) -> None:
    data = bytes(range(256)) * 9000  # more than HASH_CHUNK_BYTES (1 MiB)
    target = tmp_path / "big"
    target.write_bytes(data)
    assert read_file(str(target), max_bytes=len(data)) == data


def test_a_missing_file_is_file_missing_error_with_exit_2(tmp_path: Path) -> None:
    with pytest.raises(FileMissingError) as raised:
        read_file(str(tmp_path / "nope"), max_bytes=10, label="baseline file")
    assert raised.value.exit_code == ExitCode.ERROR
    assert "baseline file" in raised.value.message
    assert "does not exist" in raised.value.message


def test_a_directory_is_not_a_regular_file(tmp_path: Path) -> None:
    with pytest.raises(FileAccessError, match="not a regular file"):
        read_file(str(tmp_path), max_bytes=10)


def test_a_file_over_the_cap_is_refused_before_any_byte_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "big"
    target.write_bytes(b"x" * 11)

    def forbidden(*_args: Any) -> bytes:
        raise AssertionError("read after the size check should have refused")

    monkeypatch.setattr("fim.fs.safe_files.os.read", forbidden)
    with pytest.raises(FileTooLargeError, match="larger than 10 bytes"):
        read_file(str(target), max_bytes=10)


def test_a_file_exactly_at_the_cap_is_read(tmp_path: Path) -> None:
    target = tmp_path / "exact"
    target.write_bytes(b"x" * 10)
    assert read_file(str(target), max_bytes=10) == b"x" * 10
    target.write_bytes(b"x" * 11)
    with pytest.raises(FileTooLargeError):
        read_file(str(target), max_bytes=10)


def test_a_file_that_grows_after_the_size_check_is_still_capped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "growing"
    target.write_bytes(b"x" * 50)
    real_fstat = os.fstat

    def small(descriptor: int) -> Any:
        return FakeStat(real_fstat(descriptor), st_size=5)

    monkeypatch.setattr("fim.fs.safe_files.os.fstat", small)
    with pytest.raises(FileTooLargeError):
        read_file(str(target), max_bytes=10)


def test_too_large_is_a_file_access_error_with_exit_2() -> None:
    assert issubclass(FileTooLargeError, FileAccessError)
    assert FileTooLargeError("x").exit_code == ExitCode.ERROR


def test_a_path_swapped_between_lstat_and_open_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "k"
    target.write_bytes(b"abc")
    real_fstat = os.fstat
    monkeypatch.setattr(
        "fim.fs.safe_files.os.fstat",
        lambda descriptor: FakeStat(
            real_fstat(descriptor), st_ino=real_fstat(descriptor).st_ino + 1
        ),
    )
    with pytest.raises(FileAccessError, match="replaced while it was being opened"):
        read_file(str(target), max_bytes=10)


def test_an_opened_reparse_point_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "k"
    target.write_bytes(b"abc")
    real_fstat = os.fstat
    monkeypatch.setattr(
        "fim.fs.safe_files.os.fstat",
        lambda d: FakeStat(real_fstat(d), st_file_attributes=0x400, st_reparse_tag=0xA0000003),
    )
    with pytest.raises(FileAccessError, match="replaced while it was being opened"):
        read_file(str(target), max_bytes=10)


def test_a_special_file_swapped_in_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "k"
    target.write_bytes(b"abc")
    real_fstat = os.fstat
    monkeypatch.setattr(
        "fim.fs.safe_files.os.fstat",
        lambda d: FakeStat(real_fstat(d), st_mode=stat.S_IFIFO | 0o600),
    )
    with pytest.raises(FileAccessError, match="not a regular file"):
        read_file(str(target), max_bytes=10)


def test_an_open_failure_is_a_file_access_error_with_the_errno_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "k"
    target.write_bytes(b"abc")
    real_open = os.open

    def deny(path: str, flags: int, *rest: Any) -> int:
        if str(path) == str(target):
            raise PermissionError(errno.EACCES, "denied")
        return real_open(path, flags, *rest)

    monkeypatch.setattr("fim.fs.safe_files.os.open", deny)
    with pytest.raises(FileAccessError, match=r"could not be opened \(EACCES\)"):
        read_file(str(target), max_bytes=10)


def test_a_read_failure_is_a_file_access_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "k"
    target.write_bytes(b"abc")

    def fail(*_args: Any) -> bytes:
        raise OSError(errno.EIO, "io")

    monkeypatch.setattr("fim.fs.safe_files.os.read", fail)
    with pytest.raises(FileAccessError, match=r"could not be read \(EIO\)"):
        read_file(str(target), max_bytes=10)


def test_a_lstat_failure_other_than_missing_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "k"
    target.write_bytes(b"abc")
    real_lstat = os.lstat

    def fail(path: Any, *a: Any, **k: Any) -> Any:
        if str(path) == str(target):
            raise PermissionError(errno.EACCES, "denied")
        return real_lstat(path, *a, **k)

    monkeypatch.setattr("fim.fs.safe_files.os.lstat", fail)
    with pytest.raises(FileAccessError, match=r"could not be examined \(EACCES\)"):
        read_file(str(target), max_bytes=10)


# ---- links and reparse points --------------------------------------------------------------------


@pytest.mark.requires_symlinks
def test_a_symlink_to_a_file_is_not_read(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.write_bytes(b"secret")
    link = tmp_path / "link"
    os.symlink(real, link)
    with pytest.raises(FileAccessError, match="symbolic link or reparse point"):
        read_file(str(link), max_bytes=100)


@pytest.mark.requires_symlinks
def test_a_dangling_symlink_is_refused_as_a_link_not_as_missing(tmp_path: Path) -> None:
    link = tmp_path / "dangling"
    os.symlink(tmp_path / "gone", link)
    with pytest.raises(FileAccessError, match="symbolic link or reparse point"):
        read_file(str(link), max_bytes=100)


@pytest.mark.requires_symlinks
def test_writing_never_goes_through_a_symlink_even_with_force(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.write_bytes(b"original")
    link = tmp_path / "link"
    os.symlink(real, link)
    for force in (False, True):
        with pytest.raises(FileAccessError, match="symbolic link or reparse point"):
            write_file(str(link), b"evil", force=force)
    assert real.read_bytes() == b"original"
    assert link.is_symlink()
    assert names(tmp_path) == ["link", "real"]


@pytest.mark.requires_symlinks
def test_writing_to_a_dangling_symlink_does_not_create_its_target(tmp_path: Path) -> None:
    target = tmp_path / "not-yet"
    link = tmp_path / "link"
    os.symlink(target, link)
    with pytest.raises(FileAccessError, match="symbolic link or reparse point"):
        write_file(str(link), b"evil", force=True)
    assert not target.exists()


@pytest.mark.windows_only
def test_a_junction_is_refused_for_reading_and_writing(tmp_path: Path) -> None:
    real = tmp_path / "realdir"
    real.mkdir()
    junction = tmp_path / "junction"
    winhelp.make_junction(junction, real)
    with pytest.raises(FileAccessError, match="symbolic link or reparse point"):
        read_file(str(junction), max_bytes=10)
    for force in (False, True):
        with pytest.raises(FileAccessError, match="symbolic link or reparse point"):
            write_file(str(junction), b"x", force=force)
    assert names(real) == []


# ---- path rules ----------------------------------------------------------------------------------

BOTH_OS = [
    "http://example.com/x",
    "https://host/key",
    "file:///etc/passwd",
    "FILE:x",
    "a/../b",
    "..",
    "",
    "bad\x00name",
    "bad\x1b[31mname",
    "bad\u202ename",
    "bad\nname",
]
WINDOWS_ONLY = [
    "\\\\server\\share\\k",
    "\\\\?\\C:\\k",
    "\\\\.\\COM1",
    "C:k",
    "C:\\dir\\CON",
    "C:\\dir\\nul.txt",
    "C:\\dir\\k.txt:stream",
    "\\\\?\\UNC\\server\\share\\k",
    "\\??\\C:\\k",
    "\\k",
    "C:\\dir\\k.",
    "C:\\dir\\k ",
    'C:\\dir\\k"x',
]
POSIX_ONLY = ["\\\\server\\share", "C:\\x", "c:foo"]


@pytest.mark.parametrize("raw", BOTH_OS + (WINDOWS_ONLY if IS_WINDOWS else POSIX_ONLY))
def test_hostile_and_unsupported_paths_are_refused_everywhere(raw: str) -> None:
    with pytest.raises(PathRuleError):
        RAW_READ(raw, max_bytes=10)
    with pytest.raises(PathRuleError):
        RAW_WRITE(raw, b"x", force=True)
    with pytest.raises(PathRuleError):
        RAW_ENSURE(raw, force=True)


def test_a_non_text_path_is_refused() -> None:
    with pytest.raises(PathRuleError):
        RAW_READ(b"/x", max_bytes=1)  # type: ignore[arg-type]  # the wrong type is the test


def test_refusals_never_touch_the_filesystem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("the filesystem was touched for a refused path")

    for name in ("open", "lstat", "link", "replace", "unlink"):
        monkeypatch.setattr(f"fim.fs.safe_files.os.{name}", forbidden)
    for raw in ("http://example.com/x", "a/../b", ""):
        with pytest.raises(PathRuleError):
            RAW_WRITE(raw, b"x", force=True)
        with pytest.raises(PathRuleError):
            RAW_READ(raw, max_bytes=1)


def test_the_refusal_message_shows_the_path_escaped() -> None:
    with pytest.raises(PathRuleError) as raised:
        RAW_READ("bad\x1b[31mname", max_bytes=10)
    assert "\x1b" not in raised.value.message


# ---- files inside a monitored root ---------------------------------------------------------------


def test_a_file_inside_a_monitored_root_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "watched"
    root.mkdir()
    inside = root / "sub" / "fim.key"
    inside.parent.mkdir()
    for call in (
        lambda: write_file(str(inside), b"x", force=True, avoid_roots=[str(root)]),
        lambda: read_file(str(inside), max_bytes=10, avoid_roots=[str(root)]),
        lambda: safe_files.ensure_can_write(str(inside), force=True, avoid_roots=[str(root)]),
    ):
        with pytest.raises(PathRuleError, match="must not be inside a monitored path"):
            call()
    assert names(inside.parent) == []


def test_the_root_itself_and_a_direct_child_are_inside(tmp_path: Path) -> None:
    root = tmp_path / "watched"
    root.mkdir()
    with pytest.raises(PathRuleError):
        write_file(str(root), b"x", force=True, avoid_roots=[str(root)])
    with pytest.raises(PathRuleError):
        write_file(str(root / "k"), b"x", force=True, avoid_roots=[str(root)])


def test_a_sibling_with_the_same_prefix_is_not_inside(tmp_path: Path) -> None:
    root = tmp_path / "watched"
    root.mkdir()
    sibling = tmp_path / "watched-keys"
    sibling.mkdir()
    write_file(str(sibling / "k"), b"x", force=False, avoid_roots=[str(root)])
    assert (sibling / "k").read_bytes() == b"x"


def test_a_relative_path_is_compared_by_its_absolute_form(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "watched"
    root.mkdir()
    monkeypatch.chdir(root)
    with pytest.raises(PathRuleError, match="must not be inside"):
        write_file("k", b"x", force=True, avoid_roots=[str(root)])
    assert names(root) == []


@pytest.mark.windows_only
def test_root_comparison_ignores_case_on_windows(tmp_path: Path) -> None:
    root = tmp_path / "Watched"
    root.mkdir()
    with pytest.raises(PathRuleError):
        write_file(str(root / "k").upper(), b"x", force=True, avoid_roots=[str(root).lower()])


@pytest.mark.requires_symlinks
def test_a_path_reached_through_a_link_into_a_root_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "watched"
    root.mkdir()
    alias = tmp_path / "alias"
    os.symlink(root, alias, target_is_directory=True)
    with pytest.raises(PathRuleError, match="must not be inside"):
        write_file(str(alias / "k"), b"x", force=True, avoid_roots=[str(root)])
    assert names(root) == []


def test_several_roots_are_all_checked(tmp_path: Path) -> None:
    first, second = tmp_path / "one", tmp_path / "two"
    first.mkdir()
    second.mkdir()
    with pytest.raises(PathRuleError):
        write_file(str(second / "k"), b"x", force=True, avoid_roots=[str(first), str(second)])


# ---- writing -------------------------------------------------------------------------------------


def test_writes_the_data_and_leaves_no_temporary_file(tmp_path: Path) -> None:
    target = tmp_path / "out.bin"
    write_file(str(target), b"payload", force=False)
    assert target.read_bytes() == b"payload"
    assert names(tmp_path) == ["out.bin"]


def test_writes_empty_and_large_data(tmp_path: Path) -> None:
    write_file(str(tmp_path / "empty"), b"", force=False)
    data = os.urandom(3 * 1024 * 1024)
    write_file(str(tmp_path / "big"), data, force=False)
    assert (tmp_path / "empty").read_bytes() == b""
    assert (tmp_path / "big").read_bytes() == data


def test_refuses_to_overwrite_without_force_and_keeps_the_old_content(tmp_path: Path) -> None:
    target = tmp_path / "out"
    target.write_bytes(b"old")
    with pytest.raises(FileAccessError, match="already exists; use --force") as raised:
        write_file(str(target), b"new", force=False, label="baseline file")
    assert "baseline file" in raised.value.message
    assert target.read_bytes() == b"old"
    assert names(tmp_path) == ["out"]


def test_force_replaces_an_existing_file(tmp_path: Path) -> None:
    target = tmp_path / "out"
    target.write_bytes(b"old")
    write_file(str(target), b"new", force=True)
    assert target.read_bytes() == b"new"
    assert names(tmp_path) == ["out"]


def test_a_directory_in_the_way_is_refused_even_with_force(tmp_path: Path) -> None:
    (tmp_path / "out").mkdir()
    with pytest.raises(FileAccessError, match="not a regular file"):
        write_file(str(tmp_path / "out"), b"x", force=True)


def test_a_missing_parent_directory_is_an_error_and_creates_nothing(tmp_path: Path) -> None:
    with pytest.raises(FileAccessError, match="could not be created"):
        write_file(str(tmp_path / "nodir" / "out"), b"x", force=False)
    assert names(tmp_path) == []


def test_no_clobber_uses_a_hard_link_and_force_uses_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    real_link, real_replace = os.link, os.replace
    monkeypatch.setattr("fim.fs.safe_files.os.link", record_call(calls, "link", real_link))
    monkeypatch.setattr("fim.fs.safe_files.os.replace", record_call(calls, "replace", real_replace))
    write_file(str(tmp_path / "one"), b"x", force=False)
    write_file(str(tmp_path / "one"), b"y", force=True)
    assert calls == ["link", "replace"]


def test_a_file_created_after_the_check_is_not_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The check-then-write race: someone creates the target between the check and the publish."""
    target = tmp_path / "out"
    real_link = os.link

    def racing_link(source: str, destination: str) -> None:
        Path(destination).write_bytes(b"someone else")
        real_link(source, destination)  # now raises FileExistsError

    monkeypatch.setattr("fim.fs.safe_files.os.link", racing_link)
    with pytest.raises(FileAccessError, match="already exists; use --force"):
        write_file(str(target), b"mine", force=False)
    assert target.read_bytes() == b"someone else"
    assert names(tmp_path) == ["out"]


def test_partial_writes_are_completed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real_write = os.write
    monkeypatch.setattr(
        "fim.fs.safe_files.os.write", lambda fd, data: real_write(fd, bytes(data[:3]))
    )
    write_file(str(tmp_path / "out"), b"abcdefghij", force=False)
    assert (tmp_path / "out").read_bytes() == b"abcdefghij"


@pytest.mark.parametrize(
    ("function", "force"),
    [("write", False), ("fsync", False), ("link", False), ("replace", True)],
)
def test_the_temporary_file_is_removed_when_a_step_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, function: str, force: bool
) -> None:
    def fail(*_a: Any, **_k: Any) -> Any:
        raise OSError(errno.ENOSPC, "no space")

    monkeypatch.setattr(f"fim.fs.safe_files.os.{function}", fail)
    with pytest.raises(FileAccessError, match="ENOSPC"):
        write_file(str(tmp_path / "out"), b"data", force=force)
    assert names(tmp_path) == []


def test_a_failed_force_write_keeps_the_old_file_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "out"
    target.write_bytes(b"old")
    monkeypatch.setattr("fim.fs.safe_files.os.replace", raising(OSError(errno.EIO, "x")))
    with pytest.raises(FileAccessError):
        write_file(str(target), b"new", force=True)
    assert target.read_bytes() == b"old"
    assert names(tmp_path) == ["out"]


# errno values mean the same thing everywhere, so these run on every OS.
NO_LINK_ERRORS = [
    OSError(errno.EPERM, "operation not permitted"),
    OSError(errno.ENOTSUP, "not supported"),
    OSError(errno.EOPNOTSUPP, "not supported"),
    OSError(errno.ENOSYS, "not implemented"),
    OSError(errno.EINVAL, "invalid"),
    OSError(errno.EMLINK, "too many links"),
]
NO_LINK_WINERRORS = [1, 50]  # ERROR_INVALID_FUNCTION (exFAT), ERROR_NOT_SUPPORTED (redirectors)


def only_winerror(code: int) -> OSError:
    """An error whose only sign of "no hard links" is a ``winerror`` attribute.

    The 4th constructor argument is honoured on Windows only (POSIX ignores it, so the literal
    ``OSError(0, "x", None, 1)`` is a different error on each OS: on Windows its errno becomes
    EINVAL). A class attribute is the same on every OS, and errno EIO is no reason to fall back.
    """

    class WinerrorOnlyError(OSError):
        winerror = code

    return WinerrorOnlyError(errno.EIO, "carries only a winerror")


@pytest.mark.parametrize("error", NO_LINK_ERRORS)
def test_without_hard_links_the_file_is_created_directly_and_exclusively(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: OSError
) -> None:
    assert_fallback_creates_the_file_exclusively(tmp_path, monkeypatch, error)


@pytest.mark.windows_only
@pytest.mark.parametrize("code", NO_LINK_WINERRORS)
def test_on_windows_a_winerror_for_no_hard_links_falls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    assert_fallback_creates_the_file_exclusively(tmp_path, monkeypatch, only_winerror(code))
    # The way a real exFAT volume reports it: the constructor form, errno derived by Python.
    assert_fallback_creates_the_file_exclusively(
        tmp_path / "again", monkeypatch, OSError(0, "function is not valid", None, code)
    )


@pytest.mark.posix_only
@pytest.mark.parametrize("code", NO_LINK_WINERRORS)
def test_on_posix_a_winerror_alone_is_not_a_reason_to_fall_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    """The exact shape that failed on Linux CI, and its attribute form: they must raise."""
    for error in (only_winerror(code), OSError(0, "function is not valid", None, code)):
        monkeypatch.setattr("fim.fs.safe_files.os.link", raising(error))
        with pytest.raises(FileAccessError, match="could not be published"):
            write_file(str(tmp_path / "out"), b"d", force=False)
        assert names(tmp_path) == []


@pytest.mark.parametrize(("platform", "expected"), [("win32", True), ("linux", False)])
@pytest.mark.parametrize("code", NO_LINK_WINERRORS)
def test_winerror_codes_are_read_only_on_windows(
    monkeypatch: pytest.MonkeyPatch, platform: str, expected: bool, code: int
) -> None:
    """The decision itself, on every OS, with the platform substituted."""
    monkeypatch.setattr(sys, "platform", platform)
    assert safe_files._hard_links_unsupported(only_winerror(code)) is expected


@pytest.mark.parametrize("platform", ["win32", "linux"])
def test_errno_codes_count_on_every_platform_and_other_codes_never(
    monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    monkeypatch.setattr(sys, "platform", platform)
    for error in NO_LINK_ERRORS:
        assert safe_files._hard_links_unsupported(error) is True
    for code in (5, 32, 183):  # access denied, sharing violation, already exists
        assert safe_files._hard_links_unsupported(only_winerror(code)) is False
    assert safe_files._hard_links_unsupported(OSError(errno.EIO, "io")) is False


def assert_fallback_creates_the_file_exclusively(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: OSError
) -> None:
    tmp_path.mkdir(exist_ok=True)
    calls: list[str] = []
    real_open = os.open

    def spy(path: str, flags: int, mode: int = 0o777, **k: Any) -> int:
        calls.append(f"open:{Path(path).name}:{bool(flags & os.O_EXCL)}")
        return real_open(path, flags, mode, **k)

    monkeypatch.setattr("fim.fs.safe_files.os.link", raising(error))
    monkeypatch.setattr("fim.fs.safe_files.os.open", spy)
    write_file(str(tmp_path / "out"), b"payload", force=False)
    assert (tmp_path / "out").read_bytes() == b"payload"
    assert names(tmp_path) == ["out"]  # no temporary file left behind
    final = [call for call in calls if call.startswith("open:out")]
    assert final == ["open:out:True"]  # created with O_EXCL at the final path


def test_the_fallback_is_still_no_clobber(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The target appears between the check and the fallback: it must not be overwritten."""
    target = tmp_path / "out"

    def no_links_but_someone_creates_the_target(source: str, destination: str) -> None:
        Path(destination).write_bytes(b"someone else")
        raise OSError(errno.EPERM, "operation not permitted")

    monkeypatch.setattr("fim.fs.safe_files.os.link", no_links_but_someone_creates_the_target)
    with pytest.raises(FileAccessError, match="already exists; use --force"):
        write_file(str(target), b"mine", force=False)
    assert target.read_bytes() == b"someone else"
    assert names(tmp_path) == ["out"]


def test_the_fallback_creates_the_file_with_the_same_flags_as_the_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """So on POSIX it also has O_NOFOLLOW (a link planted at the target is not followed)."""
    seen: dict[str, int] = {}
    real_open = os.open

    def spy(path: str, flags: int, mode: int = 0o777, **k: Any) -> int:
        seen[Path(path).name.split(".")[0] or "temp"] = flags
        return real_open(path, flags, mode, **k)

    monkeypatch.setattr("fim.fs.safe_files.os.link", raising(OSError(errno.EPERM, "x")))
    monkeypatch.setattr("fim.fs.safe_files.os.open", spy)
    write_file(str(tmp_path / "out"), b"d", force=False)
    assert seen["out"] == seen["temp"] == safe_files._write_flags()
    assert seen["out"] & os.O_EXCL


def test_a_failed_fallback_write_removes_the_partial_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_write = os.write
    writes: list[int] = []

    def fail_on_the_final_file(descriptor: int, data: Any) -> int:
        writes.append(descriptor)
        if len(writes) > 1:  # the first write fills the temporary file
            raise OSError(errno.ENOSPC, "no space")
        return real_write(descriptor, data)

    monkeypatch.setattr("fim.fs.safe_files.os.link", raising(OSError(errno.EPERM, "x")))
    monkeypatch.setattr("fim.fs.safe_files.os.write", fail_on_the_final_file)
    with pytest.raises(FileAccessError, match=r"could not be written \(ENOSPC\)"):
        write_file(str(tmp_path / "out"), b"data", force=False)
    assert names(tmp_path) == []


def test_a_fallback_that_cannot_create_the_file_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_open = os.open

    def deny_final(path: str, flags: int, mode: int = 0o777, **k: Any) -> int:
        if Path(path).name == "out":
            raise PermissionError(errno.EACCES, "denied")
        return real_open(path, flags, mode, **k)

    monkeypatch.setattr("fim.fs.safe_files.os.link", raising(OSError(errno.EPERM, "x")))
    monkeypatch.setattr("fim.fs.safe_files.os.open", deny_final)
    with pytest.raises(FileAccessError, match=r"could not be created \(EACCES\)"):
        write_file(str(tmp_path / "out"), b"data", force=False)
    assert names(tmp_path) == []


@pytest.mark.parametrize(
    "error",
    [
        OSError(errno.ENOSPC, "no space"),
        OSError(errno.EIO, "io"),
        OSError(errno.EACCES, "denied"),
        OSError(errno.EXDEV, "cross-device"),
        only_winerror(5),  # ERROR_ACCESS_DENIED: a real failure on Windows, nothing on POSIX
    ],
)
def test_other_link_failures_are_not_a_reason_to_fall_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: OSError
) -> None:
    monkeypatch.setattr("fim.fs.safe_files.os.link", raising(error))
    with pytest.raises(FileAccessError, match="could not be published"):
        write_file(str(tmp_path / "out"), b"d", force=False)
    assert names(tmp_path) == []


def test_force_never_uses_the_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "out").write_bytes(b"old")
    monkeypatch.setattr("fim.fs.safe_files.os.replace", raising(OSError(errno.EPERM, "x")))
    with pytest.raises(FileAccessError, match="could not be published"):
        write_file(str(tmp_path / "out"), b"new", force=True)
    assert (tmp_path / "out").read_bytes() == b"old"


def test_the_temporary_file_is_created_exclusively_in_the_same_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[str, int, int]] = []
    real_open = os.open

    def spy(path: str, flags: int, mode: int = 0o777, **k: Any) -> int:
        seen.append((str(path), flags, mode))
        return real_open(path, flags, mode, **k)

    monkeypatch.setattr("fim.fs.safe_files.os.open", spy)
    write_file(str(tmp_path / "out"), b"d", force=False)
    path, flags, mode = seen[0]
    assert Path(path).parent == tmp_path
    assert Path(path).name.startswith(".fim-")
    assert flags & os.O_EXCL
    assert flags & os.O_CREAT
    assert mode == 0o600


def test_ensure_can_write_checks_without_writing(tmp_path: Path) -> None:
    safe_files.ensure_can_write(str(tmp_path / "new"), force=False)
    assert names(tmp_path) == []
    (tmp_path / "old").write_bytes(b"x")
    with pytest.raises(FileAccessError, match="already exists"):
        safe_files.ensure_can_write(str(tmp_path / "old"), force=False)
    safe_files.ensure_can_write(str(tmp_path / "old"), force=True)


def test_a_lstat_failure_while_checking_the_target_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "fim.fs.safe_files.os.lstat",
        raising(OSError(errno.EIO, "x")),
    )
    with pytest.raises(FileAccessError, match="could not be examined"):
        write_file(str(tmp_path / "out"), b"d", force=False)


# ---- POSIX behaviour, exercised on every OS by substituting the platform ------------------------

O_NOFOLLOW, O_NONBLOCK, O_CLOEXEC, O_BINARY = 0x100, 0x200, 0x400, 0x8000


def pretend(monkeypatch: pytest.MonkeyPatch, platform: str) -> None:
    monkeypatch.setattr(sys, "platform", platform)
    for name, value in (
        ("O_NOFOLLOW", O_NOFOLLOW),
        ("O_NONBLOCK", O_NONBLOCK),
        ("O_CLOEXEC", O_CLOEXEC),
        ("O_BINARY", O_BINARY),
    ):
        monkeypatch.setattr(f"fim.fs.safe_files.os.{name}", value, raising=False)


def test_posix_read_flags_do_not_follow_links_or_block(monkeypatch: pytest.MonkeyPatch) -> None:
    pretend(monkeypatch, "linux")
    assert safe_files._read_flags() == os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC


def test_posix_write_flags_are_exclusive_and_do_not_follow_links(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pretend(monkeypatch, "linux")
    assert safe_files._write_flags() == (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC
    )


def test_windows_flags_are_binary_and_exclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    pretend(monkeypatch, "win32")
    assert safe_files._read_flags() == os.O_RDONLY | O_BINARY
    assert safe_files._write_flags() == os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_BINARY


def test_posix_uid_helpers_report_the_real_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    pretend(monkeypatch, "linux")
    monkeypatch.setattr("fim.fs.safe_files.os.geteuid", lambda: 4242, raising=False)
    assert safe_files._current_uid() == 4242
    assert safe_files._owner_uid(FakeStat(os.stat_result((0,) * 10), st_uid=7)) == 7  # type: ignore[arg-type]  # a FakeStat stands in


def test_windows_has_no_uid_to_compare(monkeypatch: pytest.MonkeyPatch) -> None:
    pretend(monkeypatch, "win32")
    assert safe_files._current_uid() is None
    assert safe_files._owner_uid(os.stat_result((0,) * 10)) is None


def test_the_directory_is_synced_after_a_write_on_posix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[tuple[str, Any]] = []
    pretend(monkeypatch, "linux")

    def fake_open(path: str, _flags: int) -> int:
        events.append(("open", path))
        return 99

    def fake_fsync(descriptor: int) -> None:
        events.append(("fsync", descriptor))

    def fake_close(descriptor: int) -> None:
        events.append(("close", descriptor))

    monkeypatch.setattr("fim.fs.safe_files.os.open", fake_open)
    monkeypatch.setattr("fim.fs.safe_files.os.fsync", fake_fsync)
    monkeypatch.setattr("fim.fs.safe_files.os.close", fake_close)
    safe_files._sync_directory(str(tmp_path))
    assert events == [("open", str(tmp_path)), ("fsync", 99), ("close", 99)]


def test_a_failing_directory_sync_is_ignored_and_the_descriptor_still_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    closed: list[int] = []
    pretend(monkeypatch, "linux")
    monkeypatch.setattr("fim.fs.safe_files.os.open", lambda _path, _flags: 77)
    monkeypatch.setattr("fim.fs.safe_files.os.fsync", raising(OSError(errno.EINVAL, "x")))
    monkeypatch.setattr("fim.fs.safe_files.os.close", closed.append)
    safe_files._sync_directory(str(tmp_path))
    assert closed == [77]
    monkeypatch.setattr("fim.fs.safe_files.os.open", raising(OSError(errno.EACCES, "x")))
    safe_files._sync_directory(str(tmp_path))  # an unopenable directory is also fine


def test_no_directory_sync_on_windows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pretend(monkeypatch, "win32")
    monkeypatch.setattr("fim.fs.safe_files.os.open", raising(AssertionError("no")))
    safe_files._sync_directory(str(tmp_path))


# ---- the private-file rule (key files) -----------------------------------------------------------


def with_ids(
    monkeypatch: pytest.MonkeyPatch, mode: int, owner: int | None, current: int | None
) -> None:
    real_fstat = os.fstat
    monkeypatch.setattr(
        "fim.fs.safe_files.os.fstat",
        lambda d: FakeStat(real_fstat(d), st_mode=stat.S_IFREG | mode),
    )
    monkeypatch.setattr("fim.fs.safe_files._owner_uid", lambda _info: owner)
    monkeypatch.setattr("fim.fs.safe_files._current_uid", lambda: current)


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o660, 0o666, 0o700 | 0o010])
def test_a_key_that_group_or_others_can_access_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int
) -> None:
    target = tmp_path / "k"
    target.write_bytes(b"abc")
    with_ids(monkeypatch, mode, owner=1000, current=1000)
    with pytest.raises(FileAccessError, match="not private: it is accessible to its group"):
        read_file(str(target), max_bytes=10, private=True, label="key file")
    assert read_file(str(target), max_bytes=10, private=False) == b"abc"


def test_a_key_owned_by_another_user_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "k"
    target.write_bytes(b"abc")
    with_ids(monkeypatch, 0o600, owner=0, current=1000)
    with pytest.raises(FileAccessError, match="owned by another user"):
        read_file(str(target), max_bytes=10, private=True)


def test_a_private_key_owned_by_the_current_user_is_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "k"
    target.write_bytes(b"abc")
    with_ids(monkeypatch, 0o600, owner=1000, current=1000)
    assert read_file(str(target), max_bytes=10, private=True) == b"abc"


@pytest.mark.windows_only
def test_on_windows_the_private_check_cannot_judge_and_does_not_refuse(tmp_path: Path) -> None:
    target = tmp_path / "k"
    target.write_bytes(b"abc")
    assert read_file(str(target), max_bytes=10, private=True) == b"abc"


@pytest.mark.posix_only
@pytest.mark.requires_non_root
def test_a_real_group_readable_key_is_refused_and_a_real_0600_key_is_accepted(
    tmp_path: Path,
) -> None:
    target = tmp_path / "k"
    target.write_bytes(b"abc")
    target.chmod(0o640)
    with pytest.raises(FileAccessError, match="not private"):
        read_file(str(target), max_bytes=10, private=True)
    target.chmod(0o600)
    assert read_file(str(target), max_bytes=10, private=True) == b"abc"


@pytest.mark.posix_only
def test_a_written_file_has_mode_0600_on_posix(tmp_path: Path) -> None:
    write_file(str(tmp_path / "k"), b"x", force=False)
    assert stat.S_IMODE((tmp_path / "k").stat().st_mode) == 0o600
    write_file(str(tmp_path / "k"), b"y", force=True)
    assert stat.S_IMODE((tmp_path / "k").stat().st_mode) == 0o600


@pytest.mark.posix_only
def test_a_real_fifo_is_not_opened_or_read(tmp_path: Path) -> None:
    fifo = tmp_path / "fifo"
    if sys.platform != "win32":
        os.mkfifo(fifo)
    with pytest.raises(FileAccessError, match="not a regular file"):
        read_file(str(fifo), max_bytes=10)


# ---- the guard itself ----------------------------------------------------------------------------


def test_the_path_guard_wraps_the_public_functions_of_safe_files() -> None:
    wrapped: list[Callable[..., Any]] = [
        safe_files.read_own_file,
        safe_files.write_own_file,
        safe_files.ensure_can_write,
    ]
    assert all(hasattr(function, "__wrapped__") for function in wrapped)


def test_the_guard_refuses_a_path_outside_the_temporary_directory() -> None:
    outside = str(Path(__file__).resolve())
    with pytest.raises(AssertionError, match="outside the pytest temporary directory"):
        read_file(outside, max_bytes=10)
    with pytest.raises(AssertionError, match="outside the pytest temporary directory"):
        write_file(outside + ".copy", b"x", force=True)


def test_a_root_that_cannot_be_compared_is_not_a_match(tmp_path: Path) -> None:
    """An absolute path and a relative root (or two drives) cannot contain one another."""
    assert safe_files._inside(str(tmp_path), "relative/dir") is False
    assert safe_files._inside(str(tmp_path / "a"), str(tmp_path)) is True
    assert safe_files._inside(str(tmp_path), str(tmp_path / "a")) is False


# ---- the append log ------------------------------------------------------------------------------


def open_log(*args: Any, **kwargs: Any) -> safe_files.AppendLog:
    return safe_files.open_append_log(*args, **kwargs)


def test_a_new_log_is_created_and_lines_are_appended_in_order(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    with open_log(str(path), force=False) as log:
        log.append(["one\n", "two\n"])
        assert path.read_bytes() == b"one\ntwo\n"  # on disk before the log is closed
        log.append(["three\n"])
    assert path.read_bytes() == b"one\ntwo\nthree\n"
    assert names(tmp_path) == ["events.jsonl"]


def test_a_log_is_never_created_over_an_existing_file_without_force(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_bytes(b"precious")
    with pytest.raises(FileAccessError, match="already exists; use --force"):
        open_log(str(path), force=False)
    assert path.read_bytes() == b"precious"


def test_force_replaces_the_old_log_with_an_empty_one_and_leaves_no_temporary_file(
    tmp_path: Path,
) -> None:
    path = tmp_path / "events.jsonl"
    path.write_bytes(b"old\n")
    with open_log(str(path), force=True) as log:
        assert path.read_bytes() == b""
        log.append(["new\n"])
    assert path.read_bytes() == b"new\n"
    assert names(tmp_path) == ["events.jsonl"]


def test_every_line_is_one_write_and_a_batch_is_synced_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    writes: list[bytes] = []
    syncs: list[int] = []
    real_write, real_fsync = os.write, os.fsync
    path = tmp_path / "events.jsonl"
    log = open_log(str(path), force=False)

    def spy_write(descriptor: int, data: Any) -> int:
        writes.append(bytes(data))
        return real_write(descriptor, data)

    def spy_fsync(descriptor: int) -> None:
        syncs.append(descriptor)
        real_fsync(descriptor)

    monkeypatch.setattr("fim.fs.safe_files.os.write", spy_write)
    monkeypatch.setattr("fim.fs.safe_files.os.fsync", spy_fsync)
    log.append(["a\n", "b\n", "c\n"])
    log.close()
    assert writes == [b"a\n", b"b\n", b"c\n"]
    assert len(syncs) == 1


def test_a_short_write_is_continued_until_the_line_is_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_write = os.write

    def two_bytes_at_a_time(descriptor: int, data: Any) -> int:
        return real_write(descriptor, bytes(data)[:2])

    path = tmp_path / "events.jsonl"
    log = open_log(str(path), force=False)
    monkeypatch.setattr("fim.fs.safe_files.os.write", two_bytes_at_a_time)
    log.append(["abcdefg\n"])
    log.close()
    assert path.read_bytes() == b"abcdefg\n"


def test_a_write_failure_is_a_file_access_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = open_log(str(tmp_path / "events.jsonl"), force=False)
    monkeypatch.setattr("fim.fs.safe_files.os.write", raising(OSError(errno.ENOSPC, "full")))
    with pytest.raises(FileAccessError, match=r"could not be written \(ENOSPC\)"):
        log.append(["x\n"])
    log.close()


def test_a_closed_log_refuses_more_lines_and_closing_twice_is_harmless(tmp_path: Path) -> None:
    log = open_log(str(tmp_path / "events.jsonl"), force=False)
    log.close()
    log.close()
    with pytest.raises(FileAccessError, match="already closed"):
        log.append(["x\n"])


def test_a_log_inside_a_monitored_root_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "watched"
    root.mkdir()
    with pytest.raises(PathRuleError, match="must not be inside a monitored path"):
        open_log(str(root / "events.jsonl"), force=False, avoid_roots=[str(root)])
    assert names(root) == []


def test_a_log_in_a_missing_directory_is_a_file_access_error(tmp_path: Path) -> None:
    with pytest.raises(FileAccessError, match="could not be created"):
        open_log(str(tmp_path / "no-such-dir" / "events.jsonl"), force=False)


@pytest.mark.parametrize("raw", ["\\\\server\\share\\log", "http://example.com/log", "a/../b", ""])
def test_hostile_log_paths_are_refused_before_any_io(raw: str) -> None:
    with pytest.raises(PathRuleError):
        safe_files.open_append_log.__wrapped__(raw, force=False)  # type: ignore[attr-defined]


@pytest.mark.requires_symlinks
@pytest.mark.parametrize("force", [False, True])
def test_a_log_path_that_is_a_link_is_refused_even_with_force(tmp_path: Path, force: bool) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"keep")
    link = tmp_path / "events.jsonl"
    os.symlink(target, link)
    with pytest.raises(FileAccessError):
        open_log(str(link), force=force)
    assert target.read_bytes() == b"keep"


def test_a_swap_between_placing_and_opening_the_forced_log_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "events.jsonl"
    path.write_bytes(b"old")
    real_open = os.open

    def swap_then_open(target: str, flags: int, *a: Any, **k: Any) -> int:
        if Path(target).name == "events.jsonl" and not flags & os.O_EXCL:
            # Someone replaces the file we just placed. The old one is renamed, not deleted, so
            # its inode number cannot be handed to the new file (ext4 reuses freed numbers).
            os.rename(target, target + ".moved")
            Path(target).write_bytes(b"other")
        return real_open(target, flags, *a, **k)

    monkeypatch.setattr("fim.fs.safe_files.os.open", swap_then_open)
    with pytest.raises(FileAccessError, match="replaced while it was being opened"):
        open_log(str(path), force=True)
    assert path.read_bytes() == b"other"


def test_the_log_module_exports() -> None:
    assert {"AppendLog", "open_append_log"} <= set(safe_files.__all__)


def test_append_flags_are_exclusive_when_creating_and_never_follow_links_on_posix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pretend(monkeypatch, "linux")
    created = safe_files._append_flags(create=True)
    reopened = safe_files._append_flags(create=False)
    assert created == os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC
    assert reopened == os.O_WRONLY | os.O_APPEND | O_NOFOLLOW | O_CLOEXEC
    pretend(monkeypatch, "win32")
    assert safe_files._append_flags(create=True) == (
        os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL | O_BINARY
    )


def test_a_file_that_appears_between_the_check_and_the_create_is_not_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("fim.fs.safe_files.os.open", raising(FileExistsError(errno.EEXIST, "x")))
    with pytest.raises(FileAccessError, match="already exists; use --force"):
        open_log(str(tmp_path / "events.jsonl"), force=False)


def test_a_forced_log_that_vanishes_before_it_is_opened_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("fim.fs.safe_files._lstat", lambda *_args: None)
    with pytest.raises(FileAccessError, match="replaced while it was being opened"):
        open_log(str(tmp_path / "events.jsonl"), force=True)


def test_a_forced_log_that_cannot_be_opened_or_examined_is_a_file_access_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "events.jsonl"
    real_open = os.open

    def deny_the_reopen(target: str, flags: int, *a: Any, **k: Any) -> int:
        if Path(target).name == "events.jsonl" and not flags & os.O_EXCL:
            raise PermissionError(errno.EACCES, "denied")
        return real_open(target, flags, *a, **k)

    monkeypatch.setattr("fim.fs.safe_files.os.open", deny_the_reopen)
    with pytest.raises(FileAccessError, match=r"could not be opened \(EACCES\)"):
        open_log(str(path), force=True)
    monkeypatch.undo()

    closed: list[int] = []
    real_close = os.close

    def note_close(descriptor: int) -> None:
        closed.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr("fim.fs.safe_files.os.fstat", raising(OSError(errno.EIO, "io")))
    monkeypatch.setattr("fim.fs.safe_files.os.close", note_close)
    with pytest.raises(FileAccessError, match=r"could not be examined \(EIO\)"):
        open_log(str(path), force=True)
    assert closed  # the descriptor was not leaked
