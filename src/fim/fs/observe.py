"""The only module that touches monitored files, and it only reads (PLAN.md section 1.3).

Nothing here modifies, moves, renames, changes the mode of, truncates or deletes a file; the
architecture checker bans every such call in this module. Files are opened read-only, and only
regular files are opened at all: FIFOs, sockets and devices are described by ``lstat`` and left
alone. Reading can update a file's access time; that is documented, not hidden.

Every function returns a value; an operating-system error becomes an ``FsProblem`` or a
``HashResult`` status and is never raised to the caller. The platform facts come back as plain
integers (``RawStat``) and core/perms.py interprets them, so the interpretation is tested on
every OS.

Hashing follows these steps, with a retry once if the file changes under it:
1. open read-only (POSIX ``O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC``, ``O_NOATIME`` when allowed);
2. ``fstat`` the descriptor and compare device and inode with the earlier ``lstat``: a mismatch
   means the path was swapped, which is ``unstable``, not a crash;
3. read in chunks, asking ``should_stop`` between chunks so the run-time budget is honoured;
4. ``fstat`` again: a changed size or modification time means it changed while being hashed.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import os
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass

from fim.core.limits import HASH_CHUNK_BYTES
from fim.core.models import HashStatus

__all__ = [
    "DirListing",
    "FsProblem",
    "HashResult",
    "RawStat",
    "ReadOps",
    "hash_file",
    "list_dir",
    "lstat",
    "read_link",
    "stat_target",
    "system_read_ops",
]

_UNKNOWN_ERRNO = "UNKNOWN"
_VANISHED_ERRNOS = frozenset({errno.ENOENT, errno.ENOTDIR})


@dataclass(frozen=True, slots=True)
class FsProblem:
    """An operating-system error, reduced to what the caller needs."""

    errno_name: str  # e.g. "EACCES"; always plain ASCII
    vanished: bool  # the path is gone (or a parent stopped being a directory)
    denied: bool  # permission denied


@dataclass(frozen=True, slots=True)
class RawStat:
    """Plain facts from lstat, stat or fstat (POSIX fills uid and gid, Windows the last two)."""

    st_mode: int
    size: int
    mtime_ns: int
    dev: int
    ino: int
    nlink: int
    uid: int | None
    gid: int | None
    file_attributes: int | None
    reparse_tag: int | None


@dataclass(frozen=True, slots=True)
class DirListing:
    """Names in a directory, sorted by code point. ``truncated`` means more existed."""

    names: tuple[str, ...]
    truncated: bool


@dataclass(frozen=True, slots=True)
class HashResult:
    """Outcome of hashing one regular file. A partial file is never given a hash."""

    status: HashStatus
    sha256: str | None
    bytes_read: int
    size: int
    mtime_ns: int
    error: str | None  # errno name for unreadable
    detail: str  # short plain text for a scan issue
    stopped: bool = False  # the time budget ended the read; the caller records nothing


@dataclass(frozen=True, slots=True)
class ReadOps:
    """The four operations hashing needs on an open descriptor; tests substitute their own."""

    open_fd: Callable[[str, bool], int]  # (path, follow_links) -> descriptor
    fstat: Callable[[int], RawStat]
    read: Callable[[int, int], bytes]
    close: Callable[[int], None]


# ---- errors and stat -----------------------------------------------------------------------------


def _problem(exc: OSError | ValueError) -> FsProblem:
    if isinstance(exc, ValueError):  # an embedded NUL byte in a path
        return FsProblem("EINVAL", vanished=False, denied=False)
    name = errno.errorcode.get(exc.errno or 0, _UNKNOWN_ERRNO)
    vanished = isinstance(exc, FileNotFoundError) or exc.errno in _VANISHED_ERRNOS
    return FsProblem(name, vanished=vanished, denied=isinstance(exc, PermissionError))


def _raw(result: os.stat_result) -> RawStat:
    uid: int | None = None
    gid: int | None = None
    attributes: int | None = None
    reparse_tag: int | None = None
    if sys.platform == "win32":
        attributes = result.st_file_attributes
        reparse_tag = result.st_reparse_tag
    else:
        uid = result.st_uid
        gid = result.st_gid
    return RawStat(
        st_mode=result.st_mode,
        size=result.st_size,
        mtime_ns=result.st_mtime_ns,
        dev=result.st_dev,
        ino=result.st_ino,
        nlink=result.st_nlink,
        uid=uid,
        gid=gid,
        file_attributes=attributes,
        reparse_tag=reparse_tag,
    )


def lstat(path: str) -> RawStat | FsProblem:
    """Describe ``path`` itself, without following a link."""
    try:
        return _raw(os.lstat(path))
    except (OSError, ValueError) as exc:
        return _problem(exc)


def stat_target(path: str) -> RawStat | FsProblem:
    """Describe what ``path`` points to (follows links). Used only by the ``files`` policy."""
    try:
        return _raw(os.stat(path))
    except (OSError, ValueError) as exc:
        return _problem(exc)


def read_link(path: str) -> str | FsProblem:
    """The text of a symbolic link, exactly as stored."""
    try:
        return os.readlink(path)
    except (OSError, ValueError) as exc:
        return _problem(exc)


def list_dir(path: str, limit: int) -> DirListing | FsProblem:
    """Names in directory ``path``, sorted, at most ``limit`` of them.

    Reading stops after ``limit + 1`` names, so a directory with millions of entries cannot
    exhaust memory; ``truncated`` then tells the caller the run is incomplete.
    """
    names: list[str] = []
    truncated = False
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                if len(names) >= limit:
                    truncated = True
                    break
                names.append(entry.name)
    except (OSError, ValueError) as exc:
        return _problem(exc)
    return DirListing(tuple(sorted(names)), truncated)


# ---- hashing -------------------------------------------------------------------------------------


def _open_readonly(path: str, follow: bool) -> int:
    flags = os.O_RDONLY
    if sys.platform == "win32":
        flags |= os.O_BINARY
    else:
        flags |= os.O_NONBLOCK | os.O_CLOEXEC
        if not follow:
            flags |= os.O_NOFOLLOW  # a link swapped in after lstat must not be followed
        if sys.platform == "linux":
            try:
                return os.open(path, flags | os.O_NOATIME)
            except PermissionError:
                pass  # O_NOATIME is refused for files we do not own; open normally below
    return os.open(path, flags)


def _fstat(descriptor: int) -> RawStat:
    return _raw(os.fstat(descriptor))


def _read(descriptor: int, size: int) -> bytes:
    return os.read(descriptor, size)


def _close(descriptor: int) -> None:
    # A read-only descriptor cannot lose data when closing fails; there is nothing to report.
    with contextlib.suppress(OSError):
        os.close(descriptor)


def system_read_ops() -> ReadOps:
    """The real operations."""
    return ReadOps(open_fd=_open_readonly, fstat=_fstat, read=_read, close=_close)


def _result(
    status: HashStatus,
    *,
    size: int,
    mtime_ns: int,
    detail: str,
    sha256: str | None = None,
    bytes_read: int = 0,
    error: str | None = None,
    stopped: bool = False,
) -> HashResult:
    return HashResult(
        status=status,
        sha256=sha256,
        bytes_read=bytes_read,
        size=size,
        mtime_ns=mtime_ns,
        error=error,
        detail=detail,
        stopped=stopped,
    )


def _failed_open(exc: OSError | ValueError, expected: RawStat) -> HashResult:
    problem = _problem(exc)
    if problem.vanished:
        return _result(
            HashStatus.VANISHED,
            size=expected.size,
            mtime_ns=expected.mtime_ns,
            detail="disappeared before it could be read",
        )
    if isinstance(exc, OSError) and exc.errno == errno.ELOOP:
        # O_NOFOLLOW met a link: the regular file seen by lstat was replaced by one.
        return _result(
            HashStatus.UNSTABLE,
            size=expected.size,
            mtime_ns=expected.mtime_ns,
            detail="replaced by a link during the scan",
        )
    return _result(
        HashStatus.UNREADABLE,
        size=expected.size,
        mtime_ns=expected.mtime_ns,
        detail="cannot be read",
        error=problem.errno_name,
    )


def _hash_once(
    path: str,
    expected: RawStat,
    max_bytes: int,
    should_stop: Callable[[], bool],
    ops: ReadOps,
    follow: bool,
) -> HashResult | None:
    """One attempt. None means the file changed while it was read and the caller may retry."""
    try:
        descriptor = ops.open_fd(path, follow)
    except (OSError, ValueError) as exc:
        return _failed_open(exc, expected)
    try:
        before = ops.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or (before.dev, before.ino) != (
            expected.dev,
            expected.ino,
        ):
            return _result(
                HashStatus.UNSTABLE,
                size=before.size,
                mtime_ns=before.mtime_ns,
                detail="replaced during the scan",
            )
        if before.size > max_bytes:
            return _result(
                HashStatus.SKIPPED_TOO_LARGE,
                size=before.size,
                mtime_ns=before.mtime_ns,
                detail="larger than the hashing limit",
            )
        digest = hashlib.sha256()
        total = 0
        while True:
            if should_stop():
                return _result(
                    HashStatus.UNSTABLE,
                    size=before.size,
                    mtime_ns=before.mtime_ns,
                    detail="stopped by the time budget",
                    bytes_read=total,
                    stopped=True,
                )
            chunk = ops.read(descriptor, HASH_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:  # it grew past the limit while being read
                return _result(
                    HashStatus.SKIPPED_TOO_LARGE,
                    size=total,
                    mtime_ns=before.mtime_ns,
                    detail="grew past the hashing limit during the scan",
                    bytes_read=total,
                )
            digest.update(chunk)
        after = ops.fstat(descriptor)
        if (after.size, after.mtime_ns) != (before.size, before.mtime_ns) or total != after.size:
            return None
        return _result(
            HashStatus.OK,
            size=after.size,
            mtime_ns=after.mtime_ns,
            detail="",
            sha256=digest.hexdigest(),
            bytes_read=total,
        )
    except OSError as exc:
        problem = _problem(exc)
        status = HashStatus.VANISHED if problem.vanished else HashStatus.UNREADABLE
        return _result(
            status,
            size=expected.size,
            mtime_ns=expected.mtime_ns,
            detail="disappeared while being read" if problem.vanished else "cannot be read",
            error=None if problem.vanished else problem.errno_name,
        )
    finally:
        ops.close(descriptor)


def hash_file(
    path: str,
    expected: RawStat,
    *,
    max_bytes: int,
    should_stop: Callable[[], bool],
    ops: ReadOps | None = None,
    follow: bool = False,
) -> HashResult:
    """SHA-256 of a regular file, or the reason there is none. Never raises.

    ``expected`` is the earlier ``lstat`` (or ``stat`` with ``follow``); the descriptor must
    agree with it. A file that changes during the read is read once more; if it changes again
    the result is ``unstable``. ``should_stop`` is asked between chunks.
    """
    real = ops if ops is not None else system_read_ops()
    for _attempt in range(2):
        outcome = _hash_once(path, expected, max_bytes, should_stop, real, follow)
        if outcome is not None:
            return outcome
    return _result(
        HashStatus.UNSTABLE,
        size=expected.size,
        mtime_ns=expected.mtime_ns,
        detail="changed while being hashed",
    )
