"""The only module that reads and writes the tool's own files (PLAN.md section 1.4): the key, the
baseline, the rollback anchor, the configuration and report outputs.

Monitored files are never handled here (that is fs/observe.py, read-only), and nothing here
touches a file the tool did not create or was not told to read.

Every function checks the path with core/pathrules first (no UNC or device path, no URL, no
reserved name, no drive-relative path, no ``..``) and refuses a path that lies inside a
monitored root, compared both as text and after resolving links in the directory part.

Reading never follows a link: the final component is examined with ``lstat``, opened without
following where the OS can (``O_NOFOLLOW``), and the open descriptor is compared with the
``lstat`` result (device and inode), so a link swapped in between is refused. The size is capped
before any byte is read.

Writing is atomic and never clobbers by accident: the data goes to a temporary file in the same
directory (created exclusively, mode 0600 on POSIX, flushed and fsynced); without ``force`` it is
published with a hard link, which fails if the target exists, on NTFS and POSIX alike, so there
is no check-then-write race; with ``force`` it replaces the target with ``os.replace``, which
replaces a link itself and never writes through it. The temporary file is removed on every path.
On a file system without hard links (FAT, exFAT) the publish falls back to creating the final
file directly with ``O_CREAT | O_EXCL`` and an fsync: still no-clobber, but not atomic.
Residual risk, documented: a parent directory swapped between the checks and the rename.
"""

from __future__ import annotations

import contextlib
import errno
import os
import secrets
import stat
import sys
from collections.abc import Sequence

from fim.core.errors import FileAccessError, FileMissingError, PathRuleError
from fim.core.limits import HASH_CHUNK_BYTES
from fim.core.models import EntryType
from fim.core.pathrules import Flavour, display_user_path, validate_user_path
from fim.core.perms import entry_type, private_file_problem

__all__ = ["FileTooLargeError", "ensure_can_write", "read_own_file", "write_own_file"]

_MESSAGE_PATH_CHARS = 120
_DEFAULT_MODE = 0o600
_LINK_TYPES = (EntryType.SYMLINK, EntryType.REPARSE)


class FileTooLargeError(FileAccessError):
    """A file is larger than the cap given to ``read_own_file``; nothing was read."""


def _shown(path: str) -> str:
    return display_user_path(path, _flavour(), _MESSAGE_PATH_CHARS)


def _flavour() -> Flavour:
    return Flavour.WINDOWS if sys.platform == "win32" else Flavour.POSIX


def _errno_name(exc: OSError) -> str:
    return errno.errorcode.get(exc.errno or 0, "UNKNOWN")


def _failure(label: str, path: str, action: str, exc: OSError) -> FileAccessError:
    return FileAccessError(f"{label} '{_shown(path)}' could not be {action} ({_errno_name(exc)})")


# ---- path checks ---------------------------------------------------------------------------------


def _inside(candidate: str, root: str) -> bool:
    """True if ``candidate`` is ``root`` or below it, compared by whole components."""
    left = os.path.normcase(candidate)
    right = os.path.normcase(root)
    try:
        return os.path.commonpath([left, right]) == right
    except ValueError:  # different drives, or an absolute and a relative path
        return False


def _check_path(raw: str, avoid_roots: Sequence[str], label: str) -> None:
    """Apply the path rules and the monitored-root rule; raise PathRuleError."""
    if not isinstance(raw, str):
        raise PathRuleError(f"{label} path must be text")
    validate_user_path(raw, _flavour())
    absolute = os.path.abspath(raw)
    # Resolve links in the directory part only: the final name is examined separately and a
    # link there is refused, not resolved.
    resolved = os.path.join(os.path.realpath(os.path.dirname(absolute)), os.path.basename(absolute))
    for root in avoid_roots:
        if _inside(absolute, root) or _inside(resolved, os.path.realpath(root)):
            raise PathRuleError(
                f"{label} '{_shown(raw)}' must not be inside a monitored path "
                f"('{_shown(root)}'): the tool would then watch its own files"
            )


def _lstat(raw: str, label: str) -> os.stat_result | None:
    """``lstat`` of the final component, or None if it does not exist."""
    try:
        return os.lstat(raw)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _failure(label, raw, "examined", exc) from None


def _is_link(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", None)
    tag = getattr(info, "st_reparse_tag", None)
    return entry_type(info.st_mode, attributes, tag) in _LINK_TYPES


# ---- reading -------------------------------------------------------------------------------------


def _read_flags() -> int:
    flags = os.O_RDONLY
    if sys.platform == "win32":
        flags |= os.O_BINARY
    else:
        # O_NONBLOCK: a FIFO swapped in after the lstat must not block the open.
        flags |= os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    return flags


def _current_uid() -> int | None:
    """The user running the tool; None on Windows, where there is no uid to compare."""
    if sys.platform == "win32":
        return None
    else:
        return os.geteuid()


def _owner_uid(info: os.stat_result) -> int | None:
    if sys.platform == "win32":
        return None
    else:
        return info.st_uid


def read_own_file(
    path: str,
    *,
    max_bytes: int,
    avoid_roots: Sequence[str] = (),
    private: bool = False,
    label: str = "file",
) -> bytes:
    """Read the whole of one of the tool's own files, refusing links and oversize files.

    ``max_bytes`` is a hard cap: a larger file raises ``FileTooLargeError`` before it is read.
    ``private`` demands (POSIX) that only the owner can access the file and that the owner is
    the current user, as for the key. A missing file raises ``FileMissingError``.
    """
    _check_path(path, avoid_roots, label)
    before = _lstat(path, label)
    if before is None:
        raise FileMissingError(f"{label} '{_shown(path)}' does not exist")
    if _is_link(before):
        raise FileAccessError(
            f"{label} '{_shown(path)}' is a symbolic link or reparse point; "
            "refusing to follow it, give the real path"
        )
    if not stat.S_ISREG(before.st_mode):
        raise FileAccessError(f"{label} '{_shown(path)}' is not a regular file")
    try:
        descriptor = os.open(path, _read_flags())
    except OSError as exc:
        raise _failure(label, path, "opened", exc) from None
    try:
        return _read_open_file(descriptor, before, path, max_bytes, private, label)
    except OSError as exc:
        raise _failure(label, path, "read", exc) from None
    finally:
        with contextlib.suppress(OSError):
            os.close(descriptor)


def _read_open_file(
    descriptor: int,
    before: os.stat_result,
    path: str,
    max_bytes: int,
    private: bool,
    label: str,
) -> bytes:
    opened = os.fstat(descriptor)
    if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or _is_link(opened):
        raise FileAccessError(f"{label} '{_shown(path)}' was replaced while it was being opened")
    if not stat.S_ISREG(opened.st_mode):
        raise FileAccessError(f"{label} '{_shown(path)}' is not a regular file")
    if private:
        problem = private_file_problem(opened.st_mode, _owner_uid(opened), _current_uid())
        if problem is not None:
            raise FileAccessError(f"{label} '{_shown(path)}' is not private: {problem}")
    too_large = FileTooLargeError(f"{label} '{_shown(path)}' is larger than {max_bytes} bytes")
    if opened.st_size > max_bytes:
        raise too_large
    chunks: list[bytes] = []
    total = 0
    while True:
        # One byte more than the cap, so a file that grew after the fstat is still caught.
        chunk = os.read(descriptor, min(HASH_CHUNK_BYTES, max_bytes + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise too_large
        chunks.append(chunk)
    return b"".join(chunks)


# ---- writing -------------------------------------------------------------------------------------


def _write_flags() -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if sys.platform == "win32":
        flags |= os.O_BINARY
    else:
        flags |= os.O_NOFOLLOW | os.O_CLOEXEC
    return flags


def _sync_directory(directory: str) -> None:
    """Make the rename durable (POSIX). Best effort: the file is already in place."""
    if sys.platform != "win32":
        with contextlib.suppress(OSError):
            descriptor = os.open(directory, os.O_RDONLY | os.O_CLOEXEC)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        view = view[written:]
    os.fsync(descriptor)


def _check_target(path: str, force: bool, label: str) -> None:
    existing = _lstat(path, label)
    if existing is None:
        return
    if _is_link(existing):
        raise FileAccessError(
            f"{label} '{_shown(path)}' is a symbolic link or reparse point; "
            "refusing to write through or replace it, give the real path"
        )
    if not stat.S_ISREG(existing.st_mode):
        raise FileAccessError(f"{label} '{_shown(path)}' exists and is not a regular file")
    if not force:
        raise FileAccessError(f"{label} '{_shown(path)}' already exists; use --force to replace it")


def _check_writable(path: str, force: bool, avoid_roots: Sequence[str], label: str) -> None:
    _check_path(path, avoid_roots, label)
    _check_target(path, force, label)


def ensure_can_write(
    path: str,
    *,
    force: bool,
    avoid_roots: Sequence[str] = (),
    label: str = "file",
) -> None:
    """Run the checks ``write_own_file`` will run, without writing, so a long job can fail early."""
    _check_writable(path, force, avoid_roots, label)


def write_own_file(
    path: str,
    data: bytes,
    *,
    force: bool,
    avoid_roots: Sequence[str] = (),
    mode: int = _DEFAULT_MODE,
    label: str = "file",
) -> None:
    """Atomically write ``data`` to ``path``; refuse to overwrite unless ``force``.

    A link or reparse point at ``path`` is refused even with ``force``. The temporary file is
    always removed.
    """
    _check_writable(path, force, avoid_roots, label)
    directory = os.path.dirname(os.path.abspath(path))
    temp = os.path.join(directory, f".fim-{secrets.token_hex(8)}.tmp")
    try:
        try:
            descriptor = os.open(temp, _write_flags(), mode)
        except OSError as exc:
            raise _failure(label, path, "created (does its directory exist?)", exc) from None
        try:
            _write_all(descriptor, data)
        except OSError as exc:
            raise _failure(label, path, "written", exc) from None
        finally:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        _publish(temp, path, force, label, data, mode)
        _sync_directory(directory)
    finally:
        # After os.replace the temporary name is gone; after os.link it is still there.
        with contextlib.suppress(OSError):
            os.unlink(temp)


# A hard link that fails for one of these reasons means the file system has no hard links (FAT,
# exFAT, some network and removable file systems). Windows reports it as ERROR_INVALID_FUNCTION (1)
# or ERROR_NOT_SUPPORTED (50), which Python maps to EINVAL.
_NO_HARD_LINKS_ERRNOS = frozenset(
    {errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS, errno.EINVAL, errno.EMLINK}
)
_NO_HARD_LINKS_WINERRORS = frozenset({1, 50})


def _hard_links_unsupported(exc: OSError) -> bool:
    return exc.errno in _NO_HARD_LINKS_ERRNOS or getattr(exc, "winerror", None) in (
        _NO_HARD_LINKS_WINERRORS
    )


def _publish(temp: str, path: str, force: bool, label: str, data: bytes, mode: int) -> None:
    try:
        if force:
            os.replace(temp, path)
        else:
            os.link(temp, path)
    except FileExistsError:
        raise FileAccessError(
            f"{label} '{_shown(path)}' already exists; use --force to replace it"
        ) from None
    except OSError as exc:
        if force or not _hard_links_unsupported(exc):
            raise _failure(label, path, "published", exc) from None
        _write_exclusive(path, data, mode, label)


def _write_exclusive(path: str, data: bytes, mode: int, label: str) -> None:
    """Fallback for file systems without hard links: create the final file exclusively.

    ``O_CREAT | O_EXCL`` keeps the no-clobber rule (an existing file or link, even one that
    appeared a moment ago, is refused), and the data is fsynced, but the write is no longer
    atomic: a crash can leave a partial file, and a reader can see one while it is written.
    That is the documented price of such file systems; a partial file is removed on failure.
    """
    try:
        descriptor = os.open(path, _write_flags(), mode)
    except FileExistsError:
        raise FileAccessError(
            f"{label} '{_shown(path)}' already exists; use --force to replace it"
        ) from None
    except OSError as exc:
        raise _failure(label, path, "created", exc) from None
    try:
        _write_all(descriptor, data)
    except OSError as exc:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        with contextlib.suppress(OSError):
            os.unlink(path)  # we created it a moment ago with O_EXCL, so it is ours
        raise _failure(label, path, "written", exc) from None
    with contextlib.suppress(OSError):
        os.close(descriptor)
