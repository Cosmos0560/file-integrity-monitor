"""Interpretation of raw file facts (PLAN.md D5, D6, D7).

The platform code in fs/observe.py collects plain integers (``st_mode``, ``st_file_attributes``,
the reparse tag). This module turns them into the tool's vocabulary, with no operating-system
calls, so the interpretation is tested on every OS with synthetic numbers.

POSIX records keep the permission bits including setuid, setgid and sticky. Windows records
keep only READONLY, HIDDEN and SYSTEM: ARCHIVE flips on every write and would duplicate a
``modified`` finding, and ACLs and owners are out of scope (D7).
"""

from __future__ import annotations

import stat

from fim.core.errors import ModelError
from fim.core.models import EntryType

__all__ = [
    "FILE_ATTRIBUTE_HIDDEN",
    "FILE_ATTRIBUTE_OFFLINE",
    "FILE_ATTRIBUTE_READONLY",
    "FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS",
    "FILE_ATTRIBUTE_RECALL_ON_OPEN",
    "FILE_ATTRIBUTE_REPARSE_POINT",
    "FILE_ATTRIBUTE_SYSTEM",
    "IO_REPARSE_TAG_MOUNT_POINT",
    "IO_REPARSE_TAG_SYMLINK",
    "TRACKED_WINDOWS_ATTRIBUTES",
    "describe_posix_mode",
    "describe_windows_attributes",
    "entry_type",
    "is_offline",
    "is_reparse_point",
    "posix_permissions",
    "tracked_windows_attributes",
]

FILE_ATTRIBUTE_READONLY = 0x00000001
FILE_ATTRIBUTE_HIDDEN = 0x00000002
FILE_ATTRIBUTE_SYSTEM = 0x00000004
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_ATTRIBUTE_OFFLINE = 0x00001000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x00040000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000

IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003  # NTFS junction
IO_REPARSE_TAG_SYMLINK = 0xA000000C

TRACKED_WINDOWS_ATTRIBUTES = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
# Opening a file with any of these bits can make the system download or restore its content.
_OFFLINE_BITS = (
    FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
)
_MAX_ATTRIBUTES = 0xFFFFFFFF
_MAX_MODE = 0o177777


def _check(name: str, value: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ModelError(f"{name} is not a valid raw value")


def posix_permissions(st_mode: int) -> int:
    """The permission bits (rwx for user, group, other, plus setuid, setgid and sticky)."""
    _check("st_mode", st_mode, _MAX_MODE)
    return stat.S_IMODE(st_mode)


def tracked_windows_attributes(file_attributes: int) -> int:
    """Only the READONLY, HIDDEN and SYSTEM bits of ``st_file_attributes``."""
    _check("file attributes", file_attributes, _MAX_ATTRIBUTES)
    return file_attributes & TRACKED_WINDOWS_ATTRIBUTES


def is_reparse_point(file_attributes: int) -> bool:
    _check("file attributes", file_attributes, _MAX_ATTRIBUTES)
    return bool(file_attributes & FILE_ATTRIBUTE_REPARSE_POINT)


def is_offline(file_attributes: int) -> bool:
    """True for a cloud or archive placeholder whose content would be fetched on read (D5)."""
    _check("file attributes", file_attributes, _MAX_ATTRIBUTES)
    return bool(file_attributes & _OFFLINE_BITS)


def entry_type(st_mode: int, file_attributes: int | None, reparse_tag: int | None) -> EntryType:
    """Classify an ``lstat`` result.

    A Windows reparse point is a ``symlink`` only when its tag says so; junctions, mount
    points, app-execution links and cloud tags are ``reparse`` and are never followed (D6).
    ``file_attributes`` is None on POSIX.
    """
    _check("st_mode", st_mode, _MAX_MODE)
    if reparse_tag is not None:
        _check("reparse tag", reparse_tag, _MAX_ATTRIBUTES)
    if file_attributes is not None and is_reparse_point(file_attributes):
        return EntryType.SYMLINK if reparse_tag == IO_REPARSE_TAG_SYMLINK else EntryType.REPARSE
    if stat.S_ISLNK(st_mode):
        return EntryType.SYMLINK
    if stat.S_ISDIR(st_mode):
        return EntryType.DIR
    if stat.S_ISREG(st_mode):
        return EntryType.FILE
    if stat.S_ISFIFO(st_mode):
        return EntryType.FIFO
    if stat.S_ISSOCK(st_mode):
        return EntryType.SOCKET
    if stat.S_ISCHR(st_mode) or stat.S_ISBLK(st_mode):
        return EntryType.DEVICE
    return EntryType.OTHER


def describe_posix_mode(mode: int) -> str:
    """'0755', or '4755' with setuid, '2755' with setgid, '1777' with sticky: octal, 4 digits."""
    _check("mode", mode, _MAX_MODE)
    return f"{stat.S_IMODE(mode):04o}"


_WINDOWS_NAMES = (
    (FILE_ATTRIBUTE_READONLY, "READONLY"),
    (FILE_ATTRIBUTE_HIDDEN, "HIDDEN"),
    (FILE_ATTRIBUTE_SYSTEM, "SYSTEM"),
)


def describe_windows_attributes(file_attributes: int) -> str:
    """'READONLY|SYSTEM' for the tracked bits that are set, or 'none'."""
    _check("file attributes", file_attributes, _MAX_ATTRIBUTES)
    names = [name for bit, name in _WINDOWS_NAMES if file_attributes & bit]
    return "|".join(names) if names else "none"
