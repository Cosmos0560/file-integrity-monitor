"""core/perms.py: raw numbers become the tool's vocabulary, the same way on every OS."""

from __future__ import annotations

import stat
from typing import Any

import pytest

from fim.core import perms
from fim.core.errors import ModelError
from fim.core.models import EntryType
from fim.core.perms import (
    FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_READONLY,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
    FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_SYSTEM,
    IO_REPARSE_TAG_MOUNT_POINT,
    IO_REPARSE_TAG_SYMLINK,
    describe_posix_mode,
    describe_windows_attributes,
    entry_type,
    is_offline,
    is_reparse_point,
    posix_permissions,
    tracked_windows_attributes,
)

ARCHIVE = 0x20
DIRECTORY = 0x10
NORMAL = 0x80
CLOUD_TAG = 0x9000001A  # a cloud-files reparse tag, not a symlink

# ---- POSIX ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        (stat.S_IFREG | 0o644, 0o644),
        (stat.S_IFREG | 0o755, 0o755),
        (stat.S_IFREG | 0o4755, 0o4755),  # setuid
        (stat.S_IFREG | 0o2755, 0o2755),  # setgid
        (stat.S_IFDIR | 0o1777, 0o1777),  # sticky
        (stat.S_IFREG | 0o6777, 0o6777),
        (stat.S_IFREG, 0),
        (0o100000 | 0o777, 0o777),
    ],
)
def test_posix_permissions_keep_special_bits_and_drop_the_type(mode: int, expected: int) -> None:
    assert posix_permissions(mode) == expected


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        (stat.S_IFREG | 0o644, EntryType.FILE),
        (stat.S_IFDIR | 0o755, EntryType.DIR),
        (stat.S_IFLNK | 0o777, EntryType.SYMLINK),
        (stat.S_IFIFO | 0o600, EntryType.FIFO),
        (stat.S_IFSOCK | 0o755, EntryType.SOCKET),
        (stat.S_IFCHR | 0o600, EntryType.DEVICE),
        (stat.S_IFBLK | 0o600, EntryType.DEVICE),
        (0o130000, EntryType.OTHER),  # a type value no S_IS* predicate knows
        (0o644, EntryType.OTHER),  # no type bits at all
    ],
)
def test_posix_entry_types(mode: int, expected: EntryType) -> None:
    assert entry_type(mode, None, None) is expected


# ---- Windows -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("attrs", "expected"),
    [
        (NORMAL, 0),
        (FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_READONLY),
        (FILE_ATTRIBUTE_HIDDEN | ARCHIVE, FILE_ATTRIBUTE_HIDDEN),  # ARCHIVE is ignored (D7)
        (ARCHIVE, 0),
        (FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY | ARCHIVE | DIRECTORY, 0x5),
        (0xFFFFFFFF, 0x7),
    ],
)
def test_tracked_windows_attributes_are_readonly_hidden_system_only(
    attrs: int, expected: int
) -> None:
    assert tracked_windows_attributes(attrs) == expected


@pytest.mark.parametrize(
    ("attrs", "expected"),
    [
        (0, "none"),
        (ARCHIVE, "none"),
        (FILE_ATTRIBUTE_READONLY, "READONLY"),
        (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, "HIDDEN|SYSTEM"),
        (0x7, "READONLY|HIDDEN|SYSTEM"),
    ],
)
def test_describe_windows_attributes(attrs: int, expected: str) -> None:
    assert describe_windows_attributes(attrs) == expected


@pytest.mark.parametrize(
    ("attrs", "tag", "mode", "expected"),
    [
        (NORMAL, None, stat.S_IFREG | 0o666, EntryType.FILE),
        (DIRECTORY, None, stat.S_IFDIR | 0o777, EntryType.DIR),
        # a symlink is a reparse point whose tag says so, whatever st_mode claims
        (FILE_ATTRIBUTE_REPARSE_POINT, IO_REPARSE_TAG_SYMLINK, stat.S_IFLNK, EntryType.SYMLINK),
        (
            FILE_ATTRIBUTE_REPARSE_POINT | DIRECTORY,
            IO_REPARSE_TAG_SYMLINK,
            stat.S_IFDIR,
            EntryType.SYMLINK,
        ),
        # a junction: a directory to st_mode, a reparse point to us, never followed
        (
            FILE_ATTRIBUTE_REPARSE_POINT | DIRECTORY,
            IO_REPARSE_TAG_MOUNT_POINT,
            stat.S_IFDIR | 0o777,
            EntryType.REPARSE,
        ),
        (FILE_ATTRIBUTE_REPARSE_POINT, CLOUD_TAG, stat.S_IFREG | 0o666, EntryType.REPARSE),
        (FILE_ATTRIBUTE_REPARSE_POINT, None, stat.S_IFREG | 0o666, EntryType.REPARSE),
        (FILE_ATTRIBUTE_REPARSE_POINT, 0, stat.S_IFREG | 0o666, EntryType.REPARSE),
    ],
)
def test_windows_entry_types(attrs: int, tag: int | None, mode: int, expected: EntryType) -> None:
    assert entry_type(mode, attrs, tag) is expected


def test_a_symlink_tag_without_the_reparse_attribute_is_just_what_the_mode_says() -> None:
    assert entry_type(stat.S_IFREG, NORMAL, IO_REPARSE_TAG_SYMLINK) is EntryType.FILE


@pytest.mark.parametrize(
    ("attrs", "expected"),
    [
        (NORMAL, False),
        (FILE_ATTRIBUTE_OFFLINE, True),
        (FILE_ATTRIBUTE_RECALL_ON_OPEN, True),
        (FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, True),
        (FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | FILE_ATTRIBUTE_REPARSE_POINT, True),
        (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN, False),
    ],
)
def test_offline_placeholders_are_recognised(attrs: int, expected: bool) -> None:
    assert is_offline(attrs) is expected


def test_reparse_point_detection() -> None:
    assert is_reparse_point(FILE_ATTRIBUTE_REPARSE_POINT)
    assert not is_reparse_point(NORMAL)


@pytest.mark.parametrize(
    ("mode", "expected"),
    [(0o644, "0644"), (0o4755, "4755"), (0o2755, "2755"), (0o1777, "1777"), (0, "0000")],
)
def test_describe_posix_mode(mode: int, expected: str) -> None:
    assert describe_posix_mode(stat.S_IFREG | mode) == expected


# ---- bad input -----------------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [-1, 0o200000, True, 1.5, "0644", None])
def test_raw_values_that_are_not_a_mode_are_refused(bad: Any) -> None:
    for function in (posix_permissions, describe_posix_mode):
        with pytest.raises(ModelError):
            function(bad)
    with pytest.raises(ModelError):
        entry_type(bad, None, None)


@pytest.mark.parametrize("bad", [-1, 0x1_0000_0000, True, 2.0, "1"])
def test_raw_values_that_are_not_attributes_are_refused(bad: Any) -> None:
    for function in (
        tracked_windows_attributes,
        is_reparse_point,
        is_offline,
        describe_windows_attributes,
    ):
        with pytest.raises(ModelError):
            function(bad)
    with pytest.raises(ModelError):
        entry_type(stat.S_IFREG, bad, None)
    with pytest.raises(ModelError):
        entry_type(stat.S_IFREG, None, bad)


def test_the_constants_are_the_documented_windows_values() -> None:
    assert (FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM) == (1, 2, 4)
    assert FILE_ATTRIBUTE_REPARSE_POINT == 0x400
    assert FILE_ATTRIBUTE_OFFLINE == 0x1000
    assert FILE_ATTRIBUTE_RECALL_ON_OPEN == 0x40000
    assert FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS == 0x400000
    assert IO_REPARSE_TAG_SYMLINK == 0xA000000C
    assert IO_REPARSE_TAG_MOUNT_POINT == 0xA0000003
    assert perms.TRACKED_WINDOWS_ATTRIBUTES == 0x7
