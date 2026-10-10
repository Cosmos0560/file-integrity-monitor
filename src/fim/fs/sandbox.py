"""The demo's own temporary tree: the only module that creates, changes or deletes files that are
not the tool's own key, baseline, anchor or output (PLAN.md section 1.1).

It may be imported by ``app/demo.py`` only (the architecture check enforces it). Everything it
does is confined to one directory that ``Sandbox.create`` makes with ``tempfile.mkdtemp`` (a new,
uniquely named directory, mode 0700 on POSIX): every relative path is checked to be a plain
descent below that root (no absolute path, no drive, no ``..``, no empty or dot component, no NUL,
no separator inside a component), the directory itself is never a link, and ``destroy`` removes
exactly that tree, never following a link out of it, clearing the read-only bit on Windows (and
write protection on POSIX directories) first, and then checks that the directory is gone.
"""

from __future__ import annotations

import contextlib
import os
import stat
import tempfile

from fim.core.errors import FileAccessError
from fim.core.models import EntryType
from fim.core.perms import entry_type
from fim.core.sanitize import clip_escaped

__all__ = ["Sandbox", "SandboxError"]

_PREFIX = "fim-demo-"
_SHOWN_CHARS = 120
_WRITABLE_DIRECTORY = stat.S_IRWXU
_WRITABLE_FILE = stat.S_IREAD | stat.S_IWRITE


class SandboxError(FileAccessError):
    """The demo's temporary tree could not be created, changed or removed."""


def _bad_component(component: str) -> bool:
    return (
        component in ("", ".", "..")
        or "\x00" in component
        or "/" in component
        or "\\" in component
        or (os.sep != "/" and ":" in component)  # a drive letter or an alternate data stream
    )


class Sandbox:
    """One temporary directory and the files the demo puts in it."""

    def __init__(self, root: str) -> None:
        self.root = root

    @classmethod
    def create(cls, base_directory: str | None = None) -> Sandbox:
        """Make a new, empty directory under ``base_directory`` (the system temp when None)."""
        try:
            root = tempfile.mkdtemp(prefix=_PREFIX, dir=base_directory)
        except OSError as exc:
            name = clip_escaped(base_directory or "the system temporary directory", _SHOWN_CHARS)
            raise SandboxError(
                f"could not create a temporary directory in {name} ({type(exc).__name__})"
            ) from None
        return cls(os.path.abspath(root))

    def path(self, relative: str) -> str:
        """The absolute path of ``relative`` ("/" separated) inside the sandbox, or an error."""
        parts = relative.split("/")
        if any(_bad_component(part) for part in parts):
            raise SandboxError(f"not a plain path below the sandbox: {clip_escaped(relative, 80)}")
        return os.path.join(self.root, *parts)

    def exists(self) -> bool:
        return os.path.lexists(self.root)

    def make_directory(self, relative: str) -> None:
        try:
            os.makedirs(self.path(relative), exist_ok=True)
        except OSError as exc:
            raise self._failed("create the directory", relative, exc) from None

    def write_file(self, relative: str, data: bytes) -> None:
        """Create the file, or replace its content (the parent directory is made if needed)."""
        target = self.path(relative)
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as handle:
                handle.write(data)
        except OSError as exc:
            raise self._failed("write", relative, exc) from None

    def remove_file(self, relative: str) -> None:
        try:
            os.unlink(self.path(relative))
        except OSError as exc:
            raise self._failed("delete", relative, exc) from None

    def set_mode(self, relative: str, mode: int) -> None:
        """chmod; on Windows only the read-only bit of ``mode`` has any effect."""
        try:
            os.chmod(self.path(relative), mode)
        except OSError as exc:
            raise self._failed("change the permissions of", relative, exc) from None

    def flip_byte(self, relative: str, offset: int) -> None:
        """Change one byte in place (the demo's stand-in for tampering with a baseline).

        A negative ``offset`` counts from the end of the file.
        """
        target = self.path(relative)
        try:
            with open(target, "r+b") as handle:
                handle.seek(offset, os.SEEK_END if offset < 0 else os.SEEK_SET)
                position = handle.tell()
                byte = handle.read(1)
                if not byte:
                    raise SandboxError("the offset is beyond the end of the file")
                handle.seek(position)
                handle.write(bytes([byte[0] ^ 0x01]))
        except OSError as exc:
            raise self._failed("modify", relative, exc) from None

    def _failed(self, action: str, relative: str, exc: OSError) -> SandboxError:
        return SandboxError(
            f"the demo could not {action} {clip_escaped(relative, 80)} ({type(exc).__name__})"
        )

    def destroy(self) -> None:
        """Remove the whole tree and verify that it is gone; raise ``SandboxError`` if not.

        The tree is walked by hand with ``lstat``: an entry that is a link or any reparse point
        (a symlink, or on Windows a junction, which ``os.walk`` would descend into) is removed
        as itself and never entered, so what it points at is never touched.
        """
        problems = _remove_tree(self.root)
        if os.path.lexists(self.root):
            raise SandboxError(
                f"the demo's temporary directory could not be removed completely "
                f"({problems} problems): {clip_escaped(self.root, _SHOWN_CHARS)}"
            )


def _is_link(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", None)
    tag = getattr(info, "st_reparse_tag", None)
    return entry_type(info.st_mode, attributes, tag) in (EntryType.SYMLINK, EntryType.REPARSE)


def _remove_tree(path: str) -> int:
    """Remove ``path`` and everything below it; return how many entries could not be removed.

    An entry that is already gone counts as a problem here, which is harmless: ``destroy`` only
    complains when the root still exists afterwards.
    """
    try:
        info = os.lstat(path)
    except OSError:
        return 1
    if _is_link(info) or not stat.S_ISDIR(info.st_mode):
        return _remove_entry(path, writable_first=not _is_link(info))
    problems = 0
    # A directory without write permission (POSIX) stops its children's removal, and the
    # read-only bit (Windows) stops its own.
    with contextlib.suppress(OSError):
        os.chmod(path, _WRITABLE_DIRECTORY)
    try:
        names = os.listdir(path)
    except OSError:
        names = []
        problems += 1
    for name in names:
        problems += _remove_tree(os.path.join(path, name))
    try:
        os.rmdir(path)
    except OSError:
        problems += 1
    return problems


def _remove_entry(path: str, *, writable_first: bool) -> int:
    """Remove one file or link (a symlink or junction is removed as itself, never entered)."""
    if writable_first:
        with contextlib.suppress(OSError):
            os.chmod(path, _WRITABLE_FILE)  # clears the read-only bit on Windows
    try:
        os.unlink(path)
    except OSError:
        return 1
    return 0
