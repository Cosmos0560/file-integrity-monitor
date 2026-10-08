"""Windows-only test helpers: junctions and file attributes. Only tests use them (src/ never
starts a process), and only inside directories the tests created."""

from __future__ import annotations

import ctypes
import subprocess
import sys
from pathlib import Path

FILE_ATTRIBUTE_NORMAL = 0x80


def make_junction(link: Path, target: Path) -> None:
    """Create the NTFS junction ``link`` pointing at the existing directory ``target``."""
    if sys.platform == "win32":
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            check=True,
            capture_output=True,
        )
    else:
        raise RuntimeError("junctions exist only on Windows")


def set_windows_attributes(path: Path, attributes: int) -> None:
    """Set the exact attribute bits of ``path`` (for example READONLY | HIDDEN)."""
    if sys.platform == "win32":
        if not ctypes.windll.kernel32.SetFileAttributesW(str(path), attributes):
            raise OSError(f"SetFileAttributesW failed for {path.name}")
    else:
        raise RuntimeError("file attributes exist only on Windows")
