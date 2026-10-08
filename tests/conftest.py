"""Shared test setup: environment isolation and the named skip markers.

Skips happen only through the markers declared in pyproject.toml, each with a reason that
``pytest -rs`` prints. Tests touch only temporary directories they create.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterable
from functools import cache
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# Every variable a tool could use to find the real home or config directories.
_HOME_VARIABLES = ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME")


@pytest.fixture(autouse=True)
def isolated_environment(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """Point every home and config variable at a fresh temporary directory."""
    fake_home = tmp_path_factory.mktemp("fake-home")
    for name in _HOME_VARIABLES:
        directory = fake_home / name.lower()
        directory.mkdir()
        monkeypatch.setenv(name, str(directory))
    return fake_home


@cache
def symlinks_supported() -> bool:
    """True if this process may create symlinks (Windows needs a privilege or developer mode)."""
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / "target"
        target.write_text("x", encoding="utf-8")
        try:
            os.symlink(target, Path(directory) / "link")
        except (OSError, NotImplementedError):
            return False
    return True


@cache
def git_available() -> bool:
    """True if git exists and the repository root is a git work tree."""
    git = shutil.which("git")
    if git is None:
        return False
    probe = subprocess.run(
        [git, "rev-parse", "--is-inside-work-tree"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return probe.returncode == 0 and probe.stdout.strip() == "true"


def skip_reason(
    marker_names: Iterable[str], *, platform: str, symlinks: bool, git: bool
) -> str | None:
    """Return why a test with these markers must be skipped here, or None to run it."""
    names = set(marker_names)
    if "windows_only" in names and platform != "win32":
        return "windows_only: needs Windows"
    if "posix_only" in names and platform == "win32":
        return "posix_only: needs a POSIX system"
    if "requires_symlinks" in names and not symlinks:
        return "requires_symlinks: this process cannot create symlinks"
    if "requires_git" in names and not git:
        return "requires_git: git or a git work tree is not available"
    return None


def pytest_runtest_setup(item: pytest.Item) -> None:
    names = [marker.name for marker in item.iter_markers()]
    if not {"windows_only", "posix_only", "requires_symlinks", "requires_git"} & set(names):
        return
    reason = skip_reason(
        names,
        platform=sys.platform,
        symlinks=symlinks_supported() if "requires_symlinks" in names else True,
        git=git_available() if "requires_git" in names else True,
    )
    if reason is not None:
        pytest.skip(reason)
