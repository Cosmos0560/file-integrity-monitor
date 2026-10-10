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
from collections.abc import Iterable, Iterator
from functools import cache
from pathlib import Path

import pytest

import path_guard

REPO_ROOT = Path(__file__).resolve().parents[1]

# Every variable a tool could use to find the real home or config directories.
_HOME_VARIABLES = ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME")


@pytest.fixture(scope="session")
def fake_home_directories(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """One set of empty home and config directories for the whole run.

    Creating and later deleting six directories per test was a measurable share of the gate time
    on Windows (Defender scans every one); the directories are only ever pointed at, never used.
    """
    fake_home = tmp_path_factory.mktemp("fake-home")
    directories = {name: fake_home / name.lower() for name in _HOME_VARIABLES}
    for directory in directories.values():
        directory.mkdir()
    return directories


@pytest.fixture(scope="session", autouse=True)
def session_environment(fake_home_directories: dict[str, Path]) -> Iterator[None]:
    """Point every home and config variable at an empty temporary directory, once per run.

    Setting and restoring five variables around each of 2400 tests was measurable; a test that
    changes one of them uses its own ``monkeypatch``, which restores the value set here.
    """
    with pytest.MonkeyPatch.context() as patch:
        for name, directory in fake_home_directories.items():
            patch.setenv(name, str(directory))
        yield


@pytest.fixture(autouse=True)
def isolated_environment(fake_home_directories: dict[str, Path]) -> Iterator[Path]:
    """Fail any test that wrote into one of the shared fake home directories."""
    yield next(iter(fake_home_directories.values())).parent
    for directory in fake_home_directories.values():
        leftovers = os.listdir(directory)
        if leftovers:
            raise AssertionError(f"a test wrote into the fake home {directory}: {leftovers}")


@pytest.fixture(scope="session", autouse=True)
def fs_path_guard(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    """Make fs/observe.py, fs/safe_files.py and fs/sandbox.py refuse paths outside the pytest
    temp base. The base never changes during a run, so the guard is installed once."""
    base = tmp_path_factory.getbasetemp()
    with pytest.MonkeyPatch.context() as patch:
        for module in path_guard.load_guarded_modules():
            path_guard.install_guard(patch, module, base)
        yield


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


def running_as_root() -> bool:
    """True for a POSIX superuser, who is not stopped by file permissions."""
    return sys.platform != "win32" and os.geteuid() == 0


def skip_reason(
    marker_names: Iterable[str],
    *,
    platform: str,
    symlinks: bool,
    git: bool,
    root: bool = False,
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
    if "requires_non_root" in names and root:
        return "requires_non_root: the superuser ignores file permissions"
    return None


def pytest_runtest_setup(item: pytest.Item) -> None:
    names = [marker.name for marker in item.iter_markers()]
    gated = {"windows_only", "posix_only", "requires_symlinks", "requires_git", "requires_non_root"}
    if not gated & set(names):
        return
    reason = skip_reason(
        names,
        platform=sys.platform,
        symlinks=symlinks_supported() if "requires_symlinks" in names else True,
        git=git_available() if "requires_git" in names else True,
        root=running_as_root() if "requires_non_root" in names else False,
    )
    if reason is not None:
        pytest.skip(reason)
