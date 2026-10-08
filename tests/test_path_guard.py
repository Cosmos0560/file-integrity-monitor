"""The test guard of CLAUDE.md section 6 must trip: a test that reaches outside the pytest
temporary directory through fs/observe.py fails instead of touching the real system."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import path_guard
from conftest import REPO_ROOT
from fim.fs import observe
from fim.fs.observe import RawStat
from path_guard import PathGuardError, is_inside


def test_the_guard_trips_for_every_path_taking_function_given_the_repository() -> None:
    outside = str(REPO_ROOT)
    for call in (
        lambda: observe.lstat(outside),
        lambda: observe.stat_target(outside),
        lambda: observe.read_link(outside),
        lambda: observe.list_dir(outside, 10),
    ):
        with pytest.raises(PathGuardError, match="outside the pytest temporary directory"):
            call()


def test_the_guard_trips_for_hashing_and_does_not_open_anything(tmp_path: Path) -> None:
    inside = observe.lstat(str(tmp_path))
    assert isinstance(inside, RawStat)
    with pytest.raises(PathGuardError):
        observe.hash_file(
            str(REPO_ROOT / "pyproject.toml"), inside, max_bytes=10, should_stop=lambda: False
        )


@pytest.mark.parametrize(
    "outside",
    [
        os.path.expanduser("~"),
        os.path.abspath(os.sep),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "conftest.py"),
        "relative-path-resolved-against-the-working-directory",
    ],
)
def test_the_guard_trips_for_home_root_tests_and_relative_paths(outside: str) -> None:
    with pytest.raises(PathGuardError):
        observe.lstat(outside)


def test_the_guard_trips_for_a_sibling_that_only_shares_a_prefix(tmp_path: Path) -> None:
    sibling = str(tmp_path.parent) + "-sibling"  # the base is the parent of every tmp_path
    with pytest.raises(PathGuardError):
        observe.lstat(sibling)


def test_the_guard_trips_for_a_path_that_is_not_text(tmp_path: Path) -> None:
    with pytest.raises(PathGuardError):
        observe.lstat(tmp_path)  # type: ignore[arg-type]  # a Path object, not the str the API takes


def test_the_guard_trips_when_the_path_is_passed_by_keyword() -> None:
    with pytest.raises(PathGuardError):
        observe.lstat(path=str(REPO_ROOT))


def test_paths_inside_the_temporary_directory_pass_through(tmp_path: Path) -> None:
    (tmp_path / "f").write_bytes(b"x")
    assert isinstance(observe.lstat(str(tmp_path / "f")), RawStat)
    assert isinstance(observe.lstat(path=str(tmp_path)), RawStat)
    listing = observe.list_dir(str(tmp_path), 10)
    assert listing == observe.DirListing(("f",), truncated=False)
    missing = observe.lstat(str(tmp_path / "missing"))
    assert not isinstance(missing, RawStat)  # a real answer, not a guard error


def test_the_temporary_directory_itself_and_a_nul_path_inside_it_are_allowed(
    tmp_path: Path,
) -> None:
    assert isinstance(observe.lstat(str(tmp_path)), RawStat)
    assert not isinstance(observe.lstat(str(tmp_path / "x") + "\0y"), RawStat)


def test_every_path_taking_public_function_of_observe_is_wrapped() -> None:
    names = path_guard.guarded_functions(observe)
    assert set(names) == {"lstat", "stat_target", "read_link", "list_dir", "hash_file"}
    for name in names:
        assert hasattr(getattr(observe, name), "__wrapped__"), name
    assert not hasattr(observe.system_read_ops, "__wrapped__")  # takes no path


def test_the_guard_covers_the_modules_that_exist() -> None:
    modules = path_guard.load_guarded_modules()
    assert observe in modules


def test_is_inside_compares_whole_components(tmp_path: Path) -> None:
    assert is_inside(str(tmp_path), tmp_path)
    assert is_inside(str(tmp_path / "a" / "b"), tmp_path)
    assert not is_inside(str(tmp_path) + "x", tmp_path)
    assert not is_inside(str(tmp_path.parent), tmp_path)
    assert is_inside(str(tmp_path / "a" / ".." / "a"), tmp_path)
    assert not is_inside(str(tmp_path / ".." / "elsewhere"), tmp_path)
