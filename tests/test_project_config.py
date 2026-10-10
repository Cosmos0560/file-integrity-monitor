"""pyproject.toml and the repository's top-level files, held to the approved decisions."""

from __future__ import annotations

import re
import tomllib
from typing import Any

import pytest

import gate
from conftest import REPO_ROOT
from fim import __version__


@pytest.fixture(scope="module")
def pyproject() -> dict[str, Any]:
    return tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_the_only_runtime_dependency_is_pyyaml(pyproject: dict[str, Any]) -> None:
    dependencies = pyproject["project"]["dependencies"]
    assert len(dependencies) == 1
    assert re.match(r"(?i)pyyaml\b", dependencies[0])


def test_dev_extras_are_the_approved_tools(pyproject: dict[str, Any]) -> None:
    names = {
        re.split(r"[<>=!~ ]", spec, maxsplit=1)[0]
        for spec in pyproject["project"]["optional-dependencies"]["dev"]
    }
    assert names == {"pytest", "pytest-cov", "ruff", "mypy", "types-PyYAML"}


def test_every_dev_tool_has_a_lower_and_an_upper_bound(pyproject: dict[str, Any]) -> None:
    """Known gap 5: an unpinned linter or type checker can break CI without a code change."""
    for spec in pyproject["project"]["optional-dependencies"]["dev"]:
        assert re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*>=[0-9][0-9.]*,<[0-9][0-9.]*", spec), spec


def test_ruff_and_mypy_are_pinned_to_one_minor_series(pyproject: dict[str, Any]) -> None:
    # Both ship rule or behaviour changes in minor releases; the others only in majors.
    specs = {
        re.split(r"[<>=]", spec, maxsplit=1)[0]: spec
        for spec in pyproject["project"]["optional-dependencies"]["dev"]
    }
    for tool in ("ruff", "mypy"):
        lower = re.search(r">=(\d+)\.(\d+)", specs[tool])
        upper = re.search(r"<(\d+)\.(\d+)", specs[tool])
        assert lower is not None
        assert upper is not None
        assert upper.group(1) == lower.group(1)
        assert int(upper.group(2)) == int(lower.group(2)) + 1


def test_release_only_tools_are_not_in_the_dev_extras(pyproject: dict[str, Any]) -> None:
    extras = pyproject["project"]["optional-dependencies"]
    assert set(extras["release"]) == {"build", "pip-audit", "bandit"}
    assert not set(extras["release"]) & set(extras["dev"])


def test_rejected_dependencies_are_absent(pyproject: dict[str, Any]) -> None:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8").lower()
    for rejected in ("rich", "click", "blake3", "xxhash"):
        assert not re.search(rf'"{rejected}[>=<"\[ ]', text), rejected


def test_build_backend_name_script_and_version_source(pyproject: dict[str, Any]) -> None:
    assert pyproject["build-system"]["build-backend"] == "hatchling.build"
    project = pyproject["project"]
    assert project["name"] == "file-integrity-monitor"
    assert project["scripts"] == {"fim": "fim.cli.main:main"}
    assert project["dynamic"] == ["version"]
    assert pyproject["tool"]["hatch"]["version"]["path"] == "src/fim/__init__.py"
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__)


def test_license_is_mit_and_authors_carry_a_name_only(pyproject: dict[str, Any]) -> None:
    project = pyproject["project"]
    assert project["license"] == "MIT"
    assert (REPO_ROOT / "LICENSE").read_text(encoding="utf-8").startswith("MIT License")
    assert project["authors"]
    for author in project["authors"]:
        assert set(author) == {"name"}


def test_coverage_threshold_is_85_everywhere(pyproject: dict[str, Any]) -> None:
    coverage = pyproject["tool"]["coverage"]
    assert coverage["report"]["fail_under"] == 85
    assert coverage["run"]["branch"] is True
    assert coverage["run"]["source"] == ["fim"]
    assert gate.COVERAGE_MIN == 85


def test_pytest_is_strict_and_every_marker_is_declared(pyproject: dict[str, Any]) -> None:
    options = pyproject["tool"]["pytest"]["ini_options"]
    assert "--strict-markers" in options["addopts"]
    assert "-ra" in options["addopts"]  # skips and failures are listed, so skips are visible
    assert options["filterwarnings"] == ["error"]
    declared = {marker.split(":", 1)[0] for marker in options["markers"]}
    assert declared == {
        "slow",
        "requires_symlinks",
        "requires_git",
        "posix_only",
        "windows_only",
        "requires_non_root",
    }


def test_mypy_is_strict_for_the_oldest_supported_python(pyproject: dict[str, Any]) -> None:
    mypy = pyproject["tool"]["mypy"]
    assert mypy["strict"] is True
    assert mypy["python_version"] == "3.11"
    assert set(mypy["files"]) == {"src", "scripts", "tests"}


def test_ruff_has_no_blanket_ignores(pyproject: dict[str, Any]) -> None:
    lint = pyproject["tool"]["ruff"]["lint"]
    assert "ignore" not in lint
    for pattern, rules in lint["per-file-ignores"].items():
        assert pattern in {"tests/**", "scripts/**", "src/fim/cli/**"}
        assert "ALL" not in rules


def test_security_policy_uses_private_reporting_and_no_email() -> None:
    text = (REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "private vulnerability reporting" in text.lower()
    assert "@" not in text


def test_readme_makes_no_absolute_security_claims_and_is_no_longer_a_placeholder() -> None:
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8").lower()
    assert "work in progress" not in text  # Phase 6 made it the real README
    for claim in ("tamper-proof", "unbreakable", "unhackable", "guarantees", "100% secure"):
        assert claim not in text
    # Every measured number in it is checked against docs/performance.md by tests/test_docs.py.


def test_venv_and_secrets_are_ignored_by_git() -> None:
    patterns = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    for expected in (".venv/", "*.key", "*.baseline*", "__pycache__/", "build/", "dist/"):
        assert expected in patterns


def test_line_endings_are_pinned_to_lf() -> None:
    attributes = (REPO_ROOT / ".gitattributes").read_text(encoding="utf-8")
    assert "eol=lf" in attributes
