"""README.md and docs/ against the code (PLAN.md Phase 6).

Documented values are not trusted by eye: the limits table, the exit codes, every command option
with its choices and default, the version, and every test the documents name are compared with
the code or with the test files themselves.
"""

from __future__ import annotations

import argparse
import ast
import re
from collections.abc import Iterator
from functools import cache
from pathlib import Path

from conftest import REPO_ROOT
from fim import __version__
from fim.cli.main import build_parser
from fim.core import limits
from fim.core.errors import EXIT_PRECEDENCE, ExitCode
from plan_doc import parse_quantity

README = REPO_ROOT / "README.md"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
DOCS = REPO_ROOT / "docs"
CHECKED_DOCUMENTS = (
    README,
    DOCS / "threat-model.md",
    DOCS / "performance.md",
    DOCS / "siem-mapping.md",
    DOCS / "report-schema.md",
    CHANGELOG,
)
TEST_REFERENCE = re.compile(r"`(tests/[\w/]+\.py)::(\w+)`")
_LOCAL_TRACES = ("C:\\Users", "C:\\\\Users", "/Users/", "AppData", "Lenovo")


def text_of(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def section(text: str, heading: str) -> str:
    """The lines under ``heading`` (a full heading line) up to the next heading of its level.

    Lines inside fenced code blocks are never headings.
    """
    level = len(heading) - len(heading.lstrip("#"))
    lines = text.splitlines()
    start = lines.index(heading)
    body: list[str] = []
    in_fence = False
    for line in lines[start + 1 :]:
        if line.startswith("```"):
            in_fence = not in_fence
        elif not in_fence:
            hashes = len(line) - len(line.lstrip("#"))
            if 0 < hashes <= level and line[hashes : hashes + 1] == " ":
                break
        body.append(line)
    return "\n".join(body)


def table_rows(block: str) -> Iterator[list[str]]:
    """The cells of every data row of every markdown table in ``block``."""
    for line in block.splitlines():
        if line.startswith("|") and not re.fullmatch(r"\|[-| :]+\|", line):
            yield [cell.strip() for cell in line.strip().strip("|").split("|")]


@cache
def defined_tests_in(path: Path) -> frozenset[str]:
    """Names of the test functions a test file defines at module level or in a Test class."""
    tree = ast.parse(text_of(path))
    found: set[str] = set()
    containers: list[list[ast.stmt]] = [tree.body]
    containers += [node.body for node in tree.body if isinstance(node, ast.ClassDef)]
    for body in containers:
        for node in body:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and (
                node.name.startswith("test_")
            ):
                found.add(node.name)
    return frozenset(found)


# ---- tests the documents name --------------------------------------------------------------------


def test_every_test_named_in_the_documents_exists() -> None:
    checked = 0
    for document in CHECKED_DOCUMENTS:
        if not document.exists():
            continue
        for file_name, test_name in TEST_REFERENCE.findall(text_of(document)):
            path = REPO_ROOT / file_name
            assert path.is_file(), f"{document.name} names {file_name}, which does not exist"
            assert test_name in defined_tests_in(path), (
                f"{document.name} names {file_name}::{test_name}, which is not a test there"
            )
            checked += 1
    assert checked >= 60  # the README table and the threat model name a lot of tests


def test_every_row_of_the_claims_table_names_evidence_that_exists() -> None:
    block = section(text_of(README), "## Security properties and the evidence for them")
    rows = [cells for cells in table_rows(block) if cells[0] != "Claim"]
    assert len(rows) >= 15
    for cells in rows:
        assert len(cells) == 2, cells
        claim, evidence = cells
        assert claim
        tests = TEST_REFERENCE.findall(evidence)
        documents = [
            reference
            for reference in re.findall(r"`([\w./-]+\.(?:md|py))`", evidence)
            if not reference.startswith("tests/") or "::" not in reference
        ]
        assert tests or documents, f"no evidence in the row: {claim}"
        for reference in documents:
            assert (REPO_ROOT / reference).is_file(), f"{reference} does not exist ({claim})"


def test_the_threat_model_names_a_test_for_every_control_row() -> None:
    block = section(text_of(DOCS / "threat-model.md"), "## 4. Threats, controls and what is left")
    rows = [cells for cells in table_rows(block) if re.fullmatch(r"T\d+", cells[0])]
    assert len(rows) >= 15
    for cells in rows:
        evidence = cells[-1]
        assert TEST_REFERENCE.search(evidence) or "not testable" in evidence, cells[0]


# ---- limits, exit codes and defaults -------------------------------------------------------------


def test_the_readme_limits_table_matches_limits_py() -> None:
    block = section(text_of(README), "### Limits")
    documented: set[str] = set()
    rows = 0
    for label, default_cell, ceiling_cell in (
        cells[:3] for cells in table_rows(block) if cells[0] != "Constant"
    ):
        rows += 1
        if label.startswith("watch interval"):
            parts = [parse_quantity(part) for part in default_cell.split("/")]
            assert parts == [
                limits.WATCH_INTERVAL_MIN_SECONDS,
                limits.WATCH_INTERVAL_DEFAULT_SECONDS,
                limits.WATCH_INTERVAL_MAX_SECONDS,
            ]
            continue
        names = re.findall(r"`(\w+)`", label)
        documented.update(names)
        defaults = [parse_quantity(part) for part in default_cell.split("/")]
        assert defaults == [getattr(limits, name) for name in names], label
        if ceiling_cell == "same":
            ceilings: list[int | None] = list(defaults)
        elif ceiling_cell == "-":
            ceilings = [None] * len(names)
        else:
            ceilings = [parse_quantity(part) for part in ceiling_cell.split("/")]
        assert ceilings == [getattr(limits, name + "_CEILING", None) for name in names], label
    assert rows == 14
    in_code = {
        name
        for name in dir(limits)
        if re.fullmatch(r"MAX_[A-Z_]+", name) and not name.endswith("_CEILING")
    }
    assert documented - {"HASH_CHUNK_BYTES"} == in_code


def test_the_readme_exit_codes_match_the_code() -> None:
    block = section(text_of(README), "## Exit codes")
    codes = {int(cells[0]) for cells in table_rows(block) if cells[0].isdigit()}
    assert codes == {int(code) for code in ExitCode}
    precedence = re.search(r"Precedence[^:]*: ([\d >]+)", block)
    assert precedence is not None
    stated = [int(number) for number in re.findall(r"\d", precedence.group(1))]
    assert stated == [int(code) for code in EXIT_PRECEDENCE]


def _subcommands() -> dict[str, argparse.ArgumentParser]:
    parser = build_parser()
    for action in parser._actions:  # argparse offers no public way to list them
        if isinstance(action, argparse._SubParsersAction):
            return dict(action.choices)
    raise AssertionError("the parser has no commands")


def test_every_cli_option_and_default_is_documented_in_the_readme() -> None:
    text = text_of(README)
    commands = _subcommands()
    assert set(commands) == {"init-key", "baseline", "check", "watch", "demo"}
    for name, command in commands.items():
        body = section(text, f"### `fim {name}`")
        for action in command._actions:
            if isinstance(action, argparse._HelpAction):
                continue
            for option in action.option_strings:
                assert f"`{option}" in body, f"fim {name}: {option} is not documented"
            for choice in action.choices or ():
                assert str(choice) in body, f"fim {name}: choice {choice} is not documented"
            default = action.default
            if action.option_strings and default not in (None, False, True):
                assert f"`{default}`" in body or f"{default}" in body, (
                    f"fim {name}: the default of {action.option_strings[0]} ({default}) "
                    "is not documented"
                )
    assert "`fim --version`" in text


# ---- version and pasted output -------------------------------------------------------------------


def test_the_version_in_the_readme_and_the_changelog_is_the_package_version() -> None:
    readme = text_of(README)
    assert f"Version {__version__}." in readme
    for found in re.findall(r"\bfim (\d+\.\d+\.\d+)", readme):
        assert found == __version__
    for found in re.findall(r'"tool_version":"([^"]+)"', readme):
        assert found == __version__
    first_release = re.search(r"^## \[?(\d+\.\d+\.\d+)\]?", text_of(CHANGELOG), re.MULTILINE)
    assert first_release is not None
    assert first_release.group(1) == __version__


def test_the_documents_carry_no_trace_of_the_machine_they_were_made_on() -> None:
    for document in CHECKED_DOCUMENTS:
        if not document.exists():
            continue
        text = text_of(document)
        for trace in _LOCAL_TRACES:
            assert trace not in text, f"{document.name} contains {trace!r}"


def test_pasted_output_blocks_state_their_exit_code() -> None:
    """Every block that starts with a `$ fim` command ends with the exit code that was seen."""
    blocks = re.findall(r"```\n(\$ fim .*?)```", text_of(README), re.DOTALL)
    assert len(blocks) >= 8
    for block in blocks:
        assert re.search(r"\[exit code \d\]\s*$", block), block.splitlines()[0]


# ---- performance.md ------------------------------------------------------------------------------


def test_the_numbers_in_the_readme_performance_table_appear_in_performance_md() -> None:
    """The README quotes only measured numbers: each one is copied from performance.md."""
    block = section(text_of(README), "## Performance")
    measured = text_of(DOCS / "performance.md")
    rows = [cells for cells in table_rows(block) if cells[0] != "What"]
    assert len(rows) >= 5
    for cells in rows:
        for number in re.findall(r"\d[\d,]*(?:\.\d+)?", " ".join(cells)):
            assert number in measured, f"{number!r} (README: {cells[0]}) is not in performance.md"


def test_measured_numbers_in_the_limitations_are_in_performance_md() -> None:
    """A number with a time or memory unit in the Limitations is a measurement: it is copied."""
    block = section(text_of(README), "## Limitations")
    measured = text_of(DOCS / "performance.md")
    found = re.findall(r"(\d[\d,]*(?:\.\d+)?)\s*(?:MiB|GiB|ms|s)\b", block)
    assert len(found) >= 4
    for number in found:
        assert number in measured, f"{number!r} in the Limitations is not in performance.md"


def test_performance_md_states_its_machine_and_a_command_for_every_table() -> None:
    text = text_of(DOCS / "performance.md")
    for field in ("- machine:", "- operating system:", "- Python:", "- date:"):
        assert field in text, f"performance.md does not state {field!r}"
    # Every table is preceded, in its own section, by the command that produced it.
    sections = re.split(r"^## ", text, flags=re.MULTILINE)[1:]
    tables = 0
    for body in sections:
        found = [i for i, line in enumerate(body.splitlines()) if line.startswith("|")]
        if not found:
            continue
        tables += 1
        first = body.splitlines()[found[0]]
        before = body[: body.index(first)]
        assert "command:" in before.lower(), body.splitlines()[0]
    assert tables >= 3
    assert "MAX_BASELINE_BYTES" in text
    assert f"{limits.MAX_BASELINE_BYTES // limits.MIB} MiB" in text
