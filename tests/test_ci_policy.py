"""The CI workflow is parsed and held to the policy in PLAN.md Phase 1 and decision D13.

CI itself can only be verified by pushing; these tests keep the file from drifting away from
what was promised: least privilege, cancelled duplicate runs, the full OS and Python matrix,
pinned action majors, and the full gate. ``problems`` returns what is wrong with a workflow;
the real file must have none, and planted mutations must each be caught.
"""

from __future__ import annotations

import copy
import re
import tomllib
from collections.abc import Callable
from typing import Any

import pytest
import yaml

from conftest import REPO_ROOT

WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
EXPECTED_ACTIONS = ["actions/checkout@v5", "actions/setup-python@v6"]
EXPECTED_COMMANDS = ['python -m pip install -e ".[dev]"', "python scripts/gate.py --full"]
FORBIDDEN_TEXT = (
    "pull_request_target",
    "secrets.",
    "continue-on-error",
    "github.event",  # untrusted event data must not reach a shell
    "workflow_dispatch",
    "@main",
    "@master",
    "|| true",
)

Workflow = dict[Any, Any]


def problems(workflow: Workflow, text: str) -> list[str]:
    """Everything that breaks the CI policy, as short messages (empty if it holds)."""
    found: list[str] = []
    triggers = workflow.get("on", workflow.get(True))  # YAML 1.1 reads bare `on` as True
    if not isinstance(triggers, dict) or set(triggers) != {"push", "pull_request"}:
        found.append("triggers must be push and pull_request only")
    elif triggers["push"] != {"branches": ["main"]}:
        found.append("push must be limited to the main branch")
    if workflow.get("permissions") != {"contents": "read"}:
        found.append("permissions must be contents: read")
    concurrency = workflow.get("concurrency") or {}
    if concurrency.get("cancel-in-progress") is not True:
        found.append("concurrency must cancel in-progress runs")
    group = str(concurrency.get("group", ""))
    if "github.workflow" not in group or "github.ref" not in group:
        found.append("concurrency group must use workflow and ref")

    jobs = workflow.get("jobs") or {}
    if list(jobs) != ["gate"]:
        return [*found, "there must be exactly one job named gate"]
    job = jobs["gate"]
    if "permissions" in job:
        found.append("the job must not set its own permissions")
    if job.get("timeout-minutes") != 15:
        found.append("the job needs timeout-minutes: 15")
    if job.get("runs-on") != "${{ matrix.os }}":
        found.append("runs-on must come from the matrix")
    strategy = job.get("strategy") or {}
    if strategy.get("fail-fast") is not False:
        found.append("fail-fast must be false")
    matrix = strategy.get("matrix") or {}
    if matrix.get("os") != ["ubuntu-24.04", "windows-latest"]:
        found.append("matrix os must be ubuntu-24.04 and windows-latest")
    if matrix.get("python-version") != ["3.11", "3.12", "3.13"]:
        found.append("matrix python-version must be the strings 3.11, 3.12, 3.13")

    steps = job.get("steps") or []
    used = [step["uses"] for step in steps if "uses" in step]
    if used != EXPECTED_ACTIONS:
        found.append(f"actions must be exactly {EXPECTED_ACTIONS}")
    if not all(re.fullmatch(r"[\w.-]+/[\w.-]+@v\d+", reference) for reference in used):
        found.append("every action must be pinned to a major version tag")
    setup = [s for s in steps if str(s.get("uses", "")).startswith("actions/setup-python")]
    if [s.get("with") for s in setup] != [{"python-version": "${{ matrix.python-version }}"}]:
        found.append("setup-python must use the matrix python-version")
    commands = [step["run"] for step in steps if "run" in step]
    if commands != EXPECTED_COMMANDS:
        found.append(f"run steps must be exactly {EXPECTED_COMMANDS}")
    found.extend(f"workflow text contains '{word}'" for word in FORBIDDEN_TEXT if word in text)
    return found


def load() -> tuple[Workflow, str]:
    text = WORKFLOW.read_text(encoding="utf-8")
    loaded = yaml.safe_load(text)
    assert isinstance(loaded, dict)
    return loaded, text


def test_the_real_workflow_satisfies_the_policy() -> None:
    workflow, text = load()
    assert problems(workflow, text) == []


def test_matrix_python_versions_match_the_project_metadata() -> None:
    workflow, _ = load()
    versions = workflow["jobs"]["gate"]["strategy"]["matrix"]["python-version"]
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    classifiers = {
        c.rsplit(" :: ", 1)[1]
        for c in project["classifiers"]
        if re.fullmatch(r"Programming Language :: Python :: 3\.\d+", c)
    }
    assert classifiers == set(versions)
    assert project["requires-python"] == ">=3.11"


def _job(workflow: Workflow) -> dict[str, Any]:
    job = workflow["jobs"]["gate"]
    assert isinstance(job, dict)
    return job


def _step_run(workflow: Workflow, command: str, new: str) -> None:
    for step in _job(workflow)["steps"]:
        if step.get("run") == command:
            step["run"] = new


MUTATIONS: list[tuple[str, Callable[[Workflow], None], str]] = [
    ("write-all permissions", lambda w: w.update(permissions="write-all"), "permissions"),
    ("no permissions", lambda w: w.pop("permissions"), "permissions"),
    (
        "job widens permissions",
        lambda w: _job(w).update(permissions={"contents": "write"}),
        "job must not",
    ),
    ("no concurrency", lambda w: w.pop("concurrency"), "concurrency"),
    (
        "no cancelling",
        lambda w: w["concurrency"].update({"cancel-in-progress": False}),
        "cancel in-progress",
    ),
    ("group without ref", lambda w: w["concurrency"].update(group="ci"), "group"),
    ("extra trigger", lambda w: w[True].update(workflow_dispatch={}), "triggers"),
    ("push to any branch", lambda w: w[True].update(push={}), "main branch"),
    (
        "no windows",
        lambda w: _job(w)["strategy"]["matrix"].update(os=["ubuntu-24.04"]),
        "matrix os",
    ),
    (
        "old python",
        lambda w: _job(w)["strategy"]["matrix"].update({"python-version": ["3.10", "3.11"]}),
        "python-version",
    ),
    (
        "unquoted python float",
        lambda w: _job(w)["strategy"]["matrix"].update({"python-version": [3.11, 3.12, 3.13]}),
        "python-version",
    ),
    ("fail fast", lambda w: _job(w)["strategy"].update({"fail-fast": True}), "fail-fast"),
    ("long timeout", lambda w: _job(w).update({"timeout-minutes": 360}), "timeout"),
    ("no timeout", lambda w: _job(w).pop("timeout-minutes"), "timeout"),
    ("fixed runner", lambda w: _job(w).update({"runs-on": "ubuntu-latest"}), "runs-on"),
    (
        "unpinned action",
        lambda w: _job(w)["steps"][0].update(uses="actions/checkout@main"),
        "actions must be",
    ),
    (
        "action without a version",
        lambda w: _job(w)["steps"][0].update(uses="actions/checkout"),
        "pinned",
    ),
    (
        "third-party action",
        lambda w: _job(w)["steps"].insert(1, {"uses": "someone/else@v1"}),
        "actions must be",
    ),
    (
        "gate without --full",
        lambda w: _step_run(w, "python scripts/gate.py --full", "python scripts/gate.py"),
        "run steps",
    ),
    (
        "failures ignored",
        lambda w: _step_run(
            w, "python scripts/gate.py --full", "python scripts/gate.py --full || true"
        ),
        "run steps",
    ),
    (
        "second job",
        lambda w: w["jobs"].update(extra={"runs-on": "ubuntu-24.04", "steps": []}),
        "exactly one job",
    ),
]


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [pytest.param(m, e, id=name) for name, m, e in MUTATIONS],
)
def test_each_planted_policy_violation_is_caught(
    mutate: Callable[[Workflow], None], expected: str
) -> None:
    workflow, text = load()
    mutated = copy.deepcopy(workflow)
    mutate(mutated)
    found = problems(mutated, text)
    assert any(expected in message for message in found), found


@pytest.mark.parametrize(
    "word", ["pull_request_target", "secrets.", "continue-on-error", "github.event", "@master"]
)
def test_forbidden_text_is_caught(word: str) -> None:
    workflow, text = load()
    found = problems(workflow, text + f"\n# {word}\n")
    assert any(word in message for message in found), found
