"""Architecture checker: layers, cycles, import resolution and failing closed.

Every rule has a planted violation that must trip it, and the real tree must pass.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import check_architecture as arch
from arch_helpers import check, make_tree, rules

REPO_ROOT = Path(__file__).resolve().parents[1]


# Slow: the gate's own "architecture" step runs the same checker over the same tree on every
# default gate, so this copy only matters to --full and CI (about 1 s under coverage).
@pytest.mark.slow
def test_the_real_source_tree_passes() -> None:
    violations, count = arch.run_checks(REPO_ROOT / "src")
    assert [v.format() for v in violations] == []
    assert count >= 5


def test_clean_tree_with_allowed_imports_passes(tmp_path: Path) -> None:
    files = {
        "core/limits.py": "X = 1\n",
        "core/models.py": "from fim.core import limits\nY = limits.X\n",
        "cli/main.py": "from fim.core.models import Y\nfrom fim import core\n",
    }
    assert check(tmp_path, files) == []


def test_relative_imports_are_resolved(tmp_path: Path) -> None:
    files = {
        "core/limits.py": "X = 1\n",
        "core/models.py": "from . import limits\nfrom .limits import X\nY = X\n",
    }
    assert check(tmp_path, files) == []


# ---- A001 -----------------------------------------------------------------------------------


def test_a001_module_without_a_layer_is_rejected(tmp_path: Path) -> None:
    violations = check(tmp_path, {"core/mystery.py": "X = 1\n"})
    assert rules(violations) == ["A001"]
    assert "fim.core.mystery" in violations[0].message


def test_a001_new_top_level_package_is_rejected(tmp_path: Path) -> None:
    assert "A001" in rules(check(tmp_path, {"extras/thing.py": "X = 1\n"}))


# ---- A002 -----------------------------------------------------------------------------------


def test_a002_lower_layer_importing_a_higher_layer(tmp_path: Path) -> None:
    files = {"cli/main.py": "X = 1\n", "core/limits.py": "from fim.cli import main\n"}
    violations = check(tmp_path, files)
    assert rules(violations) == ["A002"]
    assert "higher layer" in violations[0].message


def test_a002_same_layer_import_that_is_not_listed(tmp_path: Path) -> None:
    files = {"core/limits.py": "X = 1\n", "core/sanitize.py": "from fim.core import limits\n"}
    violations = check(tmp_path, files)
    assert rules(violations) == ["A002"]
    assert "unlisted same-layer" in violations[0].message


def test_a002_listed_same_layer_import_is_allowed(tmp_path: Path) -> None:
    files = {"core/sanitize.py": "X = 1\n", "core/errors.py": "from fim.core import sanitize\n"}
    assert check(tmp_path, files) == []


def test_a002_import_inside_a_function_is_still_checked(tmp_path: Path) -> None:
    files = {
        "cli/main.py": "X = 1\n",
        "core/limits.py": "def late() -> None:\n    from fim.cli import main\n",
    }
    assert rules(check(tmp_path, files)) == ["A002"]


def test_a002_type_checking_import_is_still_checked(tmp_path: Path) -> None:
    files = {
        "cli/main.py": "X = 1\n",
        "core/limits.py": (
            "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from fim.cli import main\n"
        ),
    }
    assert rules(check(tmp_path, files)) == ["A002"]


def test_a002_root_package_may_not_import_the_rest(tmp_path: Path) -> None:
    src = make_tree(tmp_path, {"core/limits.py": "X = 1\n"})
    (src / "fim" / "__init__.py").write_text("from fim.core import limits\n", encoding="utf-8")
    assert rules(arch.check_tree(src)) == ["A002"]


def test_a002_every_layer_may_import_the_root_package(tmp_path: Path) -> None:
    files = {"core/limits.py": "from fim import __version__\n"}
    assert check(tmp_path, files) == []


# ---- A003 -----------------------------------------------------------------------------------


def test_a003_two_module_cycle_is_found(tmp_path: Path) -> None:
    files = {
        "core/errors.py": "from fim.core import sanitize\n",
        "core/sanitize.py": "from fim.core import errors\n",
    }
    violations = check(tmp_path, files)
    assert "A003" in rules(violations)
    cycle = next(v for v in violations if v.rule == "A003")
    assert "fim.core.errors" in cycle.message
    assert "fim.core.sanitize" in cycle.message


def test_a003_cycle_hidden_in_a_function_is_found(tmp_path: Path) -> None:
    files = {
        "core/errors.py": "from fim.core import sanitize\n",
        "core/sanitize.py": "def f() -> None:\n    import fim.core.errors\n",
    }
    assert "A003" in rules(check(tmp_path, files))


def test_a003_cycle_hidden_behind_type_checking_is_found(tmp_path: Path) -> None:
    files = {
        "core/errors.py": "from fim.core import sanitize\n",
        "core/sanitize.py": (
            "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from fim.core import errors\n"
        ),
    }
    assert "A003" in rules(check(tmp_path, files))


def test_a003_three_module_cycle_is_found(tmp_path: Path) -> None:
    files = {
        "core/limits.py": "from fim.core import models\n",
        "core/models.py": "from fim.core import errors\n",
        "core/errors.py": "from fim.core import limits\n",
    }
    violations = check(tmp_path, files)
    cycle = next(v for v in violations if v.rule == "A003")
    assert cycle.message.count("fim.core.") == 3


def test_a003_self_import_is_a_cycle(tmp_path: Path) -> None:
    assert "A003" in rules(check(tmp_path, {"core/limits.py": "import fim.core.limits\n"}))


def test_find_cycles_ignores_acyclic_graphs() -> None:
    edges = [
        arch.ImportEdge("a", "b", 1),
        arch.ImportEdge("b", "c", 1),
        arch.ImportEdge("a", "c", 1),
    ]
    assert arch.find_cycles(edges) == []


# ---- A004 -----------------------------------------------------------------------------------


def test_a004_from_import_of_a_missing_module(tmp_path: Path) -> None:
    files = {"core/limits.py": "from fim.core.nosuchmodule import thing\n"}
    violations = check(tmp_path, files)
    assert rules(violations) == ["A004"]
    assert "fim.core.nosuchmodule" in violations[0].message


def test_a004_plain_import_of_a_missing_module(tmp_path: Path) -> None:
    assert rules(check(tmp_path, {"core/limits.py": "import fim.nosuch\n"})) == ["A004"]


def test_a004_relative_import_leaving_the_package(tmp_path: Path) -> None:
    violations = check(tmp_path, {"core/limits.py": "from ... import elsewhere\n"})
    assert rules(violations) == ["A004"]
    assert "leaves the package" in violations[0].message


def test_import_of_a_name_inside_an_existing_module_is_not_a_missing_module(
    tmp_path: Path,
) -> None:
    files = {"core/limits.py": "X = 1\n", "core/models.py": "from fim.core.limits import X\n"}
    assert check(tmp_path, files) == []


def test_external_imports_are_not_internal_resolution_errors(tmp_path: Path) -> None:
    assert check(tmp_path, {"core/limits.py": "import json\nimport hmac\n"}) == []


# ---- A005 and A014: fail closed -------------------------------------------------------------


def test_a005_syntax_error_is_a_violation_not_a_pass(tmp_path: Path) -> None:
    violations = check(tmp_path, {"core/limits.py": "def broken(:\n"})
    assert rules(violations) == ["A005"]
    assert violations[0].line >= 1


def test_a005_undecodable_source_is_a_violation(tmp_path: Path) -> None:
    assert rules(check(tmp_path, {"core/limits.py": b"X = '\xff\xfe'\n"})) == ["A005"]


def test_a005_null_byte_in_source_is_a_violation(tmp_path: Path) -> None:
    assert rules(check(tmp_path, {"core/limits.py": b"X = 1\x00\n"})) == ["A005"]


def test_a014_missing_source_directory(tmp_path: Path) -> None:
    assert rules(arch.check_tree(tmp_path / "does-not-exist")) == ["A014"]


def test_a014_package_directory_with_no_modules(tmp_path: Path) -> None:
    (tmp_path / "src" / "fim").mkdir(parents=True)
    violations = arch.check_tree(tmp_path / "src")
    assert rules(violations) == ["A014"]
    assert "no modules" in violations[0].message


def test_a014_directory_without_init_is_rejected(tmp_path: Path) -> None:
    src = make_tree(tmp_path, {"core/limits.py": "X = 1\n"})
    (src / "fim" / "core" / "__init__.py").unlink()
    violations = arch.check_tree(src)
    assert "A014" in rules(violations)
    assert any("__init__.py" in v.message for v in violations)


# ---- A013 -----------------------------------------------------------------------------------


def test_a013_sandbox_may_only_be_imported_by_the_demo(tmp_path: Path) -> None:
    files = {
        "fs/sandbox.py": "X = 1\n",
        "app/check.py": "from fim.fs import sandbox\n",
    }
    violations = check(tmp_path, files)
    assert rules(violations) == ["A013"]
    assert "fim.app.demo" in violations[0].message


def test_a013_demo_may_import_the_sandbox(tmp_path: Path) -> None:
    files = {"fs/sandbox.py": "X = 1\n", "app/demo.py": "from fim.fs import sandbox\n"}
    assert check(tmp_path, files) == []


# ---- command line of the checker --------------------------------------------------------------


def test_main_reports_ok_and_exit_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    src = make_tree(tmp_path, {"core/limits.py": "X = 1\n"})
    assert arch.main(["--src", str(src)]) == 0
    assert "architecture check OK" in capsys.readouterr().out


def test_main_reports_violations_and_exit_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    src = make_tree(tmp_path, {"core/mystery.py": "X = 1\n"})
    assert arch.main(["--src", str(src)]) == 1
    out = capsys.readouterr().out
    assert "A001" in out
    assert "FAILED" in out


def test_violation_format_has_path_line_and_rule() -> None:
    text = arch.Violation("A002", "fim/core/x.py", 7, "message").format()
    assert text == "fim/core/x.py:7: A002 message"
