"""The test guard of CLAUDE.md section 6: the public functions of fs/observe.py and
fs/safe_files.py refuse, inside a test, any path outside the pytest temporary directory.

A test that scans or writes the real home, system, project or repository directory fails
loudly instead of touching them. The guard wraps every public function of the module that has
a parameter named ``path``; it checks the path as given (made absolute, not resolved), so a
link inside the temporary directory can still be examined with ``lstat``.
"""

from __future__ import annotations

import functools
import importlib
import importlib.util
import inspect
import os
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

GUARDED_MODULES = ("fim.fs.observe", "fim.fs.safe_files")


class PathGuardError(AssertionError):
    """A test handed a path outside the pytest temporary directory to a guarded function."""


def _normal(path: str) -> str:
    try:
        return os.path.normcase(os.path.abspath(path))
    except ValueError:  # an embedded NUL byte: compare the text as given
        return os.path.normcase(path)


def is_inside(path: str, base: Path) -> bool:
    """True if ``path`` is ``base`` or lies below it, compared by whole components."""
    root = _normal(str(base))
    candidate = _normal(path)
    return candidate == root or candidate.startswith(root.rstrip(os.sep) + os.sep)


def guarded_functions(module: ModuleType) -> list[str]:
    """Names of the public functions of ``module`` that take a ``path``."""
    names = []
    for name in getattr(module, "__all__", ()):
        function = getattr(module, name, None)
        if inspect.isfunction(function) and "path" in inspect.signature(function).parameters:
            names.append(name)
    return names


def _wrap(function: Callable[..., Any], name: str, base: Path) -> Callable[..., Any]:
    signature = inspect.signature(function)

    @functools.wraps(function)
    def guarded(*args: Any, **kwargs: Any) -> Any:
        path = signature.bind(*args, **kwargs).arguments["path"]
        if not isinstance(path, str) or not is_inside(path, base):
            raise PathGuardError(
                f"{function.__module__}.{name}() was given a path outside the pytest temporary "
                f"directory: {path!r}"
            )
        return function(*args, **kwargs)

    return guarded


def install_guard(monkeypatch: pytest.MonkeyPatch, module: ModuleType, base: Path) -> list[str]:
    """Replace the module's path-taking public functions with guarded ones; return their names."""
    names = guarded_functions(module)
    for name in names:
        monkeypatch.setattr(module, name, _wrap(getattr(module, name), name, base))
    return names


def load_guarded_modules() -> list[ModuleType]:
    """The guarded modules that exist yet (safe_files arrives in Phase 3)."""
    modules = []
    for name in GUARDED_MODULES:
        if importlib.util.find_spec(name) is not None:
            modules.append(importlib.import_module(name))
    return modules
