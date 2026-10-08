"""Helpers for building throwaway source trees to feed the architecture checker."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import check_architecture as arch


def make_tree(tmp_path: Path, files: Mapping[str, str | bytes]) -> Path:
    """Write ``files`` (paths relative to ``src/fim``) under tmp_path and return ``src``.

    Missing ``__init__.py`` files are created so that every directory is a real package.
    """
    src = tmp_path / "src"
    content: dict[str, str | bytes] = {"__init__.py": ""}
    for rel, text in files.items():
        content[rel] = text
        parts = Path(rel).parent.parts
        for depth in range(1, len(parts) + 1):
            content.setdefault("/".join(parts[:depth]) + "/__init__.py", "")
    for rel, text in content.items():
        target = src / "fim" / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            target.write_bytes(text)
        else:
            target.write_text(text, encoding="utf-8", newline="\n")
    return src


def rules(violations: list[arch.Violation]) -> list[str]:
    """The rule ids of ``violations`` in order."""
    return [v.rule for v in violations]


def check(tmp_path: Path, files: Mapping[str, str | bytes]) -> list[arch.Violation]:
    """Build a tree from ``files`` and run all architecture rules on it."""
    return arch.check_tree(make_tree(tmp_path, files))
