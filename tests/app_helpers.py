"""A throwaway workspace for the app and CLI tests: a watched tree, a key directory, a config."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Workspace:
    base: Path
    watched: Path
    keys: Path
    key_file: Path
    baseline: Path
    config: Path


def yaml_text(value: str) -> str:
    """A YAML scalar for ``value``: a JSON string is also a valid YAML double-quoted string."""
    return json.dumps(value)


def write_config(
    path: Path,
    roots: list[Path],
    *,
    key_file: Path | None = None,
    limits: dict[str, int] | None = None,
    extra: str = "",
) -> None:
    lines = ["version: 1"]
    if key_file is not None:
        lines.append(f"key_file: {yaml_text(str(key_file))}")
    lines.append("host_label: lab-01")
    if limits:
        lines.append("limits:")
        lines.extend(f"  {name}: {value}" for name, value in limits.items())
    lines.append("paths:")
    for root in roots:
        lines.append(f"  - path: {yaml_text(str(root))}")
        lines.append("    severity: high")
    if extra:
        lines.append(extra)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def make_workspace(base: Path, *, files: int = 3) -> Workspace:
    watched = base / "watched"
    keys = base / "keys"
    watched.mkdir()
    keys.mkdir()
    (watched / "sub").mkdir()
    for index in range(files):
        (watched / f"file{index}.txt").write_bytes(f"content {index}\n".encode())
    (watched / "sub" / "nested.txt").write_bytes(b"nested\n")
    workspace = Workspace(
        base=base,
        watched=watched,
        keys=keys,
        key_file=keys / "fim.key",
        baseline=base / "out" / "fim.baseline",
        config=base / "fim.yaml",
    )
    workspace.baseline.parent.mkdir()
    write_config(workspace.config, [watched])
    return workspace


def tree_state(root: Path) -> dict[str, tuple[object, ...]]:
    """Content hash, size, mtime_ns and mode of everything below ``root`` (read-only invariant)."""
    state: dict[str, tuple[object, ...]] = {}
    for current, directories, names in os.walk(root):
        for name in [*directories, *names]:
            path = Path(current) / name
            info = path.lstat()
            digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""
            state[str(path.relative_to(root))] = (
                digest,
                info.st_size,
                info.st_mtime_ns,
                info.st_mode,
            )
    return state
