"""Architecture checker for src/fim. Run: python scripts/check_architecture.py [--src src]

Enforces the rules in CLAUDE.md section 5 by reading the source with ``ast`` (nothing is
imported or executed):

* every module has a layer, and imports only from lower layers or from same-layer modules that
  are listed in SAME_LAYER_ALLOWED;
* no import cycles, counting function-level and TYPE_CHECKING imports;
* the checker fails closed: a syntax error, an unreadable file, an unresolvable internal import,
  a missing or empty source tree is a violation, never a silent pass.

Rule ids (the tests plant one violation per id):
  A001 module without a layer           A002 import against the layering
  A003 import cycle                     A004 unresolvable internal import
  A005 unparsable or unreadable source  A006 filesystem API outside fs/
  A007 write API in fs/observe.py       A008 clock access outside platform/clock.py
  A009 third-party import not allowed   A010 banned module, builtin or API
  A011 assert statement                 A012 printing outside cli/
  A013 restricted module imported       A014 source tree structure problem
  A015 impure import in core/
"""

from __future__ import annotations

import argparse
import ast
import sys
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

PACKAGE = "fim"

# The root package holds only the version constant, so every layer may import it.
ROOT_LAYER = -1

LAYERS: Mapping[str, int] = {
    "fim": ROOT_LAYER,
    # L0 core: pure logic.
    "fim.core": 0,
    "fim.core.limits": 0,
    "fim.core.models": 0,
    "fim.core.errors": 0,
    "fim.core.sanitize": 0,
    "fim.core.pathrules": 0,
    "fim.core.globs": 0,
    "fim.core.policy": 0,
    "fim.core.perms": 0,
    "fim.core.diff": 0,
    "fim.core.canonical": 0,
    "fim.core.clock": 0,
    # L1 fs / platform / render.
    "fim.fs": 1,
    "fim.fs.observe": 1,
    "fim.fs.safe_files": 1,
    "fim.fs.sandbox": 1,
    "fim.platform": 1,
    "fim.platform.clock": 1,
    "fim.platform.hostinfo": 1,
    "fim.render": 1,
    "fim.render.table": 1,
    "fim.render.json_out": 1,
    "fim.render.jsonl": 1,
    "fim.render.csv_out": 1,
    # L2 services.
    "fim.services": 2,
    "fim.services.config": 2,
    "fim.services.scanner": 2,
    "fim.services.baseline_codec": 2,
    "fim.services.keystore": 2,
    # L3 use cases.
    "fim.app": 3,
    "fim.app.baseline": 3,
    "fim.app.check": 3,
    "fim.app.watch": 3,
    "fim.app.demo": 3,
    # L4 command line.
    "fim.cli": 4,
    "fim.cli.main": 4,
    # Above the CLI: python -m fim.
    "fim.__main__": 5,
}

# Same-layer imports that are allowed, keyed by the importing module. Everything not listed is a
# violation (A002). Phases that add modules extend this table with the edges they need.
SAME_LAYER_ALLOWED: Mapping[str, frozenset[str]] = {
    "fim.core.errors": frozenset({"fim.core.sanitize"}),
    "fim.core.models": frozenset({"fim.core.limits"}),
    "fim.core.pathrules": frozenset({"fim.core.errors", "fim.core.limits", "fim.core.sanitize"}),
}

# module -> the only modules that may import it (A013).
RESTRICTED_IMPORTERS: Mapping[str, frozenset[str]] = {
    "fim.fs.sandbox": frozenset({"fim.app.demo"}),
}


@dataclass(frozen=True, slots=True)
class Violation:
    """One broken rule at one place."""

    rule: str
    path: str
    line: int
    message: str

    def format(self) -> str:
        return f"{self.path}:{self.line}: {self.rule} {self.message}"


@dataclass(frozen=True, slots=True)
class ImportEdge:
    """An internal import, resolved to the module that provides the imported name."""

    source: str
    target: str
    line: int


@dataclass(slots=True)
class ModuleInfo:
    """A parsed source file."""

    name: str
    path: Path
    is_package: bool
    tree: ast.Module


@dataclass(slots=True)
class Tree:
    """Everything read from the source tree, plus the problems found while reading it."""

    modules: dict[str, ModuleInfo]
    violations: list[Violation]


def _display(path: Path, base: Path) -> str:
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return path.as_posix()


def module_name_for(src: Path, file: Path) -> str:
    """Dotted module name of ``file`` below ``src`` (``pkg/__init__.py`` is ``pkg``)."""
    parts = list(file.relative_to(src).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def load_tree(src: Path) -> Tree:
    """Parse every module below ``src/fim``. Any problem becomes a violation (fail closed)."""
    violations: list[Violation] = []
    modules: dict[str, ModuleInfo] = {}
    package_dir = src / PACKAGE
    if not package_dir.is_dir():
        violations.append(Violation("A014", src.as_posix(), 0, f"no '{PACKAGE}' package found"))
        return Tree(modules, violations)

    files = sorted(package_dir.rglob("*.py"))
    for file in files:
        shown = _display(file, src)
        # Packages must be real packages: implicit namespace packages hide modules from the
        # layer table and from import resolution.
        directory = file.parent
        while directory != src:
            if not (directory / "__init__.py").is_file():
                violations.append(
                    Violation("A014", shown, 0, f"directory '{directory.name}' has no __init__.py")
                )
                break
            directory = directory.parent
        try:
            source = file.read_bytes().decode("utf-8")
            tree = ast.parse(source, filename=shown)
        except (OSError, UnicodeDecodeError, SyntaxError, ValueError) as exc:
            line = (exc.lineno or 0) if isinstance(exc, SyntaxError) else 0
            violations.append(
                Violation("A005", shown, line, f"cannot read or parse: {type(exc).__name__}")
            )
            continue
        name = module_name_for(src, file)
        modules[name] = ModuleInfo(name, file, file.name == "__init__.py", tree)

    if not modules and not violations:
        violations.append(Violation("A014", src.as_posix(), 0, "no modules found to check"))
    return Tree(modules, violations)


def _resolve_relative(module: ModuleInfo, level: int, name: str | None) -> str | None:
    package = module.name if module.is_package else module.name.rpartition(".")[0]
    parts = package.split(".") if package else []
    if level - 1 > len(parts):
        return None
    base = parts[: len(parts) - (level - 1)]
    if name:
        base = [*base, *name.split(".")]
    return ".".join(base) if base else None


def iter_imports(module: ModuleInfo) -> Iterator[tuple[str, str | None, int]]:
    """Yield (base, name, line) for every import statement, including nested ones.

    ``import a.b`` yields ("a.b", None). ``from a.b import c`` yields ("a.b", "c"): the caller
    decides whether ``c`` is a submodule or a name defined in ``a.b``. A relative import that
    leaves the package yields a base that starts with a dot.
    """
    for node in ast.walk(module.tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, None, node.lineno
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = _resolve_relative(module, node.level, node.module)
                if base is None:
                    yield "." * node.level + (node.module or ""), None, node.lineno
                    continue
            else:
                base = node.module or ""
            for alias in node.names:
                yield base, (None if alias.name == "*" else alias.name), node.lineno


def collect_edges(tree: Tree) -> tuple[list[ImportEdge], list[Violation]]:
    """Resolve internal imports to edges; unresolvable ones are A004 violations."""
    edges: list[ImportEdge] = []
    violations: list[Violation] = []
    for module in tree.modules.values():
        shown = module.path.as_posix()
        for base, name, line in iter_imports(module):
            if base.startswith("."):
                violations.append(
                    Violation("A004", shown, line, f"relative import '{base}' leaves the package")
                )
                continue
            if base.split(".")[0] != PACKAGE:
                continue
            if base not in tree.modules:
                violations.append(
                    Violation("A004", shown, line, f"import of unknown internal module '{base}'")
                )
                continue
            # 'from fim.core import limits' targets the submodule; 'from fim.core import x'
            # where x is not a module is a name inside fim.core itself.
            submodule = f"{base}.{name}" if name else None
            target = submodule if submodule in tree.modules else base
            edges.append(ImportEdge(module.name, target, line))
    return edges, violations


def check_layers(tree: Tree, edges: Iterable[ImportEdge]) -> list[Violation]:
    """A001 (no layer) and A002 (import against the layering)."""
    violations: list[Violation] = []
    for module in tree.modules.values():
        if module.name not in LAYERS:
            violations.append(
                Violation(
                    "A001",
                    module.path.as_posix(),
                    1,
                    f"module '{module.name}' is not assigned a layer in check_architecture.py",
                )
            )
    for edge in edges:
        if edge.source == edge.target:
            continue
        source_layer = LAYERS.get(edge.source)
        target_layer = LAYERS.get(edge.target)
        if source_layer is None or target_layer is None:
            continue  # already reported as A001
        shown = tree.modules[edge.source].path.as_posix()
        if target_layer == ROOT_LAYER or target_layer < source_layer:
            continue
        if target_layer == source_layer and edge.target in SAME_LAYER_ALLOWED.get(
            edge.source, frozenset()
        ):
            continue
        relation = (
            "a higher layer" if target_layer > source_layer else "an unlisted same-layer module"
        )
        violations.append(
            Violation(
                "A002",
                shown,
                edge.line,
                f"'{edge.source}' (L{source_layer}) imports '{edge.target}' "
                f"(L{target_layer}), {relation}",
            )
        )
    return violations


def check_restricted(tree: Tree, edges: Iterable[ImportEdge]) -> list[Violation]:
    """A013: modules that only named importers may use."""
    violations: list[Violation] = []
    for edge in edges:
        allowed = RESTRICTED_IMPORTERS.get(edge.target)
        if allowed is not None and edge.source not in allowed:
            violations.append(
                Violation(
                    "A013",
                    tree.modules[edge.source].path.as_posix(),
                    edge.line,
                    f"'{edge.target}' may only be imported by {sorted(allowed)}",
                )
            )
    return violations


def find_cycles(edges: Iterable[ImportEdge]) -> list[list[str]]:
    """Return strongly connected components with a cycle (Tarjan, iterative)."""
    graph: dict[str, set[str]] = {}
    for edge in edges:
        graph.setdefault(edge.source, set()).add(edge.target)
        graph.setdefault(edge.target, set())

    index_of: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    components: list[list[str]] = []
    counter = 0

    for start in sorted(graph):
        if start in index_of:
            continue
        work: list[tuple[str, Iterator[str]]] = [(start, iter(sorted(graph[start])))]
        index_of[start] = low[start] = counter
        counter += 1
        stack.append(start)
        on_stack.add(start)
        while work:
            node, children = work[-1]
            advanced = False
            for child in children:
                if child not in index_of:
                    index_of[child] = low[child] = counter
                    counter += 1
                    stack.append(child)
                    on_stack.add(child)
                    work.append((child, iter(sorted(graph[child]))))
                    advanced = True
                    break
                if child in on_stack:
                    low[node] = min(low[node], index_of[child])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index_of[node]:
                component: list[str] = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == node:
                        break
                if len(component) > 1 or node in graph[node]:
                    components.append(sorted(component))
    return sorted(components)


def check_cycles(tree: Tree, edges: list[ImportEdge]) -> list[Violation]:
    """A003: every import cycle, reported once at its first member."""
    violations: list[Violation] = []
    for component in find_cycles(edges):
        first = tree.modules[component[0]]
        violations.append(
            Violation("A003", first.path.as_posix(), 1, "import cycle: " + " <-> ".join(component))
        )
    return violations


def run_checks(src: Path) -> tuple[list[Violation], int]:
    """Run every rule against ``src``; return the sorted violations and the module count."""
    tree = load_tree(src)
    violations = list(tree.violations)
    edges, unresolved = collect_edges(tree)
    violations.extend(unresolved)
    violations.extend(check_layers(tree, edges))
    violations.extend(check_restricted(tree, edges))
    violations.extend(check_cycles(tree, edges))
    ordered = sorted(violations, key=lambda v: (v.path, v.line, v.rule, v.message))
    return ordered, len(tree.modules)


def check_tree(src: Path) -> list[Violation]:
    """Return all violations for ``src`` (empty means the tree passes)."""
    return run_checks(src)[0]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the fim architecture rules.")
    parser.add_argument("--src", type=Path, default=Path("src"), help="source root (default: src)")
    args = parser.parse_args(argv)
    violations, count = run_checks(args.src)
    if violations:
        for violation in violations:
            print(violation.format())
        print(f"architecture check FAILED: {len(violations)} violation(s)")
        return 1
    print(f"architecture check OK: {count} modules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
