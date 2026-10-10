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
    "fim.core.canonical": frozenset({"fim.core.errors"}),
    "fim.core.diff": frozenset(
        {
            "fim.core.canonical",
            "fim.core.limits",
            "fim.core.models",
            "fim.core.pathrules",
            "fim.core.perms",
            "fim.core.sanitize",
        }
    ),
    "fim.core.errors": frozenset({"fim.core.sanitize"}),
    "fim.core.globs": frozenset({"fim.core.errors", "fim.core.limits", "fim.core.sanitize"}),
    "fim.core.limits": frozenset({"fim.core.errors"}),
    "fim.core.models": frozenset(
        {"fim.core.errors", "fim.core.limits", "fim.core.pathrules", "fim.core.sanitize"}
    ),
    "fim.core.pathrules": frozenset({"fim.core.errors", "fim.core.limits", "fim.core.sanitize"}),
    "fim.core.perms": frozenset({"fim.core.errors", "fim.core.models"}),
    "fim.core.policy": frozenset(
        {
            "fim.core.canonical",
            "fim.core.errors",
            "fim.core.globs",
            "fim.core.limits",
            "fim.core.models",
            "fim.core.pathrules",
        }
    ),
    # The codec signs with the keystore's Key; the keystore knows nothing of the codec.
    "fim.services.baseline_codec": frozenset({"fim.services.keystore"}),
    # check reuses the configuration, key and verified-baseline helpers of the baseline use case.
    "fim.app.check": frozenset({"fim.app.baseline"}),
    # watch is check in a loop: the same helpers.
    "fim.app.watch": frozenset({"fim.app.baseline"}),
    # the demo drives the real use cases, so it cannot stage a different tool.
    "fim.app.demo": frozenset({"fim.app.baseline", "fim.app.check"}),
    # The CSV rows are built from the JSONL event document, so the two cannot drift apart.
    "fim.render.csv_out": frozenset({"fim.render.jsonl"}),
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


# ---- usage rules: what a module may call, not only what it may import ----------------------

# The only modules that touch the filesystem. observe.py reads monitored files, safe_files.py
# reads and writes the tool's own files, sandbox.py mutates the demo's temporary tree.
FS_MODULES = frozenset({"fim.fs.observe", "fim.fs.safe_files", "fim.fs.sandbox"})
OBSERVE_MODULE = "fim.fs.observe"
CLOCK_MODULE = "fim.platform.clock"
CONFIG_MODULE = "fim.services.config"

# Importing these outside FS_MODULES is a filesystem access (A006).
FS_BANNED_MODULES = frozenset(
    {
        "pathlib",
        "shutil",
        "tempfile",
        "glob",
        "fileinput",
        "zipfile",
        "tarfile",
        "gzip",
        "bz2",
        "lzma",
        "sqlite3",
        "dbm",
        "mmap",
        "linecache",
    }
)
# Core is pure: besides the filesystem modules it may not even import os or sys (A015).
CORE_BANNED_MODULES = FS_BANNED_MODULES | {"os", "sys"}
# io.StringIO is memory only and allowed; the file-opening parts of io are not.
IO_BANNED_ATTRS = frozenset({"open", "open_code", "FileIO"})

BANNED_MODULES = frozenset(
    {
        "subprocess",
        "socket",
        "urllib",
        "http",
        "pickle",
        "marshal",
        "shelve",
        "random",
        "importlib",
        "ctypes",
        "builtins",
    }
)
BANNED_BUILTINS = frozenset({"eval", "exec", "__import__"})
YAML_BANNED_ATTRS = frozenset(
    {
        "load",
        "load_all",
        "unsafe_load",
        "unsafe_load_all",
        "full_load",
        "full_load_all",
        "Loader",
        "UnsafeLoader",
        "FullLoader",
        "CLoader",
        "CUnsafeLoader",
        "CFullLoader",
    }
)
ALLOWED_THIRD_PARTY = {"yaml": frozenset({CONFIG_MODULE})}

# Outside FS_MODULES only these `os` names are allowed (no file functions).
OS_SAFE_ATTRS = frozenset(
    {
        "sep",
        "altsep",
        "extsep",
        "linesep",
        "pathsep",
        "curdir",
        "pardir",
        "devnull",
        "fspath",
        "fsencode",
        "fsdecode",
        "PathLike",
        "environ",
        "getenv",
        "getpid",
        "strerror",
        "cpu_count",
        "name",
        "error",
    }
)
OS_PATH_SAFE_ATTRS = frozenset(
    {
        "join",
        "basename",
        "dirname",
        "split",
        "splitext",
        "splitdrive",
        "normpath",
        "normcase",
        "isabs",
        "sep",
        "altsep",
        "expanduser",
        "commonpath",
        "commonprefix",
    }
)
# Starting or signalling processes is banned everywhere, fs/ included.
OS_ALWAYS_BANNED = frozenset(
    {
        "system",
        "popen",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "posix_spawn",
        "posix_spawnp",
        "fork",
        "forkpty",
        "kill",
        "killpg",
        "startfile",
        "abort",
        "_exit",
    }
)
# observe.py must contain no write or mutate API and no write open flags (A007).
OBSERVE_BANNED_OS = frozenset(
    {
        "write",
        "writev",
        "pwrite",
        "pwritev",
        "remove",
        "unlink",
        "rename",
        "renames",
        "replace",
        "mkdir",
        "makedirs",
        "rmdir",
        "removedirs",
        "chmod",
        "lchmod",
        "fchmod",
        "chown",
        "lchown",
        "fchown",
        "chflags",
        "lchflags",
        "utime",
        "truncate",
        "ftruncate",
        "link",
        "symlink",
        "fsync",
        "fdatasync",
        "mkfifo",
        "mknod",
        "sendfile",
        "copy_file_range",
        "lockf",
        "setxattr",
        "removexattr",
    }
)
OBSERVE_READ_FLAGS = frozenset(
    {
        "O_RDONLY",
        "O_NOFOLLOW",
        "O_NONBLOCK",
        "O_CLOEXEC",
        "O_NOATIME",
        "O_BINARY",
        "O_DIRECTORY",
        "O_NOCTTY",
        "O_NOINHERIT",
        "O_SEQUENTIAL",
        "O_RANDOM",
        "O_LARGEFILE",
    }
)
# Method names that mutate, whatever the receiver is (a pathlib object, a file object).
OBSERVE_BANNED_METHODS = frozenset(
    {
        "write",
        "writelines",
        "write_text",
        "write_bytes",
        "truncate",
        "mkdir",
        "unlink",
        "rmdir",
        "rename",
        "touch",
        "chmod",
        "chown",
        "symlink_to",
        "hardlink_to",
    }
)
CLOCK_CALLS = frozenset(
    {
        "datetime.datetime.now",
        "datetime.datetime.utcnow",
        "datetime.datetime.today",
        "datetime.date.today",
    }
)


def _dotted(parts: Sequence[str]) -> str:
    return ".".join(parts)


def _chain(node: ast.AST) -> list[str] | None:
    """The names of ``a.b.c`` as ['a', 'b', 'c'], or None if the root is not a plain name."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return parts[::-1]
    return None


def build_aliases(tree: ast.Module) -> dict[str, str]:
    """Map every imported local name to the dotted thing it refers to (any scope)."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    top = alias.name.split(".")[0]
                    aliases[top] = top
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _canonical(parts: Sequence[str], aliases: Mapping[str, str]) -> tuple[str, ...]:
    head = aliases.get(parts[0])
    if head is None:
        return tuple(parts)
    return (*head.split("."), *parts[1:])


def _maximal_chains(tree: ast.Module) -> Iterator[tuple[list[str], int]]:
    """Every attribute chain / bare name being read that is not the inside of a longer chain."""
    inner = {id(n.value) for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute | ast.Name) or id(node) in inner:
            continue
        if not isinstance(node.ctx, ast.Load):
            continue
        parts = _chain(node)
        if parts is not None:
            yield parts, node.lineno


class _UsageChecker:
    """Applies the usage rules to one module."""

    def __init__(self, module: ModuleInfo) -> None:
        self.module = module
        self.name = module.name
        self.layer = LAYERS.get(module.name)
        self.shown = module.path.as_posix()
        self.is_fs = module.name in FS_MODULES
        self.is_observe = module.name == OBSERVE_MODULE
        self.is_core = self.layer == 0
        self.is_cli = module.name == "fim.cli" or module.name.startswith("fim.cli.")
        self.aliases = build_aliases(module.tree)
        self.found: dict[tuple[str, int, str], Violation] = {}

    def add(self, rule: str, line: int, message: str) -> None:
        self.found.setdefault((rule, line, message), Violation(rule, self.shown, line, message))

    # -- imports ------------------------------------------------------------------------------

    def check_import(self, dotted: str, names: Sequence[str], line: int) -> None:
        """``dotted`` is the imported module; ``names`` the names taken from it (from-import)."""
        top = dotted.split(".")[0]
        if top == PACKAGE:
            return
        if top in BANNED_MODULES:
            self.add("A010", line, f"import of banned module '{top}'")
        if top in CORE_BANNED_MODULES and self.is_core:
            self.add("A015", line, f"core must stay pure: it may not import '{top}'")
        elif top in FS_BANNED_MODULES and not self.is_fs:
            self.add("A006", line, f"filesystem module '{top}' is only allowed in fs/")
        elif top in FS_BANNED_MODULES and self.is_observe and top in {"shutil", "tempfile"}:
            self.add("A007", line, f"observe.py may not import '{top}'")
        if top == "time" and self.name != CLOCK_MODULE:
            self.add("A008", line, "the time module is only allowed in platform/clock.py")
        if top not in sys.stdlib_module_names:
            allowed = ALLOWED_THIRD_PARTY.get(top)
            if allowed is None or self.name not in allowed:
                self.add("A009", line, f"third-party import '{top}' is not allowed here")
        if dotted == "io" or dotted.startswith("io."):
            for name in names:
                if name in IO_BANNED_ATTRS and not self.is_fs:
                    self.add("A006", line, f"io.{name} opens files; only fs/ may do that")
        if top == "os":
            for name in names:
                self.check_os_name(dotted, name, line)
        if top == "yaml":
            for name in names:
                if name in YAML_BANNED_ATTRS:
                    self.add("A010", line, f"yaml.{name} is unsafe; use a SafeLoader subclass")
        if top == "sys" and "modules" in names:
            self.add("A010", line, "sys.modules is banned")

    def check_os_name(self, module: str, name: str, line: int) -> None:
        """A name taken from ``os`` or ``os.path`` (from-import or attribute access)."""
        if module == "os":
            self.check_os_attr(name, None, line)
        elif (
            module == "os.path"
            and not self.is_fs
            and not self.is_core
            and name not in OS_PATH_SAFE_ATTRS
        ):
            self.add("A006", line, f"os.path.{name} touches the filesystem")

    def check_os_attr(self, attr: str, sub: str | None, line: int) -> None:
        if attr in OS_ALWAYS_BANNED:
            self.add("A010", line, f"os.{attr} starts or signals a process")
            return
        if self.is_observe:
            if attr in OBSERVE_BANNED_OS:
                self.add("A007", line, f"observe.py may not use os.{attr}")
            elif attr.startswith("O_") and attr not in OBSERVE_READ_FLAGS:
                self.add("A007", line, f"observe.py may not use the open flag os.{attr}")
            return
        if self.is_fs or self.is_core:
            return  # core is reported once, at its import (A015)
        if attr == "path":
            if sub is not None and sub not in OS_PATH_SAFE_ATTRS:
                self.add("A006", line, f"os.path.{sub} touches the filesystem")
        elif attr not in OS_SAFE_ATTRS:
            self.add("A006", line, f"os.{attr} is a filesystem or process API; only fs/ may use it")

    # -- the whole module ---------------------------------------------------------------------

    def run(self) -> list[Violation]:
        tree = self.module.tree
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.check_import(alias.name, [], node.lineno)
            elif isinstance(node, ast.ImportFrom):
                if any(alias.name == "*" for alias in node.names):
                    self.add("A010", node.lineno, "star imports are banned")
                if node.module and not node.level:
                    self.check_import(node.module, [a.name for a in node.names], node.lineno)
            elif isinstance(node, ast.Assert):
                self.add("A011", node.lineno, "assert is banned in src/; raise an explicit error")
            elif isinstance(node, ast.Call):
                self.check_call(node)
            elif (
                isinstance(node, ast.Attribute)
                and self.is_observe
                and node.attr in OBSERVE_BANNED_METHODS
            ):
                self.add("A007", node.lineno, f"observe.py may not use '.{node.attr}'")
        for parts, line in _maximal_chains(tree):
            self.check_chain(_canonical(parts, self.aliases), parts, line)
        return list(self.found.values())

    def check_chain(self, canon: tuple[str, ...], raw: Sequence[str], line: int) -> None:
        dotted = _dotted(canon)
        head = canon[0]
        if canon == ("print",) and raw[0] == "print" and not self.is_cli:
            self.add("A012", line, "print is only allowed in cli/")
        if canon[:2] in {("sys", "stdout"), ("sys", "stderr")} and not self.is_cli:
            self.add("A012", line, "writing to sys.stdout/sys.stderr is only allowed in cli/")
        if canon == ("sys", "modules"):
            self.add("A010", line, "sys.modules is banned")
        if len(canon) == 1 and head in BANNED_BUILTINS and raw[0] == head:
            self.add("A010", line, f"{head}() is banned")
        if canon == ("open",) and raw == ["open"]:
            if self.is_observe:
                self.add("A007", line, "observe.py may not call open(); use os.open read-only")
            elif not self.is_fs:
                self.add("A006", line, "open() is only allowed in fs/")
        if head == "os" and len(canon) >= 2:
            self.check_os_attr(canon[1], canon[2] if len(canon) > 2 else None, line)
        if head == "io" and len(canon) >= 2 and canon[1] in IO_BANNED_ATTRS and not self.is_fs:
            self.add("A006", line, f"io.{canon[1]} opens files; only fs/ may do that")
        if head == "yaml" and len(canon) >= 2 and canon[1] in YAML_BANNED_ATTRS:
            self.add("A010", line, f"yaml.{canon[1]} is unsafe; use a SafeLoader subclass")
        if dotted in CLOCK_CALLS and self.name != CLOCK_MODULE:
            self.add("A008", line, f"{dotted} reads the clock; inject a Clock instead")

    def check_call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "open" and not self.is_fs:
            self.add("A006", node.lineno, "'.open()' is only allowed in fs/")
        if isinstance(func, ast.Name) and func.id == "getattr" and node.args:
            parts = _chain(node.args[0])
            if parts is None or _canonical(parts, self.aliases) not in {("os",), ("os", "path")}:
                return
            attr = node.args[1] if len(node.args) > 1 else None
            if isinstance(attr, ast.Constant) and isinstance(attr.value, str):
                self.check_os_attr(attr.value, None, node.lineno)
            elif self.is_observe:
                self.add("A007", node.lineno, "observe.py may not look up os names dynamically")
            elif not self.is_fs:
                self.add("A006", node.lineno, "dynamic getattr on os is only allowed in fs/")
        if self.is_observe:
            parts = _chain(func)
            if parts is not None and _canonical(parts, self.aliases) == ("os", "open"):
                flags = node.args[1] if len(node.args) > 1 else None
                if flags is None:
                    flags = next((k.value for k in node.keywords if k.arg == "flags"), None)
                if flags is None or any(
                    isinstance(sub, ast.Constant) and isinstance(sub.value, int)
                    for sub in ast.walk(flags)
                ):
                    self.add("A007", node.lineno, "os.open flags must be named read-only constants")


def check_usage(tree: Tree) -> list[Violation]:
    """A006-A012 and A015 for every module."""
    violations: list[Violation] = []
    for module in tree.modules.values():
        violations.extend(_UsageChecker(module).run())
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
    violations.extend(check_usage(tree))
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
