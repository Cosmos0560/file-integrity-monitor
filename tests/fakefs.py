"""A virtual file tree that implements the scanner's FileSystemView, so every branch of the
scanner (links, FIFOs, junctions, offline placeholders, loops, permission errors) is exercised
on every operating system without touching a disk."""

from __future__ import annotations

import hashlib
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from fim.core.models import HashStatus
from fim.fs.observe import DirListing, FsProblem, HashResult, RawStat

NS = 1_700_000_000_000_000_000
NOT_FOUND = FsProblem("ENOENT", vanished=True, denied=False)
DENIED = FsProblem("EACCES", vanished=False, denied=True)

_KIND_MODES = {
    "file": stat.S_IFREG,
    "dir": stat.S_IFDIR,
    "symlink": stat.S_IFLNK,
    "fifo": stat.S_IFIFO,
    "socket": stat.S_IFSOCK,
    "device": stat.S_IFCHR,
    "other": 0o130000,
    "reparse": stat.S_IFDIR,  # a junction looks like a directory to st_mode
}


@dataclass
class Node:
    kind: str
    content: bytes = b""
    mode: int = 0o644
    uid: int | None = 1000
    gid: int | None = 1000
    mtime_ns: int = NS
    dev: int = 1
    ino: int = 0
    nlink: int = 1
    size: int | None = None
    attributes: int | None = None  # Windows attribute bits; None means POSIX
    tag: int | None = None
    target: str | None = None  # symlink text
    points_to: str | None = None  # symlink: path of the node it resolves to (for stat_target)


@dataclass
class FakeFs:
    """Paths are plain strings joined with ``sep``; the root of the tree is added by the test."""

    sep: str = "/"
    nodes: dict[str, Node] = field(default_factory=dict)
    lstat_errors: dict[str, FsProblem] = field(default_factory=dict)
    list_errors: dict[str, FsProblem] = field(default_factory=dict)
    link_errors: dict[str, FsProblem] = field(default_factory=dict)
    hash_overrides: dict[str, HashResult] = field(default_factory=dict)
    listing_limit_ignored: bool = False
    lstat_calls: list[str] = field(default_factory=list)
    list_calls: list[str] = field(default_factory=list)
    hash_calls: list[tuple[str, bool]] = field(default_factory=list)
    target_calls: list[str] = field(default_factory=list)
    link_calls: list[str] = field(default_factory=list)
    on_hash: Callable[[str], None] | None = None
    on_lstat: Callable[[str], None] | None = None
    _next_ino: int = 100

    # -- building -----------------------------------------------------------------------------

    def add(self, path: str, kind: str, **fields: Any) -> Node:
        node = Node(kind=kind, **fields)
        if node.ino == 0:
            node.ino = self._next_ino
            self._next_ino += 1
        if kind == "dir" and node.mode == 0o644:
            node.mode = 0o755
        self.nodes[path] = node
        return node

    def dir(self, path: str, **fields: Any) -> Node:
        return self.add(path, "dir", **fields)

    def file(self, path: str, content: bytes = b"", **fields: Any) -> Node:
        return self.add(path, "file", content=content, **fields)

    def children(self, path: str) -> list[str]:
        prefix = path if path.endswith(self.sep) else path + self.sep
        names = []
        for other in self.nodes:
            if (
                other != prefix
                and other.startswith(prefix)
                and self.sep not in other[len(prefix) :]
            ):
                names.append(other[len(prefix) :])
        return names

    # -- the view -----------------------------------------------------------------------------

    def _raw(self, node: Node) -> RawStat:
        size = node.size if node.size is not None else len(node.content)
        return RawStat(
            st_mode=_KIND_MODES[node.kind] | node.mode,
            size=size,
            mtime_ns=node.mtime_ns,
            dev=node.dev,
            ino=node.ino,
            nlink=node.nlink,
            uid=node.uid if node.attributes is None else None,
            gid=node.gid if node.attributes is None else None,
            file_attributes=node.attributes,
            reparse_tag=node.tag,
        )

    def lstat(self, path: str) -> RawStat | FsProblem:
        self.lstat_calls.append(path)
        if self.on_lstat is not None:
            self.on_lstat(path)
        if path in self.lstat_errors:
            return self.lstat_errors[path]
        node = self.nodes.get(path)
        return self._raw(node) if node is not None else NOT_FOUND

    def stat_target(self, path: str) -> RawStat | FsProblem:
        self.target_calls.append(path)
        node = self.nodes.get(path)
        if node is None:
            return NOT_FOUND
        if node.kind == "symlink":
            if node.points_to is None or node.points_to not in self.nodes:
                return NOT_FOUND
            return self._raw(self.nodes[node.points_to])
        return self._raw(node)

    def read_link(self, path: str) -> str | FsProblem:
        self.link_calls.append(path)
        if path in self.link_errors:
            return self.link_errors[path]
        node = self.nodes.get(path)
        if node is None or node.target is None:
            return NOT_FOUND
        return node.target

    def list_dir(self, path: str, limit: int) -> DirListing | FsProblem:
        self.list_calls.append(path)
        if path in self.list_errors:
            return self.list_errors[path]
        names = sorted(self.children(path))
        if len(names) > limit and not self.listing_limit_ignored:
            return DirListing(tuple(names[:limit]), truncated=True)
        return DirListing(tuple(names), truncated=False)

    def hash_file(
        self,
        path: str,
        expected: RawStat,
        *,
        max_bytes: int,
        should_stop: Callable[[], bool],
        follow: bool,
    ) -> HashResult:
        self.hash_calls.append((path, follow))
        if self.on_hash is not None:
            self.on_hash(path)
        if path in self.hash_overrides:
            return self.hash_overrides[path]
        if should_stop():
            return HashResult(
                HashStatus.UNSTABLE, None, 0, expected.size, expected.mtime_ns, None, "", True
            )
        node = self.nodes[path]
        if node.kind == "symlink" and node.points_to is not None:
            node = self.nodes[node.points_to]
        return HashResult(
            HashStatus.OK,
            hashlib.sha256(node.content).hexdigest(),
            len(node.content),
            len(node.content),
            node.mtime_ns,
            None,
            "",
        )
