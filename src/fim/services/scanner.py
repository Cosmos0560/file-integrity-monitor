"""The scanner: walks the monitored roots under a policy and returns a ScanResult.

It is an iterative walk (no recursion, so depth cannot exhaust the stack) over directories
listed in sorted order, so two runs over the same tree give the same records in the same order.
Everything it knows about the filesystem comes through a ``FileSystemView``; the real one is
fs/observe.py and tests may substitute a virtual tree. The scanner itself never opens a file.

Rules applied here (PLAN.md D5, D6, D7, D11):

* Links are recorded, never followed or traversed. A junction or any other Windows reparse
  point is type ``reparse``. With ``symlinks: files`` a symlink to a regular file is also
  hashed, through the link, but a directory behind a link is never entered.
* Only regular files are hashed. FIFOs, sockets and devices are described and left alone.
* Directories are recorded but not hashed. ``one_file_system`` stops at a mount boundary.
* A root that is missing, a link or not a file or directory is a ``root_unavailable`` issue.
* Nested roots: a directory that is itself another configured root is skipped by the enclosing
  root and scanned as its own root, so every path is recorded once, under its most specific
  root.
* Every limit that is hit (files, depth, path length, a revisited directory, the run-time
  budget) marks the run incomplete. A skipped file is never reported as clean.
* An error on one entry becomes a ``ScanIssue`` and the scan goes on.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from fim.core.clock import Clock
from fim.core.errors import PathRuleError
from fim.core.globs import matches_any
from fim.core.models import (
    EntryType,
    FileRecord,
    HashStatus,
    IssueKind,
    Policy,
    ScanIssue,
    ScanResult,
    ScanStats,
    SymlinkPolicy,
)
from fim.core.pathrules import display_path, record_path
from fim.core.perms import (
    entry_type,
    is_offline,
    posix_permissions,
    tracked_windows_attributes,
)
from fim.core.policy import RootRules, compile_rules, component_key
from fim.fs import observe
from fim.fs.observe import DirListing, FsProblem, HashResult, RawStat

__all__ = ["FileSystemView", "ObservedFileSystem", "check_roots", "inspect_root", "scan"]


class FileSystemView(Protocol):
    """What the scanner may ask of the filesystem; every method reports errors as values."""

    def lstat(self, path: str) -> RawStat | FsProblem: ...

    def stat_target(self, path: str) -> RawStat | FsProblem: ...

    def read_link(self, path: str) -> str | FsProblem: ...

    def list_dir(self, path: str, limit: int) -> DirListing | FsProblem: ...

    def hash_file(
        self,
        path: str,
        expected: RawStat,
        *,
        max_bytes: int,
        should_stop: Callable[[], bool],
        follow: bool,
    ) -> HashResult: ...


class ObservedFileSystem:
    """The real filesystem, through fs/observe.py.

    Each call looks the function up on the module at call time, so the test guard that wraps
    the module's functions is always in force.
    """

    def lstat(self, path: str) -> RawStat | FsProblem:
        return observe.lstat(path)

    def stat_target(self, path: str) -> RawStat | FsProblem:
        return observe.stat_target(path)

    def read_link(self, path: str) -> str | FsProblem:
        return observe.read_link(path)

    def list_dir(self, path: str, limit: int) -> DirListing | FsProblem:
        return observe.list_dir(path, limit)

    def hash_file(
        self,
        path: str,
        expected: RawStat,
        *,
        max_bytes: int,
        should_stop: Callable[[], bool],
        follow: bool,
    ) -> HashResult:
        return observe.hash_file(
            path, expected, max_bytes=max_bytes, should_stop=should_stop, follow=follow
        )


@dataclass(frozen=True, slots=True)
class _Directory:
    """A directory waiting to be listed."""

    parts: tuple[str, ...]
    path: str
    device: int


def _join(base: str, separator: str, name: str) -> str:
    return base + name if base.endswith(separator) else base + separator + name


def inspect_root(view: FileSystemView, text: str) -> tuple[RawStat, EntryType] | str:
    """What a configured root is, or why it cannot be monitored (the text of the scan issue).

    A root must exist and be a regular file or a directory, and not a link or reparse point.
    """
    found = view.lstat(text)
    if isinstance(found, FsProblem):
        reason = "not found" if found.vanished else f"cannot be read ({found.errno_name})"
        return f"the monitored path {reason}"
    kind = entry_type(found.st_mode, found.file_attributes, found.reparse_tag)
    if kind in (EntryType.SYMLINK, EntryType.REPARSE):
        return "the monitored path is a link or reparse point; configure the real path"
    if kind not in (EntryType.DIR, EntryType.FILE):
        return "the monitored path is neither a file nor a directory"
    return found, kind


def check_roots(policy: Policy, *, view: FileSystemView | None = None) -> tuple[ScanIssue, ...]:
    """A ``root_unavailable`` issue for every configured root that cannot be scanned.

    This is the cheap check ``baseline`` runs before the scan, so it fails fast.
    """
    fs = view if view is not None else ObservedFileSystem()
    issues: list[ScanIssue] = []
    for root in policy.roots:
        inspected = inspect_root(fs, root.path.text)
        if isinstance(inspected, str):
            issues.append(
                ScanIssue(
                    path=root.path.display(), kind=IssueKind.ROOT_UNAVAILABLE, detail=inspected
                )
            )
    return tuple(issues)


class _Scan:
    """The state of one run."""

    def __init__(self, policy: Policy, clock: Clock, view: FileSystemView) -> None:
        self.policy = policy
        self.limits = policy.limits
        self.clock = clock
        self.fs = view
        self.rules = compile_rules(policy)
        self.started_mono = clock.monotonic()
        self.records: list[FileRecord] = []
        self.issues: list[ScanIssue] = []
        self.incomplete = False
        self.halted = False
        self.noted: set[str] = set()
        self.files = 0
        self.dirs = 0
        self.bytes_hashed = 0
        self.skipped_too_large = 0
        self.skipped_offline = 0

    # -- bookkeeping --------------------------------------------------------------------------

    def time_up(self) -> bool:
        return self.clock.monotonic() - self.started_mono >= self.limits.max_run_seconds

    def issue(self, kind: IssueKind, shown: str, detail: str) -> None:
        if len(self.issues) >= self.limits.max_files:
            self.limit("issues", "too many problems; the run is stopped")
            return
        self.issues.append(ScanIssue(path=shown, kind=kind, detail=detail))

    def limit(self, key: str, detail: str, shown: str = "", *, stop: bool = True) -> None:
        """Note that a limit was hit: once per ``key``, the run becomes incomplete."""
        self.incomplete = True
        if stop:
            self.halted = True
        if key in self.noted or len(self.issues) > self.limits.max_files:
            return
        self.noted.add(key)
        kind = IssueKind.TIME_BUDGET if key == "time" else IssueKind.LIMIT_REACHED
        self.issues.append(ScanIssue(path=shown, kind=kind, detail=detail))

    def check_time(self) -> bool:
        """True (and the run stops) if the run-time budget is spent."""
        if self.time_up():
            self.limit("time", f"stopped after the {self.limits.max_run_seconds} s time budget")
            return True
        return False

    def shown(self, rules: RootRules, parts: tuple[str, ...]) -> str:
        """The escaped, display form of an entry, for issues and messages."""
        return display_path(rules.root.path, record_path(parts) if parts else "")

    # -- one root ------------------------------------------------------------------------------

    def scan_root(self, rules: RootRules) -> None:
        root = rules.root
        text = root.path.text
        shown = root.path.display()
        inspected = inspect_root(self.fs, text)
        if isinstance(inspected, str):
            self.issue(IssueKind.ROOT_UNAVAILABLE, shown, inspected)
            return
        found, kind = inspected
        pending: list[_Directory] = []
        visited: set[tuple[int, int]] = set()
        top = self.record_entry(rules, (), text, found, kind, pending, visited, found.dev)
        if top is None:
            return
        while pending and not self.halted:
            self.expand(rules, pending.pop(), pending, visited)

    def expand(
        self,
        rules: RootRules,
        directory: _Directory,
        pending: list[_Directory],
        visited: set[tuple[int, int]],
    ) -> None:
        shown = self.shown(rules, directory.parts)
        if self.check_time():
            return
        if len(directory.parts) >= self.limits.max_depth:
            self.limit(
                f"depth:{shown}",
                f"deeper than max_depth ({self.limits.max_depth}); not entered",
                shown,
                stop=False,
            )
            return
        budget = self.limits.max_files - len(self.records)
        listing = self.fs.list_dir(directory.path, max(budget, 0))
        if isinstance(listing, FsProblem):
            kind = IssueKind.VANISHED if listing.vanished else IssueKind.UNREADABLE
            detail = "directory disappeared" if listing.vanished else "directory cannot be read"
            self.issue(kind, shown, f"{detail} ({listing.errno_name})")
            return
        if listing.truncated:
            # The names that did fit are still recorded; the run is incomplete either way.
            self.limit(
                "max_files", f"more than max_files ({self.limits.max_files}) entries", stop=False
            )
        children: list[_Directory] = []
        separator = rules.root.path.sep
        for name in listing.names:
            if self.halted or self.check_time():
                break
            path = _join(directory.path, separator, name)
            found = self.fs.lstat(path)
            parts = (*directory.parts, name)
            if isinstance(found, FsProblem):
                kind = IssueKind.VANISHED if found.vanished else IssueKind.UNREADABLE
                detail = "disappeared during the scan" if found.vanished else "cannot be read"
                self.issue(kind, self.shown_safe(rules, parts), f"{detail} ({found.errno_name})")
                continue
            kind_of = entry_type(found.st_mode, found.file_attributes, found.reparse_tag)
            self.record_entry(
                rules, parts, path, found, kind_of, children, visited, directory.device
            )
        # Pushed in reverse so the first sorted directory is expanded first.
        pending.extend(reversed(children))

    def shown_safe(self, rules: RootRules, parts: tuple[str, ...]) -> str:
        try:
            return self.shown(rules, parts)
        except PathRuleError:
            return rules.root.path.display() + rules.root.path.sep + "(unrepresentable name)"

    # -- one entry -----------------------------------------------------------------------------

    def excluded(self, rules: RootRules, parts: tuple[str, ...], kind: EntryType) -> bool:
        if matches_any(rules.exclude, parts):
            return True
        return (
            kind is not EntryType.DIR
            and bool(rules.include)
            and not matches_any(rules.include, parts)
        )

    def record_entry(
        self,
        rules: RootRules,
        parts: tuple[str, ...],
        path: str,
        found: RawStat,
        kind: EntryType,
        subdirectories: list[_Directory],
        visited: set[tuple[int, int]],
        parent_device: int,
    ) -> FileRecord | None:
        """Record one entry and, for a directory to enter, queue it. None if not recorded."""
        root = rules.root
        if parts and self.excluded(rules, parts, kind):
            return None
        if parts and rules.nested:
            key = component_key(root.path.flavour, root.path.drive, (*root.path.parts, *parts))
            if key in rules.nested:
                return None  # another configured root: it records this path itself
        if len(path) > self.limits.max_path_chars:
            self.limit(
                f"path:{path}",
                f"path longer than max_path_chars ({self.limits.max_path_chars}); skipped",
                self.shown_safe(rules, parts),
                stop=False,
            )
            return None
        if len(self.records) >= self.limits.max_files:
            self.limit("max_files", f"more than max_files ({self.limits.max_files}) entries")
            return None
        try:
            stored = record_path(parts)
        except PathRuleError:
            self.issue(
                IssueKind.UNREADABLE, self.shown_safe(rules, parts), "name cannot be recorded"
            )
            return None
        record = self.build_record(rules, parts, stored, path, found, kind)
        if record is None:
            return None
        self.records.append(record)
        if kind is EntryType.DIR:
            self.dirs += 1
            self.queue_directory(rules, parts, path, found, subdirectories, visited, parent_device)
        else:
            self.files += 1
        return record

    def queue_directory(
        self,
        rules: RootRules,
        parts: tuple[str, ...],
        path: str,
        found: RawStat,
        subdirectories: list[_Directory],
        visited: set[tuple[int, int]],
        parent_device: int,
    ) -> None:
        if parts and rules.root.one_file_system and found.dev != parent_device:
            return  # a mount point: recorded, not entered
        if found.ino != 0:  # some filesystems report no inode numbers
            identity = (found.dev, found.ino)
            if identity in visited:
                shown = self.shown_safe(rules, parts)
                self.limit(
                    f"loop:{shown}", "directory reached twice; not entered again", shown, stop=False
                )
                return
            visited.add(identity)
        subdirectories.append(_Directory(parts, path, found.dev))

    # -- building a record ---------------------------------------------------------------------

    def build_record(
        self,
        rules: RootRules,
        parts: tuple[str, ...],
        stored: str,
        path: str,
        found: RawStat,
        kind: EntryType,
    ) -> FileRecord | None:
        fields: dict[str, Any] = {
            "path": stored,
            "root_index": rules.index,
            "type": kind,
            "size": 0 if kind is EntryType.DIR else found.size,
            "mtime_ns": found.mtime_ns,
            "sha256": None,
            "hash_status": HashStatus.NOT_APPLICABLE,
        }
        if found.file_attributes is None:
            fields["mode"] = posix_permissions(found.st_mode)
            fields["uid"] = found.uid
            fields["gid"] = found.gid
        else:
            fields["win_attrs"] = tracked_windows_attributes(found.file_attributes)
        if kind is EntryType.FILE:
            fields["nlink"] = found.nlink
        if found.reparse_tag is not None and kind in (EntryType.SYMLINK, EntryType.REPARSE):
            fields["reparse_tag"] = found.reparse_tag
        shown = self.shown_safe(rules, parts)
        if kind is EntryType.FILE:
            if not self.hash_into(fields, shown, path, found, follow=False):
                return None
        elif kind is EntryType.SYMLINK:
            self.describe_link(fields, shown, path)
            if self.policy.symlinks is SymlinkPolicy.FILES and not self.hash_through(
                fields, shown, path
            ):
                return None
        return FileRecord(**fields)

    def describe_link(self, fields: dict[str, Any], shown: str, path: str) -> None:
        target = self.fs.read_link(path)
        if isinstance(target, FsProblem):
            kind = IssueKind.VANISHED if target.vanished else IssueKind.UNREADABLE
            self.issue(kind, shown, f"link target cannot be read ({target.errno_name})")
            fields["error"] = target.errno_name
            return
        fields["link_target"] = target

    def hash_through(self, fields: dict[str, Any], shown: str, path: str) -> bool:
        """``symlinks: files``: hash what a link points to if that is a regular file."""
        target = self.fs.stat_target(path)
        if isinstance(target, FsProblem) or not _is_regular(target):
            return True  # dangling, a directory or special: nothing to hash, not an error
        return self.hash_into(fields, shown, path, target, follow=True)

    def hash_into(
        self, fields: dict[str, Any], shown: str, path: str, found: RawStat, *, follow: bool
    ) -> bool:
        """Fill the hash fields of a record. False means the time budget ended the read."""
        if found.file_attributes is not None and is_offline(found.file_attributes):
            fields["hash_status"] = HashStatus.SKIPPED_OFFLINE
            self.skipped_offline += 1
            return True
        if found.size > self.limits.max_hash_file_bytes:
            fields["hash_status"] = HashStatus.SKIPPED_TOO_LARGE
            self.skipped_too_large += 1
            return True
        result = self.fs.hash_file(
            path,
            found,
            max_bytes=self.limits.max_hash_file_bytes,
            should_stop=self.time_up,
            follow=follow,
        )
        if result.stopped:
            self.limit("time", f"stopped after the {self.limits.max_run_seconds} s time budget")
            return False
        fields["hash_status"] = result.status
        fields["sha256"] = result.sha256
        if not follow:  # for a link, size and time stay those of the link itself
            fields["size"] = result.size
            fields["mtime_ns"] = result.mtime_ns
        self.account(result, shown)
        if result.error is not None:
            fields["error"] = result.error
        return True

    def account(self, result: HashResult, shown: str) -> None:
        status = result.status
        if status is HashStatus.OK:
            self.bytes_hashed += result.bytes_read
        elif status is HashStatus.SKIPPED_TOO_LARGE:
            self.skipped_too_large += 1
        elif status is HashStatus.UNREADABLE:
            suffix = f" ({result.error})" if result.error else ""
            self.issue(IssueKind.UNREADABLE, shown, result.detail + suffix)
        elif status is HashStatus.UNSTABLE:
            self.issue(IssueKind.UNSTABLE, shown, result.detail)
        else:  # VANISHED: hashing never returns the other statuses
            self.issue(IssueKind.VANISHED, shown, result.detail)

    # -- the whole run -------------------------------------------------------------------------

    def run(self) -> ScanResult:
        started = self.clock.now()
        for rules in self.rules:
            if self.halted or self.check_time():
                break
            self.scan_root(rules)
        return ScanResult(
            records=tuple(self.records),
            issues=tuple(self.issues),
            complete=not self.incomplete,
            stats=ScanStats(
                files=self.files,
                dirs=self.dirs,
                bytes_hashed=self.bytes_hashed,
                skipped_too_large=self.skipped_too_large,
                skipped_offline=self.skipped_offline,
            ),
            started_at=started,
            finished_at=self.clock.now(),
        )


def _is_regular(found: RawStat) -> bool:
    return entry_type(found.st_mode, found.file_attributes, found.reparse_tag) is EntryType.FILE


def scan(policy: Policy, clock: Clock, *, view: FileSystemView | None = None) -> ScanResult:
    """Scan every root of ``policy`` and return what was found, never raising for a bad entry.

    ``view`` defaults to the real filesystem. The result is incomplete (``complete=False``)
    when any limit or the time budget stopped the run early.
    """
    return _Scan(policy, clock, view if view is not None else ObservedFileSystem()).run()
