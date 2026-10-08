"""The data model (PLAN.md section 2): frozen dataclasses and closed vocabularies.

Every object checks its own invariants on creation and raises ModelError (never ``assert``), so
a bug elsewhere cannot smuggle an inconsistent record into a baseline or a report. A
``FileRecord`` holds the exact path and link target as the filesystem reports them (PLAN.md D14);
every other text field that can come from the filesystem (findings, issues, changes, evidence)
holds *escaped* text (core/sanitize.py) and an unescaped dangerous character is a ModelError.
Collections are tuples so the objects stay immutable.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from fim.core.errors import ModelError, PathRuleError
from fim.core.limits import MAX_EVIDENCE_CHARS_CEILING, MAX_FINDINGS_REPORTED_CEILING, Limits
from fim.core.pathrules import UserPath, split_record_path
from fim.core.sanitize import clip_escaped, first_unsafe

__all__ = [
    "Baseline",
    "BaselineHeader",
    "Change",
    "Confidence",
    "EntryType",
    "FileRecord",
    "Finding",
    "FindingKind",
    "HashStatus",
    "IssueKind",
    "Policy",
    "Report",
    "ReportSummary",
    "RootPolicy",
    "ScanIssue",
    "ScanResult",
    "ScanStats",
    "Severity",
    "SymlinkPolicy",
]

_SHA256 = re.compile(r"[0-9a-f]{64}")
_HEX16 = re.compile(r"[0-9a-f]{16}")
_MAX_MODE = 0o177777


# ---- closed vocabularies -------------------------------------------------------------------------


class EntryType(enum.StrEnum):
    FILE = "file"
    DIR = "dir"
    SYMLINK = "symlink"
    REPARSE = "reparse"
    FIFO = "fifo"
    SOCKET = "socket"
    DEVICE = "device"
    OTHER = "other"


class HashStatus(enum.StrEnum):
    OK = "ok"
    SKIPPED_TOO_LARGE = "skipped_too_large"
    SKIPPED_OFFLINE = "skipped_offline"
    NOT_APPLICABLE = "not_applicable"
    UNREADABLE = "unreadable"
    VANISHED = "vanished"
    UNSTABLE = "unstable"


class IssueKind(enum.StrEnum):
    UNREADABLE = "unreadable"
    UNSTABLE = "unstable"
    VANISHED = "vanished"
    ROOT_UNAVAILABLE = "root_unavailable"
    LIMIT_REACHED = "limit_reached"
    TIME_BUDGET = "time_budget"


class FindingKind(enum.StrEnum):
    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    PERMISSION_CHANGED = "permission_changed"
    TYPE_CHANGED = "type_changed"
    LINKS_CHANGED = "links_changed"
    UNREADABLE = "unreadable"
    UNSTABLE = "unstable"
    VANISHED = "vanished"
    ROOT_UNAVAILABLE = "root_unavailable"
    POLICY_DRIFT = "policy_drift"
    BASELINE_INTEGRITY = "baseline_integrity"
    RESOLVED = "resolved"  # watch only


class SymlinkPolicy(enum.StrEnum):
    NEVER = "never"
    FILES = "files"


class Severity(enum.IntEnum):
    """How much a change matters. Ordered: INFO < LOW < MEDIUM < HIGH < CRITICAL."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def from_label(cls, label: str) -> Severity:
        try:
            return cls[label.upper()]
        except KeyError:
            raise ModelError(f"unknown severity '{clip_escaped(label, 20)}'") from None


class Confidence(enum.IntEnum):
    """How sure the observation is. Ordered: LOW < MEDIUM < HIGH."""

    LOW = 0
    MEDIUM = 1
    HIGH = 2

    @property
    def label(self) -> str:
        return self.name.lower()


# ---- validation helpers --------------------------------------------------------------------------


def _safe_text(owner: str, name: str, value: str | None) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        raise ModelError(f"{owner}.{name} must be text")
    if first_unsafe(value) is not None:
        raise ModelError(f"{owner}.{name} holds a character that was not escaped")


def _record_text(owner: str, name: str, value: str | None) -> None:
    """Exact filesystem text: any characters at all, lone surrogates included."""
    if value is not None and not isinstance(value, str):
        raise ModelError(f"{owner}.{name} must be text")


def _non_negative(owner: str, name: str, value: int | None) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ModelError(f"{owner}.{name} must be a non-negative integer")


def _utc(owner: str, name: str, value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ModelError(f"{owner}.{name} must be a timezone-aware UTC datetime")


def _hex(owner: str, name: str, value: str, pattern: re.Pattern[str]) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ModelError(f"{owner}.{name} must be lower-case hex of the right length")


# ---- scanning ------------------------------------------------------------------------------------

# Only regular files (and symlinks, whose target the "files" policy may hash) get a hash.
_NO_HASH_TYPES = frozenset(
    {
        EntryType.DIR,
        EntryType.REPARSE,
        EntryType.FIFO,
        EntryType.SOCKET,
        EntryType.DEVICE,
        EntryType.OTHER,
    }
)


@dataclass(frozen=True, slots=True, kw_only=True)
class FileRecord:
    """What was observed about one path.

    ``path`` is root-relative, "/"-separated and exact (not escaped; "" is the root itself), and
    so is ``link_target``. Both are serialised by canonical JSON and escaped only for display.
    """

    path: str
    root_index: int
    type: EntryType
    size: int
    mtime_ns: int
    sha256: str | None
    hash_status: HashStatus
    mode: int | None = None  # POSIX permission bits (S_IMODE)
    uid: int | None = None
    gid: int | None = None
    win_attrs: int | None = None  # masked Windows attribute bits
    nlink: int = 1
    link_target: str | None = None  # escaped text
    reparse_tag: int | None = None
    error: str | None = None  # errno name

    def __post_init__(self) -> None:
        owner = "FileRecord"
        _record_text(owner, "path", self.path)
        _record_text(owner, "link_target", self.link_target)
        _safe_text(owner, "error", self.error)
        try:
            split_record_path(self.path)  # "" is the root; no empty, "." or ".." component
        except PathRuleError:
            raise ModelError("FileRecord.path is not a valid record path") from None
        for name in ("root_index", "size", "nlink", "uid", "gid", "mode", "win_attrs"):
            _non_negative(owner, name, getattr(self, name))
        if self.mode is not None and self.mode > _MAX_MODE:
            raise ModelError("FileRecord.mode is not a permission mask")
        if self.mode is not None and self.win_attrs is not None:
            raise ModelError("FileRecord has both POSIX mode and Windows attributes")
        if self.sha256 is not None:
            _hex(owner, "sha256", self.sha256, _SHA256)
        # A hash exists exactly when hashing succeeded: a partial file is never given a hash.
        if (self.hash_status is HashStatus.OK) != (self.sha256 is not None):
            raise ModelError("FileRecord.sha256 must be present exactly when hash_status is ok")
        if self.type in _NO_HASH_TYPES and self.hash_status is not HashStatus.NOT_APPLICABLE:
            raise ModelError(f"a {self.type.value} record is never hashed")
        if self.type is EntryType.FILE and self.hash_status is HashStatus.NOT_APPLICABLE:
            raise ModelError("a file record needs a real hash_status")
        if self.link_target is not None and self.type is not EntryType.SYMLINK:
            raise ModelError("only a symlink record has a link_target")
        if self.reparse_tag is not None and self.type not in (EntryType.REPARSE, EntryType.SYMLINK):
            raise ModelError("only a reparse point or symlink record has a reparse_tag")


@dataclass(frozen=True, slots=True, kw_only=True)
class ScanIssue:
    """A problem met while scanning. It never aborts the run; it is reported."""

    path: str
    kind: IssueKind
    detail: str

    def __post_init__(self) -> None:
        _safe_text("ScanIssue", "path", self.path)
        _safe_text("ScanIssue", "detail", self.detail)


@dataclass(frozen=True, slots=True, kw_only=True)
class ScanStats:
    files: int = 0
    dirs: int = 0
    bytes_hashed: int = 0
    skipped_too_large: int = 0
    skipped_offline: int = 0

    def __post_init__(self) -> None:
        for name in ("files", "dirs", "bytes_hashed", "skipped_too_large", "skipped_offline"):
            _non_negative("ScanStats", name, getattr(self, name))


_INCOMPLETE_KINDS = frozenset({IssueKind.LIMIT_REACHED, IssueKind.TIME_BUDGET})


@dataclass(frozen=True, slots=True, kw_only=True)
class ScanResult:
    records: tuple[FileRecord, ...]
    issues: tuple[ScanIssue, ...]
    complete: bool
    stats: ScanStats
    started_at: datetime
    finished_at: datetime

    def __post_init__(self) -> None:
        _utc("ScanResult", "started_at", self.started_at)
        _utc("ScanResult", "finished_at", self.finished_at)
        if self.finished_at < self.started_at:
            raise ModelError("ScanResult finished before it started")
        # Hitting a limit is never "clean".
        if self.complete and any(issue.kind in _INCOMPLETE_KINDS for issue in self.issues):
            raise ModelError("a scan that hit a limit cannot be marked complete")


# ---- policy and baseline -------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class RootPolicy:
    path: UserPath
    severity: Severity = Severity.MEDIUM
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    one_file_system: bool = True

    def __post_init__(self) -> None:
        if not self.path.absolute:
            raise ModelError("a monitored root must be an absolute path")


@dataclass(frozen=True, slots=True, kw_only=True)
class Policy:
    """The effective policy; it is stored in the baseline and the baseline's copy is trusted."""

    roots: tuple[RootPolicy, ...]
    exclude: tuple[str, ...]
    symlinks: SymlinkPolicy
    limits: Limits
    digest: str  # SHA-256 over the canonical policy, computed by core/policy.py

    def __post_init__(self) -> None:
        if not self.roots:
            raise ModelError("a policy needs at least one root")
        if len(self.roots) > self.limits.max_roots:
            raise ModelError("a policy has more roots than the limit allows")
        _hex("Policy", "digest", self.digest, _SHA256)


@dataclass(frozen=True, slots=True, kw_only=True)
class BaselineHeader:
    tool_version: str
    created_at: datetime
    sequence: int
    host: str
    platform: str
    policy: Policy
    complete: bool
    limits: Limits

    def __post_init__(self) -> None:
        owner = "BaselineHeader"
        for name in ("tool_version", "host", "platform"):
            _safe_text(owner, name, getattr(self, name))
        _utc(owner, "created_at", self.created_at)
        _non_negative(owner, "sequence", self.sequence)
        if self.sequence < 1:
            raise ModelError("BaselineHeader.sequence starts at 1")


@dataclass(frozen=True, slots=True, kw_only=True)
class Baseline:
    header: BaselineHeader
    records: tuple[FileRecord, ...]


# ---- findings and reports ------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class Change:
    """One field that differs between the baseline and now."""

    field: str
    old: str | None
    new: str | None

    def __post_init__(self) -> None:
        for name in ("field", "old", "new"):
            _safe_text("Change", name, getattr(self, name))


@dataclass(frozen=True, slots=True, kw_only=True)
class Finding:
    finding_id: str  # 16 hex characters, derived from the canonical finding content
    kind: FindingKind
    path: str
    severity: Severity
    confidence: Confidence
    changes: tuple[Change, ...]
    evidence: str
    rule: str  # the monitored root whose rule applied

    def __post_init__(self) -> None:
        _hex("Finding", "finding_id", self.finding_id, _HEX16)
        for name in ("path", "evidence", "rule"):
            _safe_text("Finding", name, getattr(self, name))
        if len(self.evidence) > MAX_EVIDENCE_CHARS_CEILING:
            raise ModelError("Finding.evidence is longer than the evidence limit")


@dataclass(frozen=True, slots=True, kw_only=True)
class ReportSummary:
    by_kind: tuple[tuple[FindingKind, int], ...] = ()
    by_severity: tuple[tuple[Severity, int], ...] = ()
    suppressed: tuple[tuple[str, int], ...] = ()  # e.g. deletions under an unavailable root
    mtime_only_changes: int = 0  # changed mtime, identical hash: counted, not a finding

    def __post_init__(self) -> None:
        _non_negative("ReportSummary", "mtime_only_changes", self.mtime_only_changes)
        for _, count in (*self.by_kind, *self.by_severity, *self.suppressed):
            _non_negative("ReportSummary", "count", count)
        for label, _ in self.suppressed:
            _safe_text("ReportSummary", "suppressed", label)


@dataclass(frozen=True, slots=True, kw_only=True)
class Report:
    findings: tuple[Finding, ...]
    summary: ReportSummary
    complete: bool
    truncated: bool  # findings beyond MAX_FINDINGS_REPORTED were counted but not listed
    baseline_created_at: datetime
    baseline_sequence: int
    baseline_key_id: str
    generated_at: datetime
    tool_version: str

    def __post_init__(self) -> None:
        owner = "Report"
        _utc(owner, "baseline_created_at", self.baseline_created_at)
        _utc(owner, "generated_at", self.generated_at)
        _hex(owner, "baseline_key_id", self.baseline_key_id, _HEX16)
        _non_negative(owner, "baseline_sequence", self.baseline_sequence)
        _safe_text(owner, "tool_version", self.tool_version)
        if len(self.findings) > MAX_FINDINGS_REPORTED_CEILING:
            raise ModelError("Report lists more findings than the reporting limit")
