"""Baseline records against the current scan: findings, severity and confidence (PLAN.md D5, D8,
section 2). Pure logic: no I/O, no clock.

Per path (keyed by root index and the exact root-relative path):

* absent in the baseline -> ``created``; absent now -> ``deleted``;
* the type differs -> ``type_changed`` and nothing else for that path;
* otherwise, content: both hashed and the hash differs -> ``modified``; a link whose target
  differs -> ``modified``; a file that was not hashed (too large, offline) is compared by size
  and modification time, at lower confidence; an identical hash with a different modification
  time is not a finding but is counted (``mtime_only_changes``);
* ``mode``, ``uid``, ``gid`` or the Windows attributes differ -> ``permission_changed``;
* a regular file's hard link count differs -> ``links_changed``.

One path can give ``modified`` and ``permission_changed`` together. Directories are compared by
type and permissions only; their size and modification time churn and are not findings.

Severity is how much a change matters (the root's rule, adjusted: a type change is one step
worse, a permission change that adds world-write, setuid or setgid, or clears READONLY on a
SYSTEM file, is one step worse, hard links and scan problems are ``low``, a root that cannot be
scanned is ``critical``). Confidence is how sure the observation is, a separate field.

A root that cannot be scanned gives one ``root_unavailable`` finding and its files are not
reported deleted (they are counted as suppressed). When the scan was incomplete, or a file's
directory could not be read, a missing file is reported with low confidence instead of high.
A deleted and a created file with the same SHA-256 get "possible rename" evidence.

Every text field of a finding is escaped text (core/sanitize.py); the finding id is derived from
the exact, unescaped facts, so it does not depend on the running Python's Unicode tables.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from datetime import datetime

from fim.core.canonical import canonical_json
from fim.core.limits import MAX_EVIDENCE_CHARS_CEILING, MAX_FINDINGS_REPORTED_CEILING
from fim.core.models import (
    Baseline,
    BaselineHeader,
    Change,
    Confidence,
    EntryType,
    FileRecord,
    Finding,
    FindingKind,
    HashStatus,
    IssueKind,
    Report,
    ReportSummary,
    ScanIssue,
    ScanResult,
    Severity,
)
from fim.core.pathrules import Flavour, UserPath, display_link_target, display_path
from fim.core.perms import (
    FILE_ATTRIBUTE_READONLY,
    FILE_ATTRIBUTE_SYSTEM,
    describe_posix_mode,
    describe_windows_attributes,
)

__all__ = [
    "DiffResult",
    "build_report",
    "compare",
    "policy_drift_finding",
]

SUPPRESSED_DELETED_UNAVAILABLE = "deleted files under an unavailable monitored path"
SUPPRESSED_BELOW_MINIMUM = "findings below the minimum severity"

_NOT_HASHED_FAILURES = frozenset({HashStatus.UNREADABLE, HashStatus.UNSTABLE, HashStatus.VANISHED})
_NO_CONTENT_TYPES = frozenset(
    {EntryType.DIR, EntryType.FIFO, EntryType.SOCKET, EntryType.DEVICE, EntryType.OTHER}
)
_ISSUE_FINDINGS = {
    IssueKind.UNREADABLE: FindingKind.UNREADABLE,
    IssueKind.UNSTABLE: FindingKind.UNSTABLE,
    IssueKind.VANISHED: FindingKind.VANISHED,
}
_WORLD_WRITE = 0o002
_SETUID = 0o4000
_SETGID = 0o2000
_ELLIPSIS = "..."
_MAX_ESCAPE_WIDTH = 10
_ESCAPE_WIDTHS = {"x": 2, "y": 2, "u": 4, "U": 8}
_HEX = frozenset("0123456789abcdef")
_SHORT_HASH = 16


@dataclass(frozen=True, slots=True)
class DiffResult:
    """Everything the comparison found, before the report is assembled."""

    findings: tuple[Finding, ...]
    mtime_only_changes: int
    suppressed: tuple[tuple[str, int], ...]


# ---- small helpers -------------------------------------------------------------------------------


def _clip(text: str, limit: int) -> str:
    """Cut already-escaped text to ``limit`` characters without ending inside an escape."""
    if len(text) <= limit:
        return text
    cut = max(limit - len(_ELLIPSIS), 0)
    window_start = max(cut - _MAX_ESCAPE_WIDTH, 0)
    backslash = text.rfind("\\", window_start, cut)
    if backslash >= 0 and backslash + 1 < len(text) and text[backslash + 1] in _ESCAPE_WIDTHS:
        width = _ESCAPE_WIDTHS[text[backslash + 1]]
        digits = text[backslash + 2 : backslash + 2 + width]
        if len(digits) == width and _HEX.issuperset(digits) and backslash + 2 + width > cut:
            cut = backslash  # the cut would split a complete escape sequence
    return text[:cut] + _ELLIPSIS


def _fingerprint(record: FileRecord | None) -> dict[str, object] | None:
    """The facts a finding is about; the modification time only where there is no hash."""
    if record is None:
        return None
    return {
        "type": record.type.value,
        "size": record.size,
        "sha256": record.sha256,
        "hash_status": record.hash_status.value,
        "mode": record.mode,
        "uid": record.uid,
        "gid": record.gid,
        "win_attrs": record.win_attrs,
        "nlink": record.nlink,
        "link_target": record.link_target,
        "reparse_tag": record.reparse_tag,
        "mtime_ns": record.mtime_ns if record.sha256 is None else None,
    }


def _finding_id(document: dict[str, object]) -> str:
    return hashlib.sha256(canonical_json(document)).hexdigest()[:16]


def _step_up(severity: Severity) -> Severity:
    return Severity(min(severity + 1, Severity.CRITICAL))


def _short(sha256: str | None) -> str:
    return "none" if sha256 is None else sha256[:_SHORT_HASH] + "..."


def _target_text(record: FileRecord, flavour: Flavour) -> str | None:
    if record.link_target is None:
        return None
    return display_link_target(record.link_target, flavour)


def _escalates(old: FileRecord, new: FileRecord) -> bool:
    """True if the permission change makes the file more dangerous (PLAN.md D8)."""
    if old.mode is not None and new.mode is not None:
        added = new.mode & ~old.mode
        return bool(added & (_WORLD_WRITE | _SETUID | _SETGID))
    if old.win_attrs is not None and new.win_attrs is not None:
        cleared_readonly = bool(old.win_attrs & FILE_ATTRIBUTE_READONLY) and not (
            new.win_attrs & FILE_ATTRIBUTE_READONLY
        )
        return cleared_readonly and bool(new.win_attrs & FILE_ATTRIBUTE_SYSTEM)
    return False


# ---- one path ------------------------------------------------------------------------------------


class _Context:
    """What the comparison needs to know about the policy and the scan."""

    def __init__(self, baseline: Baseline, current: ScanResult) -> None:
        policy = baseline.header.policy
        self.roots: tuple[UserPath, ...] = tuple(root.path for root in policy.roots)
        self.severities = tuple(root.severity for root in policy.roots)
        self.root_names = tuple(path.display() for path in self.roots)
        self.complete = current.complete
        self.issues = current.issues
        self.mtime_only = 0
        by_name = {name: index for index, name in enumerate(self.root_names)}
        self.unavailable = {
            by_name[issue.path]
            for issue in current.issues
            if issue.kind is IssueKind.ROOT_UNAVAILABLE and issue.path in by_name
        }
        self.problem_paths = {
            issue.path for issue in current.issues if issue.kind in _ISSUE_FINDINGS
        }

    def shown(self, root_index: int, record_path: str) -> str:
        return display_path(self.roots[root_index], record_path)

    def flavour(self, root_index: int) -> Flavour:
        return self.roots[root_index].flavour

    def ancestors_with_problems(self, root_index: int, record_path: str) -> bool:
        """True if a directory above ``record_path`` had a read problem in this scan."""
        if not self.problem_paths or record_path == "":
            return False
        parts = record_path.split("/")
        for length in range(len(parts)):
            if self.shown(root_index, "/".join(parts[:length])) in self.problem_paths:
                return True
        return False


def _make(
    context: _Context,
    root_index: int,
    record_path: str,
    kind: FindingKind,
    severity: Severity,
    confidence: Confidence,
    changes: Sequence[Change],
    evidence: str,
    old: FileRecord | None,
    new: FileRecord | None,
) -> Finding:
    identity: dict[str, object] = {
        "root": root_index,
        "path": record_path,
        "kind": kind.value,
        "old": _fingerprint(old),
        "new": _fingerprint(new),
    }
    return Finding(
        finding_id=_finding_id(identity),
        kind=kind,
        path=context.shown(root_index, record_path),
        severity=severity,
        confidence=confidence,
        changes=tuple(changes),
        evidence=_clip(evidence, MAX_EVIDENCE_CHARS_CEILING),
        rule=context.root_names[root_index],
    )


def _created(context: _Context, record: FileRecord) -> Finding:
    detail = f"new {record.type.value}"
    if record.type is EntryType.FILE:
        detail += f", {record.size} bytes, sha256 {_short(record.sha256)}"
    changes = (Change(field="type", old=None, new=record.type.value),)
    return _make(
        context,
        record.root_index,
        record.path,
        FindingKind.CREATED,
        context.severities[record.root_index],
        Confidence.HIGH,
        changes,
        detail,
        None,
        record,
    )


def _deleted(context: _Context, record: FileRecord) -> Finding:
    detail = f"{record.type.value} is no longer present"
    confidence = Confidence.HIGH
    if not context.complete:
        confidence = Confidence.LOW
        detail += "; the scan was incomplete, so it may only be unscanned"
    elif context.ancestors_with_problems(record.root_index, record.path):
        confidence = Confidence.LOW
        detail += "; a directory above it could not be read in this scan"
    changes = (Change(field="type", old=record.type.value, new=None),)
    return _make(
        context,
        record.root_index,
        record.path,
        FindingKind.DELETED,
        context.severities[record.root_index],
        confidence,
        changes,
        detail,
        record,
        None,
    )


def _content_changes(
    context: _Context, old: FileRecord, new: FileRecord
) -> tuple[list[Change], list[str], Confidence] | None:
    """The content difference between two records of the same type, or None for none."""
    changes: list[Change] = []
    notes: list[str] = []
    confidence = Confidence.HIGH
    flavour = context.flavour(new.root_index)
    if new.type in _NO_CONTENT_TYPES:
        return None
    if new.type is EntryType.SYMLINK:
        if old.link_target != new.link_target:
            old_text, new_text = _target_text(old, flavour), _target_text(new, flavour)
            changes.append(Change(field="link_target", old=old_text, new=new_text))
            notes.append("link target changed")
        if old.sha256 is not None and new.sha256 is not None and old.sha256 != new.sha256:
            changes.append(Change(field="sha256", old=old.sha256, new=new.sha256))
            notes.append("content behind the link changed")
    elif new.type is EntryType.REPARSE:
        if old.reparse_tag != new.reparse_tag:
            changes.append(
                Change(field="reparse_tag", old=str(old.reparse_tag), new=str(new.reparse_tag))
            )
            notes.append("reparse tag changed")
    elif old.hash_status is HashStatus.OK and new.hash_status is HashStatus.OK:
        if old.sha256 != new.sha256:
            changes.append(Change(field="sha256", old=old.sha256, new=new.sha256))
            notes.append(f"sha256 differs ({_short(old.sha256)} -> {_short(new.sha256)})")
            if old.size != new.size:
                changes.append(Change(field="size", old=str(old.size), new=str(new.size)))
                notes.append(f"size {old.size} -> {new.size}")
        elif old.mtime_ns != new.mtime_ns:
            context.mtime_only += 1  # same content: not a finding, but counted
    elif (old.size, old.mtime_ns) != (new.size, new.mtime_ns):
        # At least one side was not hashed (too large, offline, unreadable then): weaker evidence.
        confidence = Confidence.MEDIUM
        if old.size != new.size:
            changes.append(Change(field="size", old=str(old.size), new=str(new.size)))
            notes.append(f"size {old.size} -> {new.size}")
        if old.mtime_ns != new.mtime_ns:
            changes.append(Change(field="mtime_ns", old=str(old.mtime_ns), new=str(new.mtime_ns)))
            notes.append("modification time differs")
        notes.append("not compared by hash")
    if not changes:
        return None
    return changes, notes, confidence


def _permission_changes(old: FileRecord, new: FileRecord) -> list[Change]:
    changes: list[Change] = []
    if old.mode != new.mode:
        old_mode = None if old.mode is None else describe_posix_mode(old.mode)
        new_mode = None if new.mode is None else describe_posix_mode(new.mode)
        changes.append(Change(field="mode", old=old_mode, new=new_mode))
    if old.win_attrs != new.win_attrs:
        old_attrs = None if old.win_attrs is None else describe_windows_attributes(old.win_attrs)
        new_attrs = None if new.win_attrs is None else describe_windows_attributes(new.win_attrs)
        changes.append(Change(field="win_attrs", old=old_attrs, new=new_attrs))
    if old.uid != new.uid:
        changes.append(Change(field="uid", old=_text_or_none(old.uid), new=_text_or_none(new.uid)))
    if old.gid != new.gid:
        changes.append(Change(field="gid", old=_text_or_none(old.gid), new=_text_or_none(new.gid)))
    return changes


def _text_or_none(value: int | None) -> str | None:
    return None if value is None else str(value)


def _compare_pair(context: _Context, old: FileRecord, new: FileRecord) -> list[Finding]:
    root = new.root_index
    base = context.severities[root]
    if old.type is not new.type:
        evidence = f"type changed from {old.type.value} to {new.type.value}"
        change = Change(field="type", old=old.type.value, new=new.type.value)
        return [
            _make(
                context,
                root,
                new.path,
                FindingKind.TYPE_CHANGED,
                _step_up(base),
                Confidence.HIGH,
                [change],
                evidence,
                old,
                new,
            )
        ]
    findings: list[Finding] = []
    if new.hash_status not in _NOT_HASHED_FAILURES:
        content = _content_changes(context, old, new)
        if content is not None:
            changes, notes, confidence = content
            findings.append(
                _make(
                    context,
                    root,
                    new.path,
                    FindingKind.MODIFIED,
                    base,
                    confidence,
                    changes,
                    "; ".join(notes),
                    old,
                    new,
                )
            )
    permission = _permission_changes(old, new)
    if permission:
        escalated = _escalates(old, new)
        severity = _step_up(base) if escalated else base
        notes = [f"{change.field} {change.old} -> {change.new}" for change in permission]
        if escalated:
            notes.append("more dangerous than before")
        findings.append(
            _make(
                context,
                root,
                new.path,
                FindingKind.PERMISSION_CHANGED,
                severity,
                Confidence.HIGH,
                permission,
                "; ".join(notes),
                old,
                new,
            )
        )
    if new.type is EntryType.FILE and old.nlink != new.nlink:
        change = Change(field="nlink", old=str(old.nlink), new=str(new.nlink))
        findings.append(
            _make(
                context,
                root,
                new.path,
                FindingKind.LINKS_CHANGED,
                Severity.LOW,
                Confidence.MEDIUM,
                [change],
                f"hard link count {old.nlink} -> {new.nlink}",
                old,
                new,
            )
        )
    return findings


# ---- rename hints, scan problems, unavailable roots ----------------------------------------


def _with_rename_hints(findings: list[Finding], records: dict[str, FileRecord]) -> list[Finding]:
    """Add "possible rename" evidence to deleted/created pairs with the same SHA-256."""
    created: dict[str, list[str]] = {}
    deleted: dict[str, list[str]] = {}
    for finding in findings:
        record = records.get(finding.finding_id)
        if record is None or record.sha256 is None or record.type is not EntryType.FILE:
            continue
        bucket = created if finding.kind is FindingKind.CREATED else deleted
        bucket.setdefault(record.sha256, []).append(finding.path)
    result: list[Finding] = []
    for finding in findings:
        record = records.get(finding.finding_id)
        others: list[str] = []
        if record is not None and record.sha256 is not None:
            counterpart = deleted if finding.kind is FindingKind.CREATED else created
            others = sorted(counterpart.get(record.sha256, []))
        if not others:
            result.append(finding)
            continue
        more = f" and {len(others) - 1} more" if len(others) > 1 else ""
        hint = f"; same content as {others[0]}{more} (possible rename)"
        result.append(
            replace(
                finding,
                confidence=Confidence.LOW,
                evidence=_clip(finding.evidence + hint, MAX_EVIDENCE_CHARS_CEILING),
            )
        )
    return result


def _issue_finding(context: _Context, issue: ScanIssue) -> Finding:
    kind = _ISSUE_FINDINGS[issue.kind]
    best = ""
    for name in context.root_names:
        if issue.path.startswith(name) and len(name) > len(best):
            best = name
    identity: dict[str, object] = {"issue": issue.kind.value, "path": issue.path}
    return Finding(
        finding_id=_finding_id(identity),
        kind=kind,
        path=issue.path,
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        changes=(),
        evidence=_clip(issue.detail, MAX_EVIDENCE_CHARS_CEILING),
        rule=best,
    )


def _unavailable_finding(context: _Context, root_index: int, detail: str) -> Finding:
    identity: dict[str, object] = {"root": root_index, "unavailable": True}
    name = context.root_names[root_index]
    return Finding(
        finding_id=_finding_id(identity),
        kind=FindingKind.ROOT_UNAVAILABLE,
        path=name,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        changes=(),
        evidence=_clip(detail, MAX_EVIDENCE_CHARS_CEILING),
        rule=name,
    )


# ---- the comparison ------------------------------------------------------------------------------


def compare(baseline: Baseline, current: ScanResult) -> DiffResult:
    """Compare the baseline with a scan made under the baseline's own policy."""
    context = _Context(baseline, current)
    old_records = {(r.root_index, r.path): r for r in baseline.records}
    new_records = {(r.root_index, r.path): r for r in current.records}
    findings: list[Finding] = []
    by_id: dict[str, FileRecord] = {}
    suppressed = 0

    for key in sorted(new_records.keys() - old_records.keys()):
        created = _created(context, new_records[key])
        findings.append(created)
        by_id[created.finding_id] = new_records[key]
    for key in sorted(old_records.keys() - new_records.keys()):
        gone = old_records[key]
        if gone.root_index in context.unavailable:
            suppressed += 1
        elif context.shown(gone.root_index, gone.path) in context.problem_paths:
            continue  # the unreadable/vanished finding for this very path says it
        else:
            deleted = _deleted(context, gone)
            findings.append(deleted)
            by_id[deleted.finding_id] = gone
    for key in sorted(old_records.keys() & new_records.keys()):
        findings.extend(_compare_pair(context, old_records[key], new_records[key]))

    findings = _with_rename_hints(findings, by_id)
    for issue in current.issues:
        if issue.kind in _ISSUE_FINDINGS:
            findings.append(_issue_finding(context, issue))
    for issue in current.issues:
        if issue.kind is IssueKind.ROOT_UNAVAILABLE and issue.path in context.root_names:
            index = context.root_names.index(issue.path)
            findings.append(_unavailable_finding(context, index, issue.detail))
    counts = ((SUPPRESSED_DELETED_UNAVAILABLE, suppressed),) if suppressed else ()
    return DiffResult(tuple(findings), context.mtime_only, counts)


def policy_drift_finding(baseline_digest: str, config_digest: str) -> Finding:
    """The notice that a configuration file describes another policy than the baseline holds.

    The check keeps using the baseline's policy (PLAN.md D4); this only recommends a new baseline.
    """
    identity: dict[str, object] = {"drift": [baseline_digest, config_digest]}
    return Finding(
        finding_id=_finding_id(identity),
        kind=FindingKind.POLICY_DRIFT,
        path="",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        changes=(
            Change(
                field="policy_digest",
                old=baseline_digest[:_SHORT_HASH],
                new=config_digest[:_SHORT_HASH],
            ),
        ),
        evidence=(
            "the configuration file describes a different policy than the baseline; this check "
            "used the baseline's policy. Run 'fim baseline --force' to adopt the new one"
        ),
        rule="",
    )


# ---- the report ----------------------------------------------------------------------------------


def _sort_key(finding: Finding) -> tuple[int, str, str, str]:
    return (-int(finding.severity), finding.path, finding.kind.value, finding.finding_id)


def build_report(
    diff: DiffResult,
    *,
    extra: Iterable[Finding] = (),
    header: BaselineHeader,
    key_id: str,
    generated_at: datetime,
    tool_version: str,
    complete: bool,
    min_severity: Severity = Severity.INFO,
    max_findings: int = MAX_FINDINGS_REPORTED_CEILING,
) -> Report:
    """Assemble the Report: filter by minimum severity, sort, count exactly, then truncate.

    The counts in the summary cover every finding at or above ``min_severity`` even when the
    list is cut at ``max_findings``; ``truncated`` says that it was. Findings below the minimum
    are counted in the summary as suppressed.
    """
    candidates = [*diff.findings, *extra]
    kept = [finding for finding in candidates if finding.severity >= min_severity]
    below = len(candidates) - len(kept)
    kept.sort(key=_sort_key)
    kinds = Counter(finding.kind for finding in kept)
    severities = Counter(finding.severity for finding in kept)
    suppressed = list(diff.suppressed)
    if below:
        suppressed.append((SUPPRESSED_BELOW_MINIMUM, below))
    summary = ReportSummary(
        by_kind=tuple((kind, kinds[kind]) for kind in FindingKind if kinds[kind]),
        by_severity=tuple(
            (severity, severities[severity])
            for severity in sorted(severities, key=int, reverse=True)
        ),
        suppressed=tuple(suppressed),
        mtime_only_changes=diff.mtime_only_changes,
    )
    limit = min(max_findings, MAX_FINDINGS_REPORTED_CEILING)
    return Report(
        findings=tuple(kept[:limit]),
        summary=summary,
        complete=complete,
        truncated=len(kept) > limit,
        baseline_created_at=header.created_at,
        baseline_sequence=header.sequence,
        baseline_key_id=key_id,
        generated_at=generated_at,
        tool_version=tool_version,
    )
