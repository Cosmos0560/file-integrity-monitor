"""Builders for valid model objects; tests override only the field they are about."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fim.core.limits import DEFAULT_LIMITS
from fim.core.models import (
    BaselineHeader,
    Confidence,
    EntryType,
    FileRecord,
    Finding,
    FindingKind,
    HashStatus,
    Policy,
    Report,
    ReportSummary,
    RootPolicy,
    ScanResult,
    ScanStats,
    Severity,
    SymlinkPolicy,
)
from fim.core.pathrules import Flavour, validate_user_path

SHA = "ab" * 32
WHEN = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def record(**overrides: Any) -> FileRecord:
    fields: dict[str, Any] = {
        "path": "docs/a.txt",
        "root_index": 0,
        "type": EntryType.FILE,
        "size": 3,
        "mtime_ns": 1_700_000_000_000_000_000,
        "sha256": SHA,
        "hash_status": HashStatus.OK,
        "mode": 0o644,
        "uid": 1000,
        "gid": 1000,
        "nlink": 1,
    }
    fields.update(overrides)
    return FileRecord(**fields)


def directory(**overrides: Any) -> FileRecord:
    fields: dict[str, Any] = {
        "type": EntryType.DIR,
        "sha256": None,
        "hash_status": HashStatus.NOT_APPLICABLE,
        "size": 0,
        "mode": 0o755,
    }
    fields.update(overrides)
    return record(**fields)


def root(raw: str = "/data", **overrides: Any) -> RootPolicy:
    return RootPolicy(path=validate_user_path(raw, Flavour.POSIX), **overrides)


def policy(**overrides: Any) -> Policy:
    fields: dict[str, Any] = {
        "roots": (root(),),
        "exclude": ("*.tmp",),
        "symlinks": SymlinkPolicy.NEVER,
        "limits": DEFAULT_LIMITS,
        "digest": "cd" * 32,
    }
    fields.update(overrides)
    return Policy(**fields)


def header(**overrides: Any) -> BaselineHeader:
    fields: dict[str, Any] = {
        "tool_version": "0.1.0",
        "created_at": WHEN,
        "sequence": 1,
        "host": "lab-01",
        "platform": "linux",
        "policy": policy(),
        "complete": True,
        "limits": DEFAULT_LIMITS,
    }
    fields.update(overrides)
    return BaselineHeader(**fields)


def scan_result(**overrides: Any) -> ScanResult:
    fields: dict[str, Any] = {
        "records": (record(),),
        "issues": (),
        "complete": True,
        "stats": ScanStats(files=1),
        "started_at": WHEN,
        "finished_at": WHEN,
    }
    fields.update(overrides)
    return ScanResult(**fields)


def finding(**overrides: Any) -> Finding:
    fields: dict[str, Any] = {
        "finding_id": "0123456789abcdef",
        "kind": FindingKind.MODIFIED,
        "path": "docs/a.txt",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "changes": (),
        "evidence": "sha256 differs",
        "rule": "/data",
    }
    fields.update(overrides)
    return Finding(**fields)


def report(**overrides: Any) -> Report:
    fields: dict[str, Any] = {
        "findings": (finding(),),
        "summary": ReportSummary(),
        "complete": True,
        "truncated": False,
        "baseline_created_at": WHEN,
        "baseline_sequence": 1,
        "baseline_key_id": "0123456789abcdef",
        "generated_at": WHEN,
        "tool_version": "0.1.0",
    }
    fields.update(overrides)
    return Report(**fields)
