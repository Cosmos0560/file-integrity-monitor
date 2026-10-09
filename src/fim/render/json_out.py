"""The JSON report (documented in docs/report-schema.md).

A pure function from a Report to JSON text. Every string is already escaped text; on top of that
the output is ASCII only (``ensure_ascii``), so no raw bidi or control character can appear.
Keys are in a fixed order. Numbers are integers; there are no floats.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from fim.core.models import Change, Finding, Report
from fim.core.sanitize import scrub

__all__ = ["REPORT_SCHEMA", "render_json", "report_document"]

REPORT_SCHEMA = "fim-report/1"


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _change(change: Change) -> dict[str, Any]:
    return {"field": change.field, "old": change.old, "new": change.new}


def _finding(finding: Finding) -> dict[str, Any]:
    return {
        "finding_id": finding.finding_id,
        "kind": finding.kind.value,
        "severity": finding.severity.label,
        "confidence": finding.confidence.label,
        "path": finding.path,
        "changes": [_change(change) for change in finding.changes],
        "evidence": finding.evidence,
        "rule": finding.rule,
    }


def report_document(report: Report, notes: Sequence[str] = ()) -> dict[str, Any]:
    """The report as plain data, in the shape the schema document describes."""
    summary = report.summary
    return {
        "schema": REPORT_SCHEMA,
        "tool_version": report.tool_version,
        "generated_at": _stamp(report.generated_at),
        "baseline": {
            "sequence": report.baseline_sequence,
            "created_at": _stamp(report.baseline_created_at),
            "key_id": report.baseline_key_id,
        },
        "complete": report.complete,
        "truncated": report.truncated,
        "summary": {
            "findings": sum(count for _, count in summary.by_kind),
            "by_kind": {kind.value: count for kind, count in summary.by_kind},
            "by_severity": {severity.label: count for severity, count in summary.by_severity},
            "suppressed": dict(summary.suppressed),
            "mtime_only_changes": summary.mtime_only_changes,
        },
        "findings": [_finding(finding) for finding in report.findings],
        "notes": [scrub(note) for note in notes],
    }


def render_json(report: Report, notes: Sequence[str] = ()) -> str:
    """The report as indented, ASCII-only JSON ending in a newline."""
    text = json.dumps(report_document(report, notes), indent=2, ensure_ascii=True, allow_nan=False)
    return text + "\n"
