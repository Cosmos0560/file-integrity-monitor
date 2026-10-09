"""The human-readable table (PLAN.md D10): one block per finding, then the summary.

A pure function from a Report to text. The finding fields are already escaped text (a hostile
file name cannot carry a terminal escape, a newline or a bidi control into this output), and
every line is scrubbed once more here, so the guarantee does not depend on the caller. Windows
paths keep their single backslashes: the escaping is done per path component, not over the
whole path.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from fim.core.limits import MAX_FINDINGS_REPORTED
from fim.core.models import Report
from fim.core.sanitize import scrub

__all__ = ["render_table"]

_HEADINGS = ("SEVERITY", "CONFIDENCE", "KIND", "PATH")
_INDENT = "  "


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _counts(pairs: Sequence[tuple[str, int]]) -> str:
    return ", ".join(f"{label} {count}" for label, count in pairs)


def render_table(report: Report, notes: Sequence[str] = ()) -> str:
    """The report as plain text ending in a newline. ``notes`` are warnings for the reader."""
    lines = [
        f"fim check: baseline sequence {report.baseline_sequence} made "
        f"{_stamp(report.baseline_created_at)} (key id {report.baseline_key_id})",
        f"checked {_stamp(report.generated_at)} with fim {report.tool_version}",
        "",
    ]
    total = sum(count for _, count in report.summary.by_kind)
    if report.findings:
        rows = [
            (finding.severity.label, finding.confidence.label, finding.kind.value, finding.path)
            for finding in report.findings
        ]
        widths = [
            max(len(heading), *(len(row[column]) for row in rows))
            for column, heading in enumerate(_HEADINGS[:3])
        ]
        header = _INDENT.join(
            heading.ljust(width) for heading, width in zip(_HEADINGS, [*widths, 0], strict=True)
        )
        lines.append(header.rstrip())
        for row, finding in zip(rows, report.findings, strict=True):
            cells = [cell.ljust(width) for cell, width in zip(row[:3], widths, strict=True)]
            lines.append(_INDENT.join([*cells, row[3]]))
            if finding.evidence:
                lines.append(" " * (sum(widths) + 3 * len(_INDENT)) + finding.evidence)
        lines.append("")
    else:
        lines.append("no changes found" if total == 0 else "no findings to show")
        lines.append("")
    severities = [(severity.label, count) for severity, count in report.summary.by_severity]
    kinds = [(kind.value, count) for kind, count in report.summary.by_kind]
    noun = "finding" if total == 1 else "findings"
    lines.append(f"{total} {noun}" + (f" ({_counts(severities)})" if severities else ""))
    if kinds:
        lines.append(f"by kind: {_counts(kinds)}")
    if report.truncated:
        lines.append(
            f"showing the first {len(report.findings)} of {total} findings "
            f"(at most {MAX_FINDINGS_REPORTED} are listed; the counts above are exact)"
        )
    if report.summary.mtime_only_changes:
        lines.append(
            f"not reported: {report.summary.mtime_only_changes} files changed only in "
            "modification time (same content)"
        )
    lines.extend(f"suppressed: {label}: {count}" for label, count in report.summary.suppressed)
    lines.append(f"complete: {'yes' if report.complete else 'NO (the result may miss changes)'}")
    lines.extend(f"note: {note}" for note in notes)
    return "\n".join(scrub(line) for line in lines) + "\n"
