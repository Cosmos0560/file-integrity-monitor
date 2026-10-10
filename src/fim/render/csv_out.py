"""CSV events: the same facts as the JSONL lines, one row per finding.

CSV is the lossy format (PLAN.md D10): every cell is escaped text, so a newline, a carriage
return, a tab or any other control character is already the visible two-to-ten character escape
and no cell can break a row; every cell is quoted (RFC 4180, a quote inside a cell doubled); and
a cell a spreadsheet would read as a formula (it starts with ``=``, ``+``, ``-`` or ``@``) gets a
leading ``'`` (CWE-1236). Rows end in a single ``\\n``.

A pure function from findings to text; ``render_csv`` writes the header only when asked, so a
long-running ``watch`` writes it once.
"""

from __future__ import annotations

from collections.abc import Sequence

from fim.core.models import Finding
from fim.core.sanitize import clip_already_escaped, csv_neutralize, scrub
from fim.render.jsonl import MAX_VALUE_CHARS, EventContext, event_document

__all__ = ["COLUMNS", "csv_header", "csv_rows", "render_csv"]

COLUMNS = (
    "timestamp",
    "host",
    "kind",
    "severity",
    "confidence",
    "path",
    "evidence",
    "finding_id",
    "old_sha256",
    "new_sha256",
    "old_size",
    "new_size",
    "old_mode",
    "new_mode",
    "old_attrs",
    "new_attrs",
    "baseline_sequence",
    "tool_version",
)

# columns that come from the event's ``fim`` object (the others are top-level)
_TOP_LEVEL = frozenset({"timestamp", "host"})


def _cell(value: object) -> str:
    text = "" if value is None else str(value)
    text = csv_neutralize(clip_already_escaped(scrub(text), MAX_VALUE_CHARS))
    return '"' + text.replace('"', '""') + '"'


def csv_header() -> str:
    """The header row, quoted like every other row."""
    return ",".join(_cell(name) for name in COLUMNS) + "\n"


def _row(finding: Finding, context: EventContext) -> str:
    document = event_document(finding, context)
    fim = document["fim"]
    cells = [document[name] if name in _TOP_LEVEL else fim.get(name, "") for name in COLUMNS]
    return ",".join(_cell(cell) for cell in cells) + "\n"


def csv_rows(findings: Sequence[Finding], context: EventContext) -> list[str]:
    """One row per finding, without the header."""
    return [_row(finding, context) for finding in findings]


def render_csv(findings: Sequence[Finding], context: EventContext, *, header: bool = True) -> str:
    """The rows as one text, preceded by the header row unless ``header`` is false."""
    return (csv_header() if header else "") + "".join(csv_rows(findings, context))
