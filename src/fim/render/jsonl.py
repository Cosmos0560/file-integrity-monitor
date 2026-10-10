"""JSON Lines events in the shape PLAN.md D12 maps onto mini-siem's generic JSON parser.

One finding is one line. The top-level keys are the ones mini-siem's parser reads (``timestamp``,
``host``, ``message``) plus ``event_type`` (``fim.<kind>``, which mini-siem keeps as
``attrs.declared_event_type`` because its vocabulary has no file events) and a ``fim`` object
that it flattens into ``fim.*`` attributes. There is never a top-level key named ``path``: that
name is an alias for ``url_path`` there. Every value is a string, a number or absent; nothing is
nested deeper than ``fim``; a line stays far below the parser's limit of 65 536 bytes and every
value below its limit of 1 024 characters, which a test holds with the worst case.

A pure function from findings to text; every string is already escaped text and is scrubbed and
clipped once more here, and the output is ASCII only (``ensure_ascii``), so a hostile file name
cannot put a raw control, bidi or lone surrogate character on a line.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from fim.core.models import Finding
from fim.core.sanitize import clip_already_escaped, scrub

__all__ = [
    "EVENT_SCHEMA",
    "MAX_MESSAGE_CHARS",
    "MAX_PATH_CHARS",
    "MAX_VALUE_CHARS",
    "EventContext",
    "event_document",
    "event_line",
    "event_lines",
    "render_jsonl",
]

EVENT_SCHEMA = "fim-event/1"
MAX_PATH_CHARS = 1000
MAX_VALUE_CHARS = 1024
MAX_MESSAGE_CHARS = 1024
_MAX_HOST_CHARS = 255  # mini-siem's limit for the host field

# change field -> (key of the old value, key of the new value) in the ``fim`` object
_CHANGE_KEYS = {
    "sha256": ("old_sha256", "new_sha256"),
    "size": ("old_size", "new_size"),
    "mode": ("old_mode", "new_mode"),
    "win_attrs": ("old_attrs", "new_attrs"),
}


@dataclass(frozen=True, slots=True)
class EventContext:
    """What a line says besides the finding: when, where, and which baseline it was made against."""

    timestamp: datetime
    host: str
    baseline_sequence: int
    tool_version: str


def _text(value: str, limit: int = MAX_VALUE_CHARS) -> str:
    return clip_already_escaped(scrub(value), limit)


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _message(finding: Finding) -> str:
    head = f"fim {finding.kind.value} [{finding.severity.label}]"
    subject = f" {finding.path}" if finding.path else ""
    detail = f": {finding.evidence}" if finding.evidence else ""
    return _text(head + subject + detail, MAX_MESSAGE_CHARS)


def event_document(finding: Finding, context: EventContext) -> dict[str, Any]:
    """One event as plain data, keys in a fixed order."""
    fim: dict[str, Any] = {
        "kind": finding.kind.value,
        "severity": finding.severity.label,
        "confidence": finding.confidence.label,
    }
    path = scrub(finding.path)
    if path:
        fim["path"] = clip_already_escaped(path, MAX_PATH_CHARS)
        fim["path_sha256"] = hashlib.sha256(path.encode("utf-8")).hexdigest()
        fim["path_truncated"] = "true" if len(path) > MAX_PATH_CHARS else "false"
    by_field = {change.field: change for change in finding.changes}
    for field, (old_key, new_key) in _CHANGE_KEYS.items():
        change = by_field.get(field)
        if change is None:
            continue
        if change.old is not None:
            fim[old_key] = _text(change.old)
        if change.new is not None:
            fim[new_key] = _text(change.new)
    if finding.evidence:
        fim["evidence"] = _text(finding.evidence)
    fim["finding_id"] = finding.finding_id
    fim["baseline_sequence"] = context.baseline_sequence
    fim["tool_version"] = _text(context.tool_version)
    fim["schema"] = EVENT_SCHEMA
    return {
        "timestamp": _stamp(context.timestamp),
        "host": _text(context.host, _MAX_HOST_CHARS),
        "message": _message(finding),
        "event_type": f"fim.{finding.kind.value}",
        "fim": fim,
    }


def event_line(finding: Finding, context: EventContext) -> str:
    """One compact, ASCII-only JSON line ending in a newline."""
    text = json.dumps(
        event_document(finding, context),
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    )
    return text + "\n"


def event_lines(findings: Iterable[Finding], context: EventContext) -> list[str]:
    """One line per finding, in the order given."""
    return [event_line(finding, context) for finding in findings]


def render_jsonl(findings: Sequence[Finding], context: EventContext) -> str:
    """All events as one text (empty when there are none)."""
    return "".join(event_lines(findings, context))
