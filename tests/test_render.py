"""render/table.py and render/json_out.py: pure renderers for a Report (PLAN.md D10, section 2)."""

from __future__ import annotations

import json
import re
from dataclasses import replace
from typing import Any

import pytest

import factories as make
from conftest import REPO_ROOT
from fim.core.diff import DiffResult, build_report
from fim.core.limits import MAX_FINDINGS_REPORTED
from fim.core.models import (
    Change,
    Confidence,
    Finding,
    FindingKind,
    Report,
    ReportSummary,
    Severity,
)
from fim.render.json_out import REPORT_SCHEMA, render_json, report_document
from fim.render.table import render_table

SCHEMA_DOC = REPO_ROOT / "docs" / "report-schema.md"


def finding(**overrides: Any) -> Finding:
    return make.finding(**overrides)


def report_with(findings: list[Finding], **overrides: Any) -> Report:
    fields: dict[str, Any] = {
        "header": make.header(),
        "key_id": "0123456789abcdef",
        "generated_at": make.WHEN,
        "tool_version": "0.1.0",
        "complete": True,
    }
    fields.update(overrides)
    return build_report(DiffResult(tuple(findings), 0, ()), **fields)


# ---- the table -----------------------------------------------------------------------------------


def test_an_empty_report_says_no_changes_found() -> None:
    text = render_table(report_with([]))
    assert "no changes found" in text
    assert "0 findings" in text
    assert "complete: yes" in text
    assert text.endswith("\n")


def test_the_table_shows_header_columns_findings_and_evidence() -> None:
    items = [
        finding(finding_id="1" * 16, path="/data/a.txt", severity=Severity.HIGH, evidence="why a"),
        finding(
            finding_id="2" * 16,
            path="/data/b.txt",
            kind=FindingKind.CREATED,
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            evidence="new file",
        ),
    ]
    lines = render_table(report_with(items)).splitlines()
    assert lines[0].startswith("fim check: baseline sequence 1 made 2026-01-01T12:00:00Z")
    assert "key id 0123456789abcdef" in lines[0]
    header = next(line for line in lines if line.startswith("SEVERITY"))
    assert header.split() == ["SEVERITY", "CONFIDENCE", "KIND", "PATH"]
    row = next(line for line in lines if "/data/a.txt" in line)
    assert row.split() == ["high", "high", "modified", "/data/a.txt"]
    evidence_row = lines[lines.index(row) + 1]
    assert evidence_row.strip() == "why a"
    # the evidence lines up under the PATH column
    assert evidence_row.index("why a") == row.index("/data/a.txt")
    assert "2 findings (high 1, low 1)" in lines
    assert "by kind: created 1, modified 1" in lines


def test_the_most_severe_finding_comes_first() -> None:
    items = [
        finding(finding_id="1" * 16, path="/low", severity=Severity.LOW),
        finding(finding_id="2" * 16, path="/crit", severity=Severity.CRITICAL),
    ]
    text = render_table(report_with(items))
    assert text.index("/crit") < text.index("/low")


def test_one_finding_is_singular() -> None:
    assert "1 finding (" in render_table(report_with([finding()]))


def test_an_incomplete_run_is_flagged() -> None:
    text = render_table(report_with([], complete=False))
    assert "complete: NO" in text
    assert "may miss changes" in text


def test_notes_and_suppressed_counts_and_mtime_only_are_shown() -> None:
    diff = DiffResult((), 3, (("deleted files under an unavailable monitored path", 2),))
    report = build_report(
        diff,
        header=make.header(),
        key_id="0123456789abcdef",
        generated_at=make.WHEN,
        tool_version="0.1.0",
        complete=True,
    )
    text = render_table(report, notes=["no rollback anchor found"])
    assert "not reported: 3 files changed only in modification time" in text
    assert "suppressed: deleted files under an unavailable monitored path: 2" in text
    assert "note: no rollback anchor found" in text


def test_a_cut_list_says_how_many_are_shown_and_the_counts_stay_exact() -> None:
    items = [finding(finding_id=f"{n:016x}", path=f"/p{n:03d}") for n in range(12)]
    text = render_table(report_with(items, max_findings=5))
    assert "12 findings" in text
    assert "showing the first 5 of 12 findings" in text
    assert str(MAX_FINDINGS_REPORTED) in text
    assert text.count("/p0") == 5


def test_everything_hidden_by_min_severity_is_not_called_no_changes() -> None:
    report = report_with([finding(severity=Severity.LOW)], min_severity=Severity.HIGH)
    text = render_table(report)
    assert "no changes found" in text  # nothing at or above the minimum
    assert "suppressed: findings below the minimum severity: 1" in text


def test_a_windows_path_never_shows_doubled_backslashes() -> None:
    """PLAN.md D10 amendment: components are escaped one by one, separators are not doubled."""
    windows_path = "C:\\Users\\lab\\Documents\\report final.txt"
    text = render_table(report_with([finding(path=windows_path, evidence="sha256 differs")]))
    assert windows_path in text
    assert "\\\\" not in text


def test_a_hostile_name_cannot_reach_the_terminal_through_the_table() -> None:
    from fim.core.sanitize import escape

    hostile = "dir\x1b[31m/line\nbreak\u202egnp.txt\u200b"
    shown = "/data/" + escape(hostile)
    text = render_table(report_with([finding(path=shown, evidence="e" + escape("\x1b[2J"))]))
    for bad in ("\x1b", "\u202e", "\u200b", "\r"):
        assert bad not in text
    assert text.count("\n") == len(text.splitlines())
    assert "\\x1b" in text


def test_the_table_scrubs_even_text_the_caller_forgot_to_escape() -> None:
    notes = ["warning with \x1b[31m escape and \u202e bidi"]
    text = render_table(report_with([]), notes=notes)
    assert "\x1b" not in text
    assert "\u202e" not in text


def test_the_table_is_deterministic() -> None:
    items = [finding(finding_id=f"{n:016x}", path=f"/p{n}") for n in range(5)]
    assert render_table(report_with(items)) == render_table(report_with(list(reversed(items))))


# ---- the JSON report -----------------------------------------------------------------------------


def sample_report() -> Report:
    items = [
        finding(
            finding_id="a" * 16,
            kind=FindingKind.PERMISSION_CHANGED,
            severity=Severity.HIGH,
            changes=(Change(field="mode", old="0644", new="0666"),),
            path="/data/x\\u00e9",
            evidence="mode 0644 -> 0666; more dangerous than before",
        ),
        finding(finding_id="b" * 16, kind=FindingKind.CREATED, severity=Severity.LOW, changes=()),
    ]
    return report_with(items, complete=False)


def test_the_json_is_valid_ascii_json_with_a_trailing_newline() -> None:
    text = render_json(sample_report(), notes=["a note"])
    assert text.endswith("\n")
    text.encode("ascii")
    assert json.loads(text)["schema"] == REPORT_SCHEMA == "fim-report/1"


def test_the_json_document_has_the_documented_shape() -> None:
    document = report_document(sample_report(), notes=["a note"])
    assert list(document) == [
        "schema",
        "tool_version",
        "generated_at",
        "baseline",
        "complete",
        "truncated",
        "summary",
        "findings",
        "notes",
    ]
    assert document["generated_at"] == "2026-01-01T12:00:00Z"
    assert document["baseline"] == {
        "sequence": 1,
        "created_at": "2026-01-01T12:00:00Z",
        "key_id": "0123456789abcdef",
    }
    assert document["complete"] is False
    assert document["truncated"] is False
    assert document["summary"] == {
        "findings": 2,
        "by_kind": {"created": 1, "permission_changed": 1},
        "by_severity": {"high": 1, "low": 1},
        "suppressed": {},
        "mtime_only_changes": 0,
    }
    first = document["findings"][0]
    assert list(first) == [
        "finding_id",
        "kind",
        "severity",
        "confidence",
        "path",
        "changes",
        "evidence",
        "rule",
    ]
    assert first["changes"] == [{"field": "mode", "old": "0644", "new": "0666"}]
    assert document["notes"] == ["a note"]


def test_a_change_without_a_side_is_null() -> None:
    created = finding(changes=(Change(field="type", old=None, new="file"),))
    document = report_document(report_with([created]))
    assert document["findings"][0]["changes"] == [{"field": "type", "old": None, "new": "file"}]


def test_non_ascii_letters_are_written_as_escapes() -> None:
    text = render_json(report_with([finding(path="/data/\u0416\u0443\u043a")]))
    text.encode("ascii")
    assert "\\u0416" in text
    assert json.loads(text)["findings"][0]["path"] == "/data/\u0416\u0443\u043a"


def test_hostile_text_is_escaped_in_the_json_too() -> None:
    from fim.core.sanitize import escape

    shown = "/data/" + escape("a\x1b[31m\u202eb\nc")
    text = render_json(report_with([finding(path=shown)]), notes=["n\x1b[0m"])
    assert "\x1b" not in text
    assert "\u202e" not in text
    parsed = json.loads(text)
    assert "\x1b" not in parsed["findings"][0]["path"]
    assert "\x1b" not in parsed["notes"][0]


def test_truncated_reports_keep_exact_counts_in_the_json() -> None:
    items = [finding(finding_id=f"{n:016x}", path=f"/p{n:03d}") for n in range(30)]
    document = report_document(report_with(items, max_findings=7))
    assert document["truncated"] is True
    assert len(document["findings"]) == 7
    assert document["summary"]["findings"] == 30
    assert document["summary"]["by_kind"] == {"modified": 30}


def test_the_json_is_deterministic() -> None:
    items = [finding(finding_id=f"{n:016x}", path=f"/p{n}") for n in range(4)]
    assert render_json(report_with(items)) == render_json(report_with(list(reversed(items))))


# ---- validation against the documented schema (hand-written, no new dependency) ------------------

HEX16 = re.compile(r"[0-9a-f]{16}")
STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
KINDS = {kind.value for kind in FindingKind} - {"baseline_integrity", "resolved"}
SEVERITIES = {severity.label for severity in Severity}
CONFIDENCES = {confidence.label for confidence in Confidence}


def check_schema(document: Any) -> None:
    """Raise AssertionError unless ``document`` is a valid fim-report/1."""
    assert isinstance(document, dict)
    assert set(document) == {
        "schema",
        "tool_version",
        "generated_at",
        "baseline",
        "complete",
        "truncated",
        "summary",
        "findings",
        "notes",
    }
    assert document["schema"] == "fim-report/1"
    assert isinstance(document["tool_version"], str)
    assert STAMP.fullmatch(document["generated_at"])
    baseline = document["baseline"]
    assert set(baseline) == {"sequence", "created_at", "key_id"}
    assert type(baseline["sequence"]) is int
    assert STAMP.fullmatch(baseline["created_at"])
    assert HEX16.fullmatch(baseline["key_id"])
    assert type(document["complete"]) is bool
    assert type(document["truncated"]) is bool
    summary = document["summary"]
    assert set(summary) == {
        "findings",
        "by_kind",
        "by_severity",
        "suppressed",
        "mtime_only_changes",
    }
    assert type(summary["findings"]) is int
    assert type(summary["mtime_only_changes"]) is int
    assert set(summary["by_kind"]) <= KINDS
    assert set(summary["by_severity"]) <= SEVERITIES
    for counts in (summary["by_kind"], summary["by_severity"], summary["suppressed"]):
        assert all(type(value) is int and value > 0 for value in counts.values())
    assert sum(summary["by_kind"].values()) == summary["findings"]
    assert sum(summary["by_severity"].values()) == summary["findings"]
    assert isinstance(document["findings"], list)
    assert len(document["findings"]) <= summary["findings"]
    for item in document["findings"]:
        assert set(item) == {
            "finding_id",
            "kind",
            "severity",
            "confidence",
            "path",
            "changes",
            "evidence",
            "rule",
        }
        assert HEX16.fullmatch(item["finding_id"])
        assert item["kind"] in KINDS
        assert item["severity"] in SEVERITIES
        assert item["confidence"] in CONFIDENCES
        assert isinstance(item["path"], str)
        assert isinstance(item["evidence"], str)
        assert len(item["evidence"]) <= 1024
        assert isinstance(item["rule"], str)
        for change in item["changes"]:
            assert set(change) == {"field", "old", "new"}
            assert isinstance(change["field"], str)
            assert all(
                change[side] is None or isinstance(change[side], str) for side in ("old", "new")
            )
    assert isinstance(document["notes"], list)
    assert all(isinstance(note, str) for note in document["notes"])


def test_real_output_validates_against_the_schema() -> None:
    check_schema(json.loads(render_json(sample_report(), notes=["x"])))
    check_schema(json.loads(render_json(report_with([]))))
    many = [finding(finding_id=f"{n:016x}", path=f"/p{n}") for n in range(9)]
    check_schema(json.loads(render_json(report_with(many, max_findings=3))))


@pytest.mark.parametrize(
    "damage",
    [
        lambda d: d.update(schema="fim-report/2"),
        lambda d: d.pop("notes"),
        lambda d: d.update(extra=1),
        lambda d: d["baseline"].update(key_id="XYZ"),
        lambda d: d["summary"].update(findings=99),
        lambda d: d["findings"][0].update(severity="urgent"),
        lambda d: d["findings"][0].update(kind="exploded"),
        lambda d: d["findings"][0].pop("rule"),
        lambda d: d["findings"][0]["changes"][0].update(old=5),
        lambda d: d.update(complete="yes"),
    ],
)
def test_the_schema_check_itself_catches_damage(damage: Any) -> None:
    document = json.loads(render_json(sample_report()))
    damage(document)
    with pytest.raises(AssertionError):
        check_schema(document)


def test_the_schema_document_lists_exactly_the_fields_the_code_writes() -> None:
    text = SCHEMA_DOC.read_text(encoding="utf-8")
    sections = re.split(r"^## ", text, flags=re.MULTILINE)
    named = {section.split("\n", 1)[0]: section for section in sections[1:]}

    def fields_of(title: str) -> list[str]:
        body = next(body for name, body in named.items() if name.startswith(title))
        return re.findall(r"^\| `([a-z_]+)` \|", body, flags=re.MULTILINE)

    document = json.loads(render_json(sample_report()))
    assert fields_of("Top level") == list(document)
    assert fields_of("`baseline`") == list(document["baseline"])
    assert fields_of("`summary`") == list(document["summary"])
    assert fields_of("Each element") == list(document["findings"][0])
    assert "fim-report/1" in text
    for kind in sorted(KINDS):
        assert f"`{kind}`" in text, kind
    for label in SEVERITIES | CONFIDENCES:
        assert f"`{label}`" in text, label


def test_the_schema_document_states_the_exit_codes() -> None:
    from fim.core.errors import ExitCode

    text = SCHEMA_DOC.read_text(encoding="utf-8")
    section = text.split("## Exit codes", 1)[1]
    for code in ExitCode:
        assert f"`{int(code)}`" in section


def test_a_report_with_no_summary_counts_is_still_valid() -> None:
    empty = replace(report_with([]), summary=ReportSummary())
    check_schema(json.loads(render_json(empty)))


def test_a_finding_without_evidence_has_just_its_row() -> None:
    lines = render_table(report_with([finding(evidence="", path="/data/a")])).splitlines()
    row = next(index for index, line in enumerate(lines) if "/data/a" in line)
    assert lines[row + 1] == ""
