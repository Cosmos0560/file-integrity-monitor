"""render/jsonl.py and render/csv_out.py: events for a SIEM and for spreadsheets (PLAN.md D10, D12).

The JSONL tests apply mini-siem's real flattening rules, copied here from its
``parsers/jsonlog.py`` and ``parsers/base.py`` (read on 2026-10-10): ``timestamp``, ``host`` and
``message`` are read, ``path`` is an alias for ``url_path``, nested objects are flattened with
dotted keys down to depth 3, at most 64 attributes, values over 1 024 characters are clipped
(here they must not occur at all), lines over 65 536 bytes are dead-lettered and lone surrogates
are rejected.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest

import factories as make
from conftest import REPO_ROOT
from fim.core.models import Change, Confidence, FindingKind, Severity
from fim.core.sanitize import escape
from fim.render import csv_out, jsonl
from fim.render.csv_out import COLUMNS, csv_header, render_csv
from fim.render.jsonl import EVENT_SCHEMA, EventContext, event_document, event_line, render_jsonl

CONTEXT = EventContext(
    timestamp=datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC),
    host="lab-01",
    baseline_sequence=7,
    tool_version="0.1.0",
)

MINI_SIEM_MAX_ATTRS = 64
MINI_SIEM_MAX_VALUE = 1024
MINI_SIEM_MAX_LINE_BYTES = 65_536
MINI_SIEM_MAX_DEPTH = 3
MINI_SIEM_HOST_MAX = 255


def flatten_like_mini_siem(data: dict[str, Any]) -> dict[str, str]:
    """The attrs mini-siem's JSON parser would produce for the keys it does not consume."""
    consumed = {"timestamp", "host", "message", "event_type"}
    attrs: dict[str, str] = {}

    def walk(obj: dict[str, Any], prefix: str, depth: int) -> None:
        for key, value in obj.items():
            name = f"{prefix}{key}"
            if isinstance(value, dict) and depth < MINI_SIEM_MAX_DEPTH:
                walk(value, f"{name}.", depth + 1)
            elif isinstance(value, list | dict):
                attrs[name] = json.dumps(value, separators=(",", ":"))[:1024]
            elif isinstance(value, bool):
                attrs[name] = "true" if value else "false"
            elif isinstance(value, str | int | float):
                attrs[name] = str(value)

    walk({k: v for k, v in data.items() if k not in consumed}, "", 1)
    return attrs


def full_finding(**overrides: Any) -> Any:
    fields: dict[str, Any] = {
        "finding_id": "feedfacefeedface",
        "kind": FindingKind.MODIFIED,
        "path": "/data/etc/app.conf",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "changes": (
            Change(field="sha256", old="a" * 64, new="b" * 64),
            Change(field="size", old="10", new="12"),
            Change(field="mode", old="0644 (rw-r--r--)", new="0666 (rw-rw-rw-)"),
            Change(field="win_attrs", old="ARCHIVE", new="ARCHIVE|READONLY"),
            Change(field="uid", old="0", new="1000"),
        ),
        "evidence": "content changed, 10 -> 12 bytes",
        "rule": "/data",
    }
    fields.update(overrides)
    return make.finding(**fields)


# ---- JSONL: shape -----------------------------------------------------------------------------


def test_an_event_has_the_documented_top_level_keys_in_order() -> None:
    document = event_document(full_finding(), CONTEXT)
    assert list(document) == ["timestamp", "host", "message", "event_type", "fim"]
    assert document["timestamp"] == "2026-03-04T05:06:07Z"
    assert document["host"] == "lab-01"
    assert document["event_type"] == "fim.modified"
    assert "path" not in document  # mini-siem aliases a top-level "path" to url_path


def test_the_fim_object_carries_the_documented_fields() -> None:
    fim = event_document(full_finding(), CONTEXT)["fim"]
    assert fim == {
        "kind": "modified",
        "severity": "high",
        "confidence": "high",
        "path": "/data/etc/app.conf",
        "path_sha256": hashlib.sha256(b"/data/etc/app.conf").hexdigest(),
        "path_truncated": "false",
        "old_sha256": "a" * 64,
        "new_sha256": "b" * 64,
        "old_size": "10",
        "new_size": "12",
        "old_mode": "0644 (rw-r--r--)",
        "new_mode": "0666 (rw-rw-rw-)",
        "old_attrs": "ARCHIVE",
        "new_attrs": "ARCHIVE|READONLY",
        "evidence": "content changed, 10 -> 12 bytes",
        "finding_id": "feedfacefeedface",
        "baseline_sequence": 7,
        "tool_version": "0.1.0",
        "schema": EVENT_SCHEMA,
    }


def test_a_finding_without_a_path_or_changes_has_no_empty_fields() -> None:
    drift = make.finding(
        kind=FindingKind.POLICY_DRIFT, path="", changes=(), evidence="", severity=Severity.LOW
    )
    fim = event_document(drift, CONTEXT)["fim"]
    assert "path" not in fim
    assert "path_sha256" not in fim
    assert "evidence" not in fim
    assert not any(key.startswith(("old_", "new_")) for key in fim)
    assert fim["kind"] == "policy_drift"


@pytest.mark.parametrize("kind", list(FindingKind))
def test_every_finding_kind_becomes_fim_dot_kind(kind: FindingKind) -> None:
    document = event_document(make.finding(kind=kind), CONTEXT)
    assert document["event_type"] == f"fim.{kind.value}"
    assert document["fim"]["kind"] == kind.value


def test_a_change_with_only_an_old_or_only_a_new_value_leaves_the_other_key_out() -> None:
    only_old = full_finding(changes=(Change(field="sha256", old="a" * 64, new=None),))
    only_new = full_finding(changes=(Change(field="size", old=None, new="12"),))
    fim_old = event_document(only_old, CONTEXT)["fim"]
    fim_new = event_document(only_new, CONTEXT)["fim"]
    assert fim_old["old_sha256"] == "a" * 64
    assert "new_sha256" not in fim_old
    assert fim_new["new_size"] == "12"
    assert "old_size" not in fim_new


def test_a_line_is_one_compact_ascii_json_object_ending_in_a_newline() -> None:
    line = event_line(full_finding(), CONTEXT)
    assert line.endswith("\n")
    assert line.count("\n") == 1
    assert line.isascii()
    assert ", " not in line.split('"message"')[0]  # compact separators
    assert json.loads(line)["fim"]["finding_id"] == "feedfacefeedface"


def test_render_jsonl_has_one_line_per_finding_and_is_empty_without_findings() -> None:
    items = [full_finding(finding_id=f"{n:016x}") for n in range(3)]
    lines = render_jsonl(items, CONTEXT).splitlines()
    assert [json.loads(line)["fim"]["finding_id"] for line in lines] == [
        f"{n:016x}" for n in range(3)
    ]
    assert render_jsonl([], CONTEXT) == ""


# ---- JSONL: what mini-siem would make of it -----------------------------------------------------

HOSTILE_PATHS = [
    "/data/" + escape("bad\x1b[31mred\x1b[0m\nname\u202etxt.exe"),
    "C:\\Users\\lab\\" + escape("report\u200b\ufeff.txt"),
    "/data/" + escape("\ud800lone"),
    "/data/" + "x" * 5000,
    "/data/" + "\u00e9" * 3000,
    "/data/" + escape("\U0001f600") * 800,
    "/data/" + escape("\x00" * 700),
    "",
]


@pytest.mark.parametrize("path", HOSTILE_PATHS)
def test_every_event_fits_mini_siems_limits(path: str) -> None:
    changes = tuple(
        Change(field=name, old="o" * 2000, new="n" * 2000)
        for name in ("sha256", "size", "mode", "win_attrs")
    )
    item = full_finding(path=path, changes=changes, evidence="e" * 1024)
    line = event_line(item, CONTEXT)
    assert len(line.encode("utf-8")) < MINI_SIEM_MAX_LINE_BYTES
    data = json.loads(line)
    assert set(data) == {"timestamp", "host", "message", "event_type", "fim"}
    assert "path" not in data
    attrs = flatten_like_mini_siem(data)
    assert len(attrs) <= 32  # D12: well under mini-siem's 64
    assert len(attrs) < MINI_SIEM_MAX_ATTRS
    assert all(key.startswith("fim.") for key in attrs)
    assert all(len(key) <= 64 for key in attrs)
    assert all(len(value) <= MINI_SIEM_MAX_VALUE for value in attrs.values())
    assert len(data["message"]) <= jsonl.MAX_MESSAGE_CHARS
    assert len(data["host"]) <= MINI_SIEM_HOST_MAX
    for text in [data["message"], *attrs.values()]:
        text.encode("utf-8")  # no lone surrogate survives (raises otherwise)
        assert "\n" not in text
        assert not any(ord(char) < 0x20 or 0x7F <= ord(char) < 0xA0 for char in text)


def test_a_long_path_is_cut_with_the_hash_of_the_whole_path_and_a_flag() -> None:
    path = "/data/" + "a" * 3000
    fim = event_document(full_finding(path=path), CONTEXT)["fim"]
    assert len(fim["path"]) <= jsonl.MAX_PATH_CHARS
    assert fim["path"].endswith("...")
    assert fim["path_truncated"] == "true"
    assert fim["path_sha256"] == hashlib.sha256(path.encode("utf-8")).hexdigest()


def test_a_cut_never_ends_inside_an_escape_sequence() -> None:
    for length in range(990, 1010):
        path = "a" * length + escape("\u202e") * 6
        shown = event_document(full_finding(path=path), CONTEXT)["fim"]["path"]
        body = shown[:-3] if shown.endswith("...") else shown
        assert not body.endswith(("\\u20", "\\u2", "\\u", "\\"))


def test_a_hostile_name_is_one_line_with_no_raw_control_or_bidi_character() -> None:
    hostile = full_finding(
        path="/data/" + escape("a\nb\r\x1b[2J\u202e"), evidence=escape("x\ny\u2028z")
    )
    line = event_line(hostile, CONTEXT)
    assert line.count("\n") == 1
    assert line.isascii()
    decoded = json.loads(line)
    assert "\u202e" not in decoded["fim"]["path"]
    assert "\n" not in decoded["message"]
    assert "\\x0a" in decoded["fim"]["path"]


def test_a_hostile_host_label_and_tool_version_are_scrubbed() -> None:
    context = replace(CONTEXT, host="lab\n01\u202e", tool_version="1.0\x1b[0m")
    line = event_line(full_finding(), context)
    data = json.loads(line)
    assert "\n" not in data["host"]
    assert "\u202e" not in data["host"]
    assert "\x1b" not in data["fim"]["tool_version"]
    assert len(line.splitlines()) == 1


def test_the_host_is_cut_to_mini_siems_limit() -> None:
    data = json.loads(event_line(full_finding(), replace(CONTEXT, host="h" * 1000)))
    assert len(data["host"]) == MINI_SIEM_HOST_MAX


def test_the_same_finding_gives_the_same_line() -> None:
    assert event_line(full_finding(), CONTEXT) == event_line(full_finding(), CONTEXT)


def test_the_message_names_kind_severity_path_and_evidence() -> None:
    message = event_document(full_finding(), CONTEXT)["message"]
    assert message == ("fim modified [high] /data/etc/app.conf: content changed, 10 -> 12 bytes")


# ---- CSV ---------------------------------------------------------------------------------------


def parse(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text, newline="")))


def test_the_header_is_the_documented_column_list() -> None:
    assert parse(csv_header()) == [list(COLUMNS)]
    assert COLUMNS[:6] == ("timestamp", "host", "kind", "severity", "confidence", "path")


def test_a_row_has_one_cell_per_column_and_the_finding_values() -> None:
    rows = parse(render_csv([full_finding()], CONTEXT))
    assert len(rows) == 2
    row = dict(zip(COLUMNS, rows[1], strict=True))
    assert row["timestamp"] == "2026-03-04T05:06:07Z"
    assert row["host"] == "lab-01"
    assert row["kind"] == "modified"
    assert row["path"] == "/data/etc/app.conf"
    assert row["old_sha256"] == "a" * 64
    assert row["new_size"] == "12"
    assert row["baseline_sequence"] == "7"
    assert row["finding_id"] == "feedfacefeedface"


def test_the_header_can_be_left_out_for_an_append_log() -> None:
    text = render_csv([full_finding()], CONTEXT, header=False)
    assert len(parse(text)) == 1
    assert render_csv([], CONTEXT, header=False) == ""
    assert render_csv([], CONTEXT) == csv_header()


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@"])
def test_a_cell_that_could_be_a_formula_is_neutralised(prefix: str) -> None:
    item = full_finding(path=prefix + "cmd|' /C calc'!A0", evidence=prefix + "1+1")
    row = dict(zip(COLUMNS, parse(render_csv([item], CONTEXT))[1], strict=True))
    assert row["path"].startswith("'" + prefix)
    assert row["evidence"].startswith("'" + prefix)


def test_a_raw_tab_or_carriage_return_is_escaped_before_it_could_start_a_cell() -> None:
    """The models refuse raw controls; the cell function does not depend on that."""
    assert csv_out._cell("\t=1") == '"\\x09=1"'
    assert csv_out._cell("\r=1") == '"\\x0d=1"'
    assert csv_out._cell("=1") == '"\'=1"'


def test_quotes_and_commas_are_quoted_and_newlines_are_escaped() -> None:
    item = full_finding(
        path='/data/he said "hi", then\\left' + escape("\nsecond\r\nthird"),
        evidence='a,b "c"',
    )
    text = render_csv([item], CONTEXT)
    assert text.count("\n") == 2  # the header row and one row: no cell holds a raw newline
    assert "\r" not in text
    rows = parse(text)
    assert len(rows) == 2
    row = dict(zip(COLUMNS, rows[1], strict=True))
    assert row["evidence"] == 'a,b "c"'
    assert '"hi", then' in row["path"]
    assert "\\x0a" in row["path"]


def test_every_csv_cell_is_quoted() -> None:
    line = render_csv([full_finding()], CONTEXT).splitlines()[1]
    assert line.startswith('"')
    assert line.endswith('"')
    assert '","' in line


def test_csv_is_ascii_safe_for_hostile_names() -> None:
    item = full_finding(path="/data/" + escape("\x1b[31m\u202e\u200b\ud800"))
    text = render_csv([item], CONTEXT)
    assert not any(ord(char) < 0x20 and char != "\n" for char in text)
    assert "\u202e" not in text
    assert "\x1b" not in text


def test_the_csv_module_exports() -> None:
    assert set(csv_out.__all__) == {"COLUMNS", "csv_header", "csv_rows", "render_csv"}


# ---- the document and the code say the same ------------------------------------------------------

SIEM_DOC = REPO_ROOT / "docs" / "siem-mapping.md"


def doc_fields(title: str) -> list[str]:
    text = SIEM_DOC.read_text(encoding="utf-8")
    sections = re.split(r"^## ", text, flags=re.MULTILINE)
    body = next(body for body in sections[1:] if body.startswith(title))
    return re.findall(r"^\| `([a-z_0-9]+)` \|", body, flags=re.MULTILINE)


def test_the_document_lists_exactly_the_fields_the_code_writes() -> None:
    document = event_document(full_finding(), CONTEXT)
    assert doc_fields("Top level") == list(document)
    assert doc_fields("`fim`") == list(document["fim"])
    assert EVENT_SCHEMA == "fim-event/1"
    assert "`fim-event/1`" in SIEM_DOC.read_text(encoding="utf-8")


def test_the_document_lists_exactly_the_csv_columns() -> None:
    assert doc_fields("CSV") == list(COLUMNS)


def test_the_document_names_every_finding_kind() -> None:
    text = SIEM_DOC.read_text(encoding="utf-8")
    kinds = text.split("## Kinds", 1)[1].split("##", 1)[0]
    for kind in FindingKind:
        assert f"`{kind.value}`" in kinds, kind.value


def test_the_limits_the_document_states_are_the_ones_in_the_code() -> None:
    text = SIEM_DOC.read_text(encoding="utf-8")
    assert f"at most {jsonl.MAX_PATH_CHARS:,} characters".replace(",", " ") in text
    assert f"{jsonl.MAX_MESSAGE_CHARS:,}".replace(",", " ") in text
    assert str(MINI_SIEM_HOST_MAX) in text
    assert "65 536" in text


def test_the_example_line_in_the_document_is_valid_and_has_the_documented_shape() -> None:
    text = SIEM_DOC.read_text(encoding="utf-8")
    block = text.split("```json\n", 1)[1].split("\n```", 1)[0]
    data = json.loads(block)
    assert list(data) == list(event_document(full_finding(), CONTEXT))
    assert next(iter(data["fim"])) == "kind"
    assert data["fim"]["schema"] == EVENT_SCHEMA
    assert block.isascii()
