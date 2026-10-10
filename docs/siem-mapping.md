# SIEM mapping: JSONL events and CSV rows (`fim-event/1`)

`fim check --format jsonl`, `fim watch` (default) and `--output FILE` produce one JSON object per
line, one line per finding, in the shape below. The shape is built to fit the generic JSON parser
of mini-siem (the sibling project in this portfolio) **without changing mini-siem**: PLAN.md D12,
option (a). The output is ASCII only (every non-ASCII character is a `\uXXXX` escape) and every
string from the filesystem is escaped text, so a hostile file name cannot put a control, bidi or
lone-surrogate character on a line. A test (`tests/test_render_events.py`) checks real output
against this document field by field and against mini-siem's flattening limits.

## One line

A real line, written by `fim check --format jsonl` on 2026-10-10 with `fim` 1.0.0 on Windows
(the temporary directory is shown as `<TMP>`; `path_sha256` is the hash of the real path text, so
it does not match the redacted `path`):

```json
{"timestamp":"2026-10-10T18:55:07Z","host":"lab-01","message":"fim modified [high] <TMP>\\lab\\etc\\app.conf: sha256 differs (e049009aabc94ce6... -> 58749731276250c5...); size 34 -> 41","event_type":"fim.modified","fim":{"kind":"modified","severity":"high","confidence":"high","path":"<TMP>\\lab\\etc\\app.conf","path_sha256":"db3efb1acda682df6923218da2897cc32a17b82405b4a5f48f7e4b0121eef214","path_truncated":"false","old_sha256":"e049009aabc94ce6cffdf75adff1fbeeaf79408a52a73c684d7a7170454c27a9","new_sha256":"58749731276250c50c6eb683eddd729318f64b46a52f1c6216dcaf0633f9eb51","old_size":"34","new_size":"41","evidence":"sha256 differs (e049009aabc94ce6... -> 58749731276250c5...); size 34 -> 41","finding_id":"83a082ae5632e841","baseline_sequence":1,"tool_version":"1.0.0","schema":"fim-event/1"}}
```

## Top level

| Field | Type | Meaning |
|---|---|---|
| `timestamp` | string | UTC time of the scan that produced the event, `YYYY-MM-DDTHH:MM:SSZ`. |
| `host` | string | The host label stored in the baseline (at most 255 characters, mini-siem's limit). |
| `message` | string | One-line summary `fim <kind> [<severity>] <path>: <evidence>`, at most 1 024 characters. |
| `event_type` | string | `fim.<kind>`. mini-siem's own vocabulary has no file events, so it keeps this in `attrs.declared_event_type` and files the event as `json_event`. |
| `fim` | object | The event's own fields (below). mini-siem flattens it into `fim.*` attributes. |

There is never a top-level key named `path`: mini-siem treats that name as an alias for `url_path`,
which would turn a file path into a URL path in its web-oriented views.

## `fim`

Every value is a string or an integer. A key that does not apply is absent, not empty. At most 19
keys, far below mini-siem's 64-attribute limit.

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | The finding kind, see below. |
| `severity` | string | `info`, `low`, `medium`, `high` or `critical`: how much the change matters (PLAN.md D8). |
| `confidence` | string | `low`, `medium` or `high`: how sure the observation is. |
| `path` | string | The path as shown to a person (escaped text), at most 1 000 characters. Absent for findings that name no path (`policy_drift`, `baseline_integrity`). |
| `path_sha256` | string | SHA-256 of the full escaped path text, always the whole path even when `path` was cut, for correlation. |
| `path_truncated` | string | `"true"` if `path` was cut (it then ends in `...`), else `"false"`. |
| `old_sha256` | string | Content hash in the baseline, when the content changed. |
| `new_sha256` | string | Content hash now, when the content changed. |
| `old_size` | string | Size in bytes in the baseline, when the size changed. |
| `new_size` | string | Size in bytes now, when the size changed. |
| `old_mode` | string | POSIX permission bits in the baseline, when they changed. |
| `new_mode` | string | POSIX permission bits now, when they changed. |
| `old_attrs` | string | Windows attribute flags in the baseline, when they changed. |
| `new_attrs` | string | Windows attribute flags now, when they changed. |
| `evidence` | string | One-line explanation, at most 1 024 characters. |
| `finding_id` | string | 16 hex characters, stable while the facts behind the finding are. `watch` uses it to report only new findings and to pair a `resolved` event with its original. |
| `baseline_sequence` | integer | Sequence number of the baseline the event was made against. |
| `tool_version` | string | The `fim` version. |
| `schema` | string | Always `"fim-event/1"`. |

## Kinds

`created`, `modified`, `deleted`, `permission_changed`, `type_changed`, `links_changed`,
`unreadable`, `unstable`, `vanished`, `root_unavailable`, `policy_drift`, `baseline_integrity`
(`watch` only, always `critical`: the baseline file stopped verifying) and `resolved` (`watch`
only, `info`: an earlier finding is no longer reported, same `finding_id` and `path`).

## What mini-siem does with a line

Read from mini-siem's `parsers/jsonlog.py` and `parsers/base.py` on 2026-10-10 (the parser is
re-read whenever this document changes):

- `timestamp`, `host` and `message` fill the typed fields; `event_type` is not in its closed
  vocabulary, so the event becomes `json_event` with `attrs.declared_event_type = "fim.<kind>"`.
- Every other key is flattened into `attrs` with dotted names to a depth of 3, at most 64
  attributes, keys up to 64 characters, values up to 1 024 characters (longer values are clipped
  and the clipped field is named in `attrs.truncated_fields`; `fim` never produces one). Lines
  over 65 536 bytes are dead-lettered; lone surrogates are rejected.
- Searches use the flattened names, for example `declared_event_type:fim.modified`.

## A real ingest

A demo tree was changed (a modified, a deleted, a permission-changed and two created files, one of
them with a right-to-left override and a zero-width space in its name) and `fim watch --max-cycles
2 --output events.jsonl` wrote 5 events. This was done once, by hand, on 2026-10-10, with `fim`
0.1.0 (the Phase 5 build, hence `tool_version` below); the event shape has not changed since and
a test pins it, but the ingest itself was not repeated for 1.0.0. mini-siem's own `ingest`
command was run from its own virtual environment with its data directory in a temporary folder
outside both repositories:

```
$ mini-siem ingest --data-dir <temp>/siem-work/data --format json <temp>/siem-demo/out/events.jsonl
<temp>/siem-demo/out/events.jsonl: format json, 5 line(s), 5 record(s), 0 blank, 0 over-long
events: 5 parsed, 5 newly stored, 0 already stored
parse failures: 0 (dead-letter file: <temp>/siem-work/data/deadletter.jsonl), over-long lines: 0
alerts: 0 stored (0 allowlisted), 0 duplicate(s) suppressed by cooldown
```

and `mini-siem search --json` on that database returned:

```
json_event  json  host=lab-01 url_path=None  attrs=12 declared_event_type=fim.deleted fim.kind=deleted
json_event  json  host=lab-01 url_path=None  attrs=14 declared_event_type=fim.permission_changed fim.kind=permission_changed
json_event  json  host=lab-01 url_path=None  attrs=12 declared_event_type=fim.created fim.kind=created
json_event  json  host=lab-01 url_path=None  attrs=16 declared_event_type=fim.modified fim.kind=modified
json_event  json  host=lab-01 url_path=None  attrs=12 declared_event_type=fim.created fim.kind=created
```

Attributes of the `modified` event as stored (paths and long hashes shortened for this page):

```
declared_event_type      fim.modified
fim.baseline_sequence    1
fim.confidence           high
fim.evidence             sha256 differs (9b4d77c32e09ff07... -> 3360c8...
fim.finding_id           6e5af281570dbf03
fim.kind                 modified
fim.new_sha256           3360c8b1013339284d77e64cccdc0724b2731427b1cef...
fim.new_size             31
fim.old_sha256           9b4d77c32e09ff079e9a6a7056ae2850da8b5bdb01f20...
fim.old_size             18
fim.path                 <TMP>\siem-demo\watched\etc\app.conf
fim.path_sha256          3c5531014a43a667e754c71afae01f0b6f6a7d95547cd...
fim.path_truncated       false
fim.schema               fim-event/1
fim.severity             high
fim.tool_version         0.1.0
```

No `url_path` was set, no attribute was clipped, and no line was dead-lettered. mini-siem's source
tree was not written to (no file in it was newer than the start of the run, and its git status
stayed clean); the bytecode of its virtual environment was not written either (`python -B`).

## CSV

`fim check --format csv` and `fim watch --format csv` write one row per finding after a header
row, with these columns in this order. CSV is lossy by design (JSON is the lossless format):
every cell is escaped text, so a newline, carriage return, tab or other control character is the
visible escape and never a row break; every cell is quoted and a quote inside it is doubled
(RFC 4180); a cell that starts with `=`, `+`, `-` or `@` gets a leading `'` so a spreadsheet does
not read it as a formula (CWE-1236). Rows end in `\n`. The column values are those of the JSONL
fields of the same name; a field that does not apply is an empty cell.

| Column | From |
|---|---|
| `timestamp` | top-level `timestamp` |
| `host` | top-level `host` |
| `kind` | `fim.kind` |
| `severity` | `fim.severity` |
| `confidence` | `fim.confidence` |
| `path` | `fim.path` |
| `evidence` | `fim.evidence` |
| `finding_id` | `fim.finding_id` |
| `old_sha256` | `fim.old_sha256` |
| `new_sha256` | `fim.new_sha256` |
| `old_size` | `fim.old_size` |
| `new_size` | `fim.new_size` |
| `old_mode` | `fim.old_mode` |
| `new_mode` | `fim.new_mode` |
| `old_attrs` | `fim.old_attrs` |
| `new_attrs` | `fim.new_attrs` |
| `baseline_sequence` | `fim.baseline_sequence` |
| `tool_version` | `fim.tool_version` |

## `watch` semantics that matter to a SIEM

- The first cycle reports every finding. Later cycles report only findings whose `finding_id` is
  new, plus a `resolved` event for each finding that is no longer reported. `--repeat` reports
  everything every cycle.
- A file changed a second time is a new finding (new id) and the earlier one is `resolved`.
- A scan that did not finish (a limit or the time budget) reports no `resolved` events, because
  the missing findings may only be files the scan never reached; the process exits with code 4.
- The `baseline_integrity` event is raised once per distinct failure, not every cycle, and the
  process exits with code 3 when it is stopped.
- `--output FILE` is an append log: a new file (an existing one is refused unless `--force`),
  one write per line, no rotation; use logrotate or similar.
