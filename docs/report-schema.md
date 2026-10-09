# JSON report schema: `fim-report/1`

`fim check --format json` prints (or `--output FILE` writes) one JSON object. The output is ASCII
only: every non-ASCII character is a `\uXXXX` escape. Text fields that come from the filesystem
(`path`, `evidence`, `rule`, `old`, `new`) are escaped text, as in the table, so a hostile file
name cannot carry a control or bidi character. Numbers are integers. Keys always appear, in this
order. A test (`tests/test_render.py`) validates real output against this document, field by
field, and fails if a field is added or removed here without the code, or the other way round.

## Top level

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | Always `"fim-report/1"`. |
| `tool_version` | string | The `fim` version that made the report. |
| `generated_at` | string | UTC time of the check, `YYYY-MM-DDTHH:MM:SSZ`. |
| `baseline` | object | Which baseline was checked (below). |
| `complete` | boolean | `false` if a limit or the time budget stopped the scan, or the baseline itself is incomplete: the result may miss changes. |
| `truncated` | boolean | `true` if more findings exist than are listed in `findings`. |
| `summary` | object | Exact counts (below), also when `findings` is cut. |
| `findings` | array | The findings, most severe first, then by path (below). |
| `notes` | array of string | Warnings for the reader, for example a missing rollback anchor. |

## `baseline`

| Field | Type | Meaning |
|---|---|---|
| `sequence` | integer | The baseline's sequence number (rollback protection, PLAN.md D3). |
| `created_at` | string | UTC time the baseline was made. |
| `key_id` | string | 16 hex characters naming the HMAC key; never the key. |

## `summary`

| Field | Type | Meaning |
|---|---|---|
| `findings` | integer | Number of findings at or above the minimum severity, listed or not. |
| `by_kind` | object | Finding kind to count (only kinds that occur). |
| `by_severity` | object | Severity label to count (only severities that occur). |
| `suppressed` | object | Reason to count: findings that exist but are not listed, for example `findings below the minimum severity`. |
| `mtime_only_changes` | integer | Files whose modification time changed but whose content hash did not. Counted, not findings. |

## Each element of `findings`

| Field | Type | Meaning |
|---|---|---|
| `finding_id` | string | 16 hex characters, stable for the same change of the same path. |
| `kind` | string | `created`, `modified`, `deleted`, `permission_changed`, `type_changed`, `links_changed`, `unreadable`, `unstable`, `vanished`, `root_unavailable`, `policy_drift`. |
| `severity` | string | How much the change matters: `info`, `low`, `medium`, `high`, `critical`. |
| `confidence` | string | How sure the observation is: `low`, `medium`, `high`. Independent of severity. |
| `path` | string | The full path, escaped. Empty for `policy_drift`. |
| `changes` | array | What differs, each `{"field": string, "old": string or null, "new": string or null}`. |
| `evidence` | string | One escaped line (at most 1024 characters) saying why. |
| `rule` | string | The monitored path whose rule applied. |

## Exit codes of `fim check`

`0` clean and complete; `1` findings at or above the minimum severity; `2` usage, configuration or
I/O error; `3` baseline integrity failure (tampered, wrong key, unknown format, rolled back);
`4` incomplete run. The precedence is 3 over 2 over 4 over 1 over 0.
