# PLAN.md - file-integrity-monitor (fim)

Design and phase plan for Project 3. Status: **approved (v0.3): all decisions D1-D14 approved, five with amendments.**
Rules for working on this plan are in CLAUDE.md. No phase starts until the decisions it depends
on are approved.

Product in one paragraph: `fim baseline` records the state of configured paths into an
HMAC-protected baseline. `fim check` rescans and reports created, modified, deleted,
permission-changed and type-changed files, with severity and confidence as separate fields and
evidence text. `fim watch` repeats the check on an interval (polling). `fim demo` shows the whole
flow in a temporary directory and then removes it. Output: table, JSON, JSONL (mini-siem
compatible), CSV. Defensive and read-only: the tool never changes a monitored file.

---

## 0. Open decisions (approve, or change and approve)

Mark each with `[x] approved` or write your change under it.

### D1 - Dependencies and hashing
**Recommendation:** stdlib only (`hashlib.sha256`, `hmac`, `secrets`, `json`, `csv`), plus
**PyYAML** as the single runtime dependency. Own chunked read loop (1 MiB chunks) instead of
`hashlib.file_digest`, because the loop must enforce the size cap, check the run-time budget
between chunks and detect files that grow or change during hashing. Dev dependencies: pytest,
pytest-cov, ruff, mypy, types-PyYAML (release-only: build, pip-audit, bandit). No `rich`, no
`click`, no `blake3`/`xxhash`.
**Reason:** a smaller supply chain is itself a security property; SHA-256 is the expected
algorithm for evidence; the stdlib is fast enough (measured in Phase 6, not assumed).
- [x] approved

### D2 - HMAC key: storage, format, lifecycle
**Recommendation:**
- `fim init-key --key-file PATH` creates 32 bytes from `secrets.token_bytes`. File format: two
  ASCII lines, `FIM-HMAC-KEY v1` and 64 hex characters. Max 4 KiB; anything else is refused.
- No default location inside the project or the monitored roots. Suggested locations (documented,
  not hard-coded): Linux `~/.config/fim/` for a lab, or better a root-owned path like
  `/etc/fim-key/` with the tool run as root and baselines writable by another account; Windows
  `%LOCALAPPDATA%\fim\`. Best: removable media or a different account than the one being watched.
- Created with mode 0600 on POSIX (via `os.open` with `O_EXCL`); on load, refuse a POSIX key that
  is group- or world-readable or not owned by the current user. On Windows the ACL cannot be
  verified without ACL APIs (D7), so this is a documented limitation, not a fake check.
- The key is passed only as a file path (`--key-file` or config `key_file`), never as a value in
  argv or environment. Refuse a key file inside any monitored root.
- `key_id` = first 16 hex of `HMAC(key, "fim key id v1")`, stored in the baseline envelope so a
  wrong key gives a clear "wrong key" message instead of only "MAC mismatch". It reveals nothing
  usable about the key.
- No passphrase mode and no `rekey` command in v1. Rotation = new key + new baseline.
**Reason:** works unattended for `watch` (a passphrase would not), simple to audit, honest about
what it protects. The HMAC defends against an attacker who can write the baseline but cannot read
the key. An attacker with the same rights as the tool can forge a baseline; that is stated in the
threat model and README, not hidden.
- [x] approved

### D3 - Baseline file format and versioning
**Recommendation:** one file, two parts, verify-before-parse:
1. Line 1: a small JSON envelope (max 1 KiB) with `format: "fim-baseline"`, `version: 1`,
   `mac_alg: "HMAC-SHA256"`, `key_id`, `mac` (hex).
2. The rest: the payload, canonical JSON bytes (UTF-8, `ensure_ascii`, sorted keys, fixed
   separators, no NaN). The payload holds a header (tool version, created_at UTC, sequence number,
   host label, platform, policy snapshot, completeness, limits used) and the records.
- MAC input is domain-separated: `b"fim-baseline\x00v1\x00" + key_id + b"\x00" + payload_bytes`,
  so version and key id are authenticated too. The payload is size-checked
  (`MAX_BASELINE_BYTES`), MAC-verified with `hmac.compare_digest`, and only then parsed.
- Unknown `format` or `version` is refused. No migrations in v1; a future v2 reader adds explicit
  migration code and tests.
- Paths in the baseline are stored in their exact original form (D14), serialised by canonical
  JSON with `ensure_ascii`, so the file contains no raw control or bidi characters because JSON
  escapes every non-ASCII character.
- Re-baselining is `fim baseline --force` (full rescan). No incremental "accept this change" in v1.
- Rollback (an attacker replaces the baseline with an older, validly signed one) cannot be
  detected without trusted external state. v1 mitigation: `check` always prints the baseline's
  `created_at` and `sequence`. Listed under Limitations.
**Reason:** verifying the MAC over the exact bytes avoids re-canonicalisation bugs and never runs
the JSON parser on attacker-controlled input. A single JSON payload is simple; at the file limit
it is still bounded (measured in Phase 6).
- [x] approved with amendment (v0.2)
- **D3 amendment (rollback anchor):** `fim baseline` also writes an anchor file next to the key
  file (same directory, mode 0600 on POSIX, atomic no-follow write) holding an HMAC-signed record
  of the latest baseline's sequence and payload SHA-256, domain-separated from the baseline MAC.
  A new baseline's sequence = anchor sequence + 1 (1 if no anchor). `check` and `watch` refuse
  with exit 3 when an anchor exists and the baseline's sequence or payload digest does not match
  it (rollback or substitution). A missing anchor gives a clear warning and the run continues.
  Residual risk for Limitations: an attacker who can delete files in the key directory can remove
  the anchor, which is only warned about. This supersedes the rollback bullet above (the
  `created_at`/`sequence` printout stays). Implemented in Phase 3.

### D4 - Policy snapshot: what `check` trusts
**Recommendation:** the effective policy (roots, include/exclude globs, per-path severity,
symlink policy, one-file-system flag, size cap) is stored in the MAC-protected baseline. `check`
and `watch` scan using the **baseline's** policy. If `--config` is given and its policy digest
differs from the baseline's, `check` reports a `policy_drift` notice and recommends re-baselining,
but does not change scope.
**Reason:** otherwise an attacker who can edit the YAML (but not the key) could add an exclude and
hide changes, or downgrade severities. The config is unauthenticated; the baseline is not.
- [x] approved

### D5 - What gets recorded
**Recommendation:**
- Regular files: type, size, mtime_ns, SHA-256 (or a `hash_status` saying why not), permissions
  (D7), nlink, and on POSIX uid/gid.
- Directories: recorded (type, permissions, mtime_ns) but not hashed, so permission and type
  changes on directories are seen.
- Symlinks / reparse points: recorded as links (D6). FIFOs, sockets, char/block devices: recorded
  by type only, never opened (opening a FIFO blocks).
- Files over the size cap: `hash_status: skipped_too_large`, compared by size + mtime only, with
  lower confidence (D8). Never hash a partial file and call it a hash.
- Windows cloud placeholders (`FILE_ATTRIBUTE_OFFLINE` or `RECALL_ON_DATA_ACCESS`, e.g. OneDrive):
  `hash_status: skipped_offline`; reading them would trigger a download.
- Mount boundaries: `one_file_system: true` by default (do not descend into another device below
  a root); configurable per root.
- An mtime-only change with an identical hash is not a finding (counted in the summary).
- A rename shows as deleted + created. If both have the same SHA-256, both findings get evidence
  text "same content as <other path> (possible rename)". No inode tracking.
**Reason:** covers the attacks that matter in a home lab (planted files, changed binaries,
permission weakening, file-to-symlink swaps) without noisy fields.
- [x] approved

### D6 - Symlinks, junctions, hard links
**Recommendation:**
- Policy `never` (default): a symlink is recorded as itself: type `symlink`, `link_target` text
  (escaped). A changed target is a `modified` finding with evidence. Dangling links are fine.
- Policy `files` (opt-in): additionally hash the target if it is a regular file. Never traverse a
  symlinked directory. A third policy (`all`) is **not offered**: loops and root escape risk.
- Windows reparse points other than symlinks (junctions, mount points, app-exec links, cloud
  tags): type `reparse` with the reparse tag; never traversed, never followed, under any policy.
  Detection uses `lstat` + `st_file_attributes` + `st_reparse_tag` (works on 3.11, which lacks
  `os.path.isjunction`).
- A configured root that is itself a symlink or reparse point is refused with a message to
  configure the real path.
- Directory loop guard: a visited `(st_dev, st_ino)` set, plus `MAX_DEPTH`.
- Hard links: record `nlink` only. A change in `nlink` on a file is a `links_changed` finding
  (low severity unless the path rule says otherwise, medium confidence): a new hard link to a
  sensitive file is worth noticing. Content changes through any link are caught by the hash.
**Reason:** "never follow" makes the walk finite and predictable; recording the link itself still
detects the classic "replace file with symlink" attack (that is a `type_changed`).
- [x] approved

### D7 - Permissions coverage per OS
**Recommendation:**
- POSIX: `S_IMODE` (including setuid, setgid, sticky) and numeric uid/gid. Names are shown
  best-effort in the table only. Out of scope: POSIX ACLs, xattrs, file capabilities
  (`security.capability`), SELinux labels. Listed under Limitations.
- Windows: the READONLY, HIDDEN and SYSTEM attribute bits from `st_file_attributes`. ARCHIVE is
  deliberately ignored (it flips on every write and would duplicate `modified`). No POSIX mode on
  Windows (Python's emulation only mirrors READONLY).
- Windows ACLs and owner: **out of scope for v1.** Reading them needs `pywin32` or `ctypes` calls
  into advapi32 (`GetNamedSecurityInfoW`), security-descriptor parsing, SID resolution and
  canonical comparison. That is a large, error-prone surface for a student project, and a
  half-correct ACL diff would produce false confidence. Documented as the main Windows limitation,
  with a v2 note. Alternate data streams: out of scope, documented.
**Reason:** precise and testable on both OSes; the interpretation of the raw bits lives in
`core/` and is tested everywhere with synthetic integers.
- [x] approved

### D8 - Severity and confidence model
**Recommendation:** two independent fields.
- **Severity** (`info` < `low` < `medium` < `high` < `critical`) = how much the change matters.
  Base = the matching path rule's `severity` (default `medium`; most specific root wins).
  Adjustments (capped at `critical`): `type_changed` +1; `permission_changed` +1 if it adds
  world-write, setuid or setgid (POSIX) or clears READONLY on a SYSTEM file (Windows);
  `links_changed` = `low`; scan issues (`unreadable`, `unstable`, `vanished`) = `low`;
  `root_unavailable` and `baseline_integrity` = `critical`.
- **Confidence** (`high` / `medium` / `low`) = how sure the observation is.
  `high`: hash differs, file absent from a complete listing, type or permission bits differ.
  `medium`: size/mtime differ on a file not hashed (too large / offline); `links_changed`.
  `low`: file changed during hashing; unreadable now but readable then; possible-rename hints.
- Evidence: a short structured list (`field`, `old`, `new`) plus one sanitised text line, max
  `MAX_EVIDENCE_CHARS`.
- If a root is missing at check time: one `root_unavailable` finding; per-file `deleted` findings
  under that root are suppressed and counted in the summary.
**Reason:** an analyst needs "how bad" and "how sure" separately; mixing them is what makes
dashboards untrustworthy.
- [x] approved

### D9 - `watch` semantics and polling defaults
**Recommendation:**
- `--interval` default **300 s**, min **10 s**, max **86 400 s**. The interval is measured from
  the end of one cycle to the start of the next, so cycles never overlap. Each cycle obeys
  `MAX_RUN_SECONDS`.
- The baseline file is re-read and MAC-verified at the start of every cycle. If verification
  fails, `watch` emits a `baseline_integrity` critical event, keeps checking against the last
  verified in-memory baseline, and exits with code 3 when stopped.
- Output: the first cycle emits all findings; later cycles emit only findings that are new or
  changed since the previous cycle (by stable `finding_id`), plus `resolved` events for findings
  that disappeared. `--repeat` emits everything every cycle.
- `--max-cycles N` exists for tests and scripted use. Clock and sleeper are injected.
- `--output FILE` for JSONL is an append log: created new (`O_EXCL`, no symlink), or replaced with
  `--force`; each event is one write. No rotation (use logrotate or similar).
**Reason:** 5 minutes is a sane default for full rehashing of a home-lab tree; delta output keeps
the SIEM from being flooded with the same finding every cycle.
- [x] approved

### D10 - Canonical path text and output encoding
**Recommendation:** one escaping function in `core/sanitize.py`, used for all output (amended by
D14: not for storage).
- Injective and reversible: `\` becomes `\\`; C0/C1 controls and DEL become `\xHH`; characters of
  Unicode category Cf, Zl, Zp, Co, Cn and non-ASCII Zs (bidi controls, zero-width, BOM, line
  separators, private use, unassigned) become `\uXXXX` / `\UXXXXXXXX`; undecodable POSIX bytes
  (surrogateescape U+DC80..U+DCFF) become `\yHH`. Everything else, including non-Latin letters,
  stays readable.
- Tests: exhaustive sweep of all code points (slow test) proving no dangerous category survives;
  seeded round-trip tests proving `unescape(escape(s)) == s`.
- JSON/JSONL use `ensure_ascii=True` on top. CSV additionally prefixes a `'` to any cell starting
  with `=`, `+`, `-`, `@`, tab or CR (CSV is therefore lossy; JSON is the lossless format).
- The CLI writes to stdout with `errors="backslashreplace"`, so a cp1252 Windows console cannot
  crash the tool.
- Not solved, and documented: visually confusable characters (Latin "a" vs Cyrillic "а").
**Reason:** one function means one place to get right.
- [x] approved with amendments (v0.2, v0.3)
- **D10 amendment (readable Windows paths):** record paths are stored relative to their root with
  "/" separators. Roots are displayed per component, escaped one by one and joined with the native
  separator only for display. A Windows path must therefore never show doubled backslashes in
  table output; a test covers this.
- **D10 amendment (v0.3, see D14):** the sanitiser is used only for display and output (table,
  the text fields of the JSON report, JSONL, CSV, messages and exceptions). It is not used for
  storage or comparison. The sentence "storing escaped text means what the user sees equals what
  the baseline holds" is withdrawn: the baseline holds the exact path, the user sees the escaped
  form. Reason: whether a code point is escaped (category Cn, newly assigned Cf) depends on the
  running Python's Unicode tables, so storing escaped text would make a baseline written under
  one Python compare differently under another.

### D11 - Limits (initial values; `core/limits.py`)
| Constant | Default | Hard ceiling |
|---|---|---|
| `MAX_ROOTS` | 64 | 64 |
| `MAX_FILES` (entries incl. dirs) | 200 000 | 1 000 000 |
| `MAX_DEPTH` | 64 | 128 |
| `MAX_PATH_CHARS` | 4 096 | 4 096 |
| `MAX_HASH_FILE_BYTES` | 256 MiB | 4 GiB |
| `HASH_CHUNK_BYTES` | 1 MiB | - |
| `MAX_RUN_SECONDS` | 900 | 3 600 |
| `MAX_BASELINE_BYTES` | 256 MiB | 256 MiB |
| `MAX_CONFIG_BYTES` | 256 KiB | 256 KiB |
| `MAX_PATTERNS` / `MAX_PATTERN_CHARS` | 256 / 512 | same |
| `MAX_FINDINGS_REPORTED` | 10 000 | 10 000 |
| `MAX_EVIDENCE_CHARS` | 1 024 | 1 024 |
| `MAX_KEY_FILE_BYTES` | 4 096 | 4 096 |
| watch interval min / default / max | 10 / 300 / 86 400 s | - |

Config may lower values, never exceed a ceiling. Phase 6 measures throughput and memory at these
sizes; if a default turns out unreasonable, it changes with a measured reason. Drift tests keep
README and docs in sync with this file.
- [x] approved with amendment (v0.2)
- **D11 amendment:** Phase 6 measures peak memory when loading a baseline near
  `MAX_BASELINE_BYTES`; if it is unreasonable for a laptop, the ceiling is lowered with the
  measured reason.

### D12 - mini-siem JSONL mapping
Based on mini-siem's actual `parsers/jsonlog.py` and `core/events.py` (read for this plan):
mini-siem's JSON parser takes `timestamp`, `host`, `message`; `event_type` must be in its closed
vocabulary (which has no file events), otherwise it becomes `json_event` with
`attrs.declared_event_type`; every other key is flattened into `attrs` (dotted keys, depth <= 3,
at most 64 attrs, each value <= 1 024 chars or the event is rejected); a key named `path` is an
alias for `url_path`; lines over 65 536 bytes are dead-lettered; lone surrogates are rejected.
**Recommendation (option a):** emit events that fit the current mini-siem schema, without
changing mini-siem:
```
timestamp        ISO-8601 UTC of the scan
host             host label from the baseline
message          one-line sanitised summary, <= 1 024 chars
event_type       "fim.<kind>"  -> lands in attrs.declared_event_type
fim: { kind, severity, confidence, path, path_sha256, path_truncated, old_sha256, new_sha256,
       old_size, new_size, old_mode, new_mode, old_attrs, new_attrs, evidence, finding_id,
       baseline_sequence, tool_version, schema: "fim-event/1" }
```
Never use top-level key `path`. `fim.path` is truncated to 1 000 chars when needed, with
`path_truncated: "true"` and the full path's `path_sha256` for correlation. Every event is under
32 attrs and well under the line limit (tested). Option b (adding native file event types to
mini-siem) is a mini-siem schema change, out of scope here. Phase 5 re-reads the mini-siem parser,
records the result in `docs/siem-mapping.md`, and pastes a real ingest of a demo JSONL file.
- [x] approved

### D13 - Project identity and tooling
**Recommendation:** distribution name `file-integrity-monitor`, import package `fim`, console
script `fim`, also `python -m fim`. `src/` layout. Build backend **hatchling** (as in
network-scanner). License MIT (as in both siblings), `authors` with name only. CI actions: same
majors as network-scanner (`actions/checkout@v4`, `actions/setup-python@v5`), because they are
known to work there and Claude Code has no GitHub access to check newer ones; you can bump them.
Not published to PyPI; releases are your GitHub tags.
- [x] approved with amendment (v0.2)
- **D13 amendment:** the `.venv` is created with Python 3.13 explicitly
  (`uv venv --python 3.13 .venv`, or `py -3.13 -m venv .venv` if uv is unavailable), never the
  machine default (which is 3.14). The Commands section of CLAUDE.md matches.

### D14 - Record paths are stored exactly, escaped only for display
**Decision:** a record path is stored in the baseline in its exact original form: relative to its
root, components joined with "/", lossless, including lone surrogates (POSIX bytes that do not
decode, carried by `surrogateescape`). The only serialisation is canonical JSON
(`core/canonical.py`) with `ensure_ascii=True`, which writes every non-ASCII character and lone
surrogate as a `\uXXXX` escape. Storage keys, hashes of paths and comparisons never depend on the
Unicode database of the running Python: two Pythons with different Unicode versions produce
identical bytes for the same path. The sanitiser in `core/sanitize.py` is used only for display
and output (table, the text fields of the JSON report, JSONL, CSV, error messages and
exceptions). Model rule: `FileRecord.path` and `FileRecord.link_target` hold exact text;
`Finding.path`, `ScanIssue.path`, `Change` values and evidence hold escaped text.
**Reason:** removes known gap 2 of the Phase 1 report (Unicode tables differ between Python
versions) at its root, instead of recording a Unicode version in the header or freezing a table.
A test builds storage keys for code points whose general category differs between Unicode 14,
15.0 and 15.1 and proves they are identical whatever the running Python's tables say.
- [x] approved

---

## 1. Architecture

### 1.1 Layers and modules
```
src/fim/
  __init__.py, __main__.py
  core/                       L0 pure, no I/O
    limits.py                 all bounds (D11)
    models.py                 FileRecord, ScanResult, Baseline, Finding, Report, enums
    errors.py                 FimError hierarchy (one exit code each)
    sanitize.py               escape/unescape (D10), CSV neutralising helper
    pathrules.py              string-level path validation: UNC/device/URL/drive-relative refusal,
                              normalisation, containment, Windows reserved names
    globs.py                  segment-wise glob matcher (*, ?, [..], **), no regex backtracking
    policy.py                 effective policy, rule lookup (most specific root), policy digest
    perms.py                  interpret raw st_mode / attribute ints
    diff.py                   baseline records vs current records -> findings (D5, D8)
    canonical.py              canonical JSON bytes for baseline payload and finding ids
    clock.py                  Clock and Sleeper protocols
  fs/                         L1
    observe.py                ONLY reader of monitored files: lstat, scandir, safe open, hash
    safe_files.py             ONLY I/O for own files: atomic no-clobber write, no-follow read,
                              append log, key-file permission check
    sandbox.py                ONLY mutator: the demo's temp tree (create/modify/chmod/delete inside)
  platform/                   L1
    clock.py                  SystemClock, SystemSleeper (only place with time.*)
    hostinfo.py               host label default, platform string
  render/                     L1 pure renderers
    table.py, json_out.py, jsonl.py, csv_out.py
  services/                   L2
    config.py                 YAML load (only yaml importer) + strict schema
    scanner.py                walk roots under policy, call observe, build ScanResult
    baseline_codec.py         envelope + payload encode/decode, HMAC sign/verify (D3)
    keystore.py               init/load key, key_id (D2)
  app/                        L3
    baseline.py, check.py, watch.py, demo.py
  cli/                        L4
    main.py                   argparse, exit codes, stdout wiring
scripts/
  gate.py, check_architecture.py, bench.py
```

### 1.2 Data flow
`cli` -> `app.baseline`: load config (services.config) -> build policy (core.policy) -> scan
(services.scanner -> fs.observe) -> encode + sign (services.baseline_codec, key from
services.keystore) -> atomic write (fs.safe_files).

`cli` -> `app.check`: read + verify baseline (verify before parse) -> scan with the baseline's
policy -> `core.diff` -> `Report` -> renderer -> stdout or atomic file write. Exit code from report.

### 1.3 Reading a monitored file safely (`fs/observe.py`)
1. `lstat` the path; only `S_ISREG` continues to hashing (D5, D6).
2. Open read-only: POSIX `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` (plus `O_NOATIME` when
   permitted, best effort); Windows `O_RDONLY | O_BINARY`.
3. `fstat` the open descriptor and compare `(st_dev, st_ino, st_mode type)` with step 1. A
   mismatch means the path was swapped: `hash_status: unstable`, evidence "replaced during scan".
4. Read in chunks up to `MAX_HASH_FILE_BYTES + 1`, checking the run-time budget between chunks.
5. `fstat` again: size or mtime_ns changed -> retry once; changed again -> `unstable`.
6. `FileNotFoundError` at any step -> `vanished`; `PermissionError` -> `unreadable`; other
   `OSError` -> `unreadable` with the errno name. Never raised to the caller.

### 1.4 Writing own files (`fs/safe_files.py`)
- Validate the path with `core.pathrules` (no UNC/device/URL), refuse if the final path is a
  symlink or reparse point, refuse if it lies inside a monitored root.
- Write a temp file in the same directory with `O_CREAT | O_EXCL` (+ `O_NOFOLLOW` on POSIX),
  mode 0600, write, flush, fsync.
- Without `--force`: publish with `os.link(temp, final)` then remove temp (fails if final exists,
  on both NTFS and POSIX; no check-then-write race). With `--force`: `os.replace`. Then fsync the
  directory on POSIX.
- Residual risk, documented: a parent directory swapped between validation and rename.

### 1.5 Exit codes
`0` clean and complete; `1` findings; `2` usage, config or I/O error; `3` baseline integrity
failure (tampered, wrong key, unknown format); `4` incomplete run (a limit or the time budget was
hit). Precedence: 3 > 2 > 4 > 1 > 0. An incomplete run still prints its findings and
`complete: false`.

### 1.6 Configuration (YAML)
Loaded with a SafeLoader subclass that also rejects duplicate keys, anchors/aliases (no
alias-expansion bombs) and custom tags; size capped by `MAX_CONFIG_BYTES`; strict schema (unknown
keys, wrong types, YAML 1.1 surprises like unquoted `yes` / `0755` rejected where a string is
expected). Shape:
```yaml
version: 1
host_label: "lab-01"            # optional
key_file: "~/.config/fim/fim.key"
symlinks: never                 # never | files
one_file_system: true
exclude: ["*.tmp", "**/__pycache__/**"]   # globs must be quoted: * starts a YAML alias
paths:
  - path: "/etc"
    severity: high
    exclude: ["mtab"]
  - path: "/home/lab/bin"
    severity: critical
    include: ["*"]
limits:
  max_files: 100000             # may only lower the ceiling
```
Roots must be absolute (or start with `~`); no environment-variable expansion; no implicit roots,
no "scan current directory" default. Glob semantics: matched against the path relative to its
root with `/` separators; a pattern without `/` matches the basename at any depth; `**` spans
directories; case-sensitive on POSIX, case-insensitive on Windows. Excludes win over includes;
excluded directories are not descended into. Nested roots: each file is recorded once, under the
most specific root.

---

## 2. Data model (all frozen dataclasses)

| Type | Fields |
|---|---|
| `EntryType` | `file`, `dir`, `symlink`, `reparse`, `fifo`, `socket`, `device`, `other` |
| `HashStatus` | `ok`, `skipped_too_large`, `skipped_offline`, `not_applicable`, `unreadable`, `vanished`, `unstable` |
| `FileRecord` | `path` (escaped text), `root_index`, `type`, `size`, `mtime_ns`, `sha256` or None, `hash_status`, `mode` (POSIX) or None, `uid`, `gid`, `win_attrs` (masked bits) or None, `nlink`, `link_target` or None, `reparse_tag` or None, `error` (errno name) or None |
| `ScanIssue` | `path`, `kind` (`unreadable`, `unstable`, `vanished`, `root_unavailable`, `limit_reached`, `time_budget`), `detail` |
| `ScanResult` | `records`, `issues`, `complete`, `stats` (files, dirs, bytes hashed, skipped by reason), `started_at`, `finished_at` |
| `Policy` | roots with per-root severity/include/exclude/one_file_system, global excludes, symlink policy, effective limits, `digest` |
| `BaselineHeader` | `tool_version`, `created_at`, `sequence`, `host`, `platform`, `policy`, `complete`, `limits` |
| `FindingKind` | `created`, `modified`, `deleted`, `permission_changed`, `type_changed`, `links_changed`, `unreadable`, `unstable`, `vanished`, `root_unavailable`, `policy_drift`, `baseline_integrity`, `resolved` (watch only) |
| `Finding` | `finding_id` (16 hex, from canonical (path, kind, old fingerprint, new fingerprint)), `kind`, `path`, `severity`, `confidence`, `changes` [(`field`, `old`, `new`)], `evidence`, `rule` (root path) |
| `Report` | `findings`, `summary` counts by kind/severity, `suppressed` counts, `complete`, `truncated`, baseline `created_at`/`sequence`/`key_id`, `generated_at`, `tool_version` |

Comparison per path (`core/diff.py`): absent in baseline -> `created`; absent now -> `deleted`;
type differs -> `type_changed` (and nothing else for that path); hash differs (or size/mtime for
unhashed files) -> `modified`; mode/uid/gid/win_attrs differ -> `permission_changed`; nlink differs
-> `links_changed`; link target differs -> `modified`. One path can produce `modified` and
`permission_changed` together.

---

## 3. Threat model summary

Assets: the integrity of the baseline; secrecy of the HMAC key; correctness of reports; the
safety of the host running the tool. Full version goes to `docs/threat-model.md` in Phase 6.

| Threat | Control | Residual / out of scope | Evidence (test) |
|---|---|---|---|
| Attacker changes monitored files | hash + metadata diff | changes reverted between two polls are missed (polling) | diff + check tests |
| Attacker edits baseline without key | HMAC, verify-before-parse, exit 3 (CWE-354) | anchor deletion by an attacker who can delete files in the key directory (D3 amendment) | tamper tests |
| Attacker edits config to hide paths | scope from the baseline's policy (D4) | - | policy drift tests |
| Attacker with the tool's own privileges | none possible: can read key and forge | documented, run as a separate account | - |
| Hostile names in output (terminal escapes, bidi, newlines) | single escaper (CWE-150, CWE-117) | confusable glyphs | sanitiser sweep |
| CSV formula injection | neutralising prefix (CWE-1236) | CSV lossy by design | csv tests |
| Symlink/junction tricks (escape roots, loops, write via link) | never follow, no traversal of reparse points, no-follow writes (CWE-59) | parent dir swap during write | symlink tests |
| File swapped or changed while hashing | lstat/fstat identity check, re-stat, `unstable` (CWE-367) | changes between scan and report | TOCTOU tests |
| Resource exhaustion (huge trees, files, paths, YAML bombs) | limits, alias rejection, size caps, time budget (CWE-400) | - | limit tests |
| Unsafe YAML deserialisation | SafeLoader subclass, banned `yaml.load` (CWE-502) | - | config + architecture tests |
| Key file readable by others | 0600 creation, POSIX permission check (CWE-732) | Windows ACL not verified | keystore tests |
| FIFO / device hangs the scanner | only regular files opened, `O_NONBLOCK` | - | special-file tests |
| Tool damages the host | read-only by architecture check + before/after tree-state test | atime may update | invariant tests |

CWE ids are used only for the tool's own controls, never on findings, and each is re-checked
against the CWE list when docs are written.

---

## 4. Phases

Six phases. Size estimates assume a Claude Pro weekly limit: roughly one phase per week, split
into 2-4 sessions, each ending at a green commit. Use the cheaper model for mechanical work and
spend effort on reviewing `observe.py`, `safe_files.py`, `baseline_codec.py` and `sanitize.py`.

### Phase 1 - Foundation, gate, CI, pure core (size: M)
Depends on: D1, D10, D11, D13.
**Scope:** `git init -b main`; `.venv`; `pyproject.toml` (hatchling, dev extras, ruff, mypy strict,
pytest markers, coverage branch + `fail_under = 85`); `.gitignore` (venv, caches, `*.key`,
`*.baseline*`, build output); LICENSE; empty CLI with `--version`; `scripts/gate.py` (all steps,
summary, `--full`, `--log`); `scripts/check_architecture.py` (layers, cycles, FS default-deny,
banned APIs, fails closed); CI workflow; `core/limits.py`, `core/models.py`, `core/errors.py`,
`core/sanitize.py`, `core/pathrules.py`, `core/clock.py`; `docs/phase-reports.md`; README stub
(no claims yet); SECURITY.md stub (GitHub private vulnerability reporting, no email).
**CI** (`.github/workflows/ci.yml`): push to main + PRs; `permissions: contents: read`;
`concurrency` with `cancel-in-progress: true`; matrix `ubuntu-24.04`, `windows-latest` x 3.11,
3.12, 3.13, `fail-fast: false`, `timeout-minutes: 15`; install `.[dev]`; run
`python scripts/gate.py --full`. CI is verified only after you push; until then the phase report
says "CI not yet run".
**Tests:** architecture checker self-tests (each rule has a fixture that must trip it, plus the real
tree passes; a planted import cycle is found); hygiene tests (bidi/zero-width/control chars;
tracked secret files; email patterns); CI-policy test (parses the workflow with `yaml.safe_load`
and asserts permissions, matrix, concurrency, pinned majors); sanitiser tests (round trip, CSV
prefix, exhaustive sweep as `slow`); pathrules tests (UNC, `\\?\`, `\\.\`, `CON`/`NUL`/`COM1`,
`C:foo`, `file:`, `http://`, over-long paths, both OS flavours via `ntpath`/`posixpath`); limits
drift test skeleton.
**Definition of done:** gate green locally on Windows with mypy for both platforms; checker
catches every planted violation; first commit made via the gate; phase report written.

### Phase 2 - Config, globs, observation and scanning (size: L)
Depends on: D4, D5, D6, D7.
**Scope:** `services/config.py` (strict loader, duplicate keys, aliases, tags, size cap, roots
validation, limits only lowered); `core/globs.py`; `core/policy.py` (most specific root, digest);
`core/perms.py`; `fs/observe.py` (section 1.3); `platform/clock.py`; `services/scanner.py`
(iterative walk, sorted entries, depth/loop guard, one-file-system, include/exclude, limits and
time budget -> `complete: false`). No CLI command yet beyond an internal test entry point.
**Tests:** config fuzz-style negatives (each invalid shape refused with a clear message); glob
table tests incl. `**`, case rules per OS, pathological patterns run in linear time; perms
interpretation from synthetic ints on every OS; scanner on tmp trees: regular files, empty files,
large-file cap, nested roots, excludes pruning, symlinks (file, dir, dangling, loop), junctions
(Windows, created with `mklink /J` in a test helper), FIFO not opened (POSIX), unreadable file
(POSIX chmod 000; skipped when running as root), file vanishing and changing mid-hash (injected
via a fake reader hook in tests, not timing), limit and time-budget truncation with a fake clock;
read-only invariant test (full tree state incl. mtime_ns and mode identical before and after a
scan).
**Definition of done:** scanning a 20k-file temp tree works within limits (slow test); every
HashStatus and ScanIssue kind has a test that produces it; gate green; report written.

### Phase 3 - Key, baseline format, `init-key` and `baseline` (size: M)
Depends on: D2, D3.
**Scope:** `services/keystore.py`; `services/baseline_codec.py` (incl. the rollback anchor, D3
amendment); `fs/safe_files.py` (section 1.4); `app/baseline.py`; CLI `init-key` and `baseline` with `--force`; exit codes 0/2/3/4 wired.
**Tests:** key created 0600 (POSIX), refused if group/world-readable, wrong header, wrong length,
inside a monitored root; key never in output or exceptions (scan captured output for the hex);
baseline round trip; tamper tests: flip one byte in envelope, payload, MAC, version, key_id;
truncated file; extra trailing bytes; wrong key -> "wrong key" message; oversize payload refused
before MAC; unknown version refused; parser never called before verification (spy); safe_files:
no overwrite without `--force`, symlink and reparse targets refused, UNC/device/URL refused,
output inside monitored root refused, temp file cleaned up on failure; canonical bytes are stable
across Python 3.11-3.13 (golden file).
**Definition of done:** `fim init-key` and `fim baseline` work end to end in a temp dir from the
CLI; all tamper cases exit 3; gate green; report written.

### Phase 4 - Diff, `check`, table and JSON output (size: M)
Depends on: D8.
**Scope:** `core/diff.py` (section 2 rules, rename hint, root_unavailable suppression, policy
drift); `app/check.py`; `render/table.py` and `render/json_out.py`; CLI `check` with `--format
table|json`, `--output`, `--force`, `--min-severity`; stdout with `backslashreplace`;
`MAX_FINDINGS_REPORTED` truncation with exact counts.
**Tests:** one test per finding kind and per severity/confidence rule (table-driven); POSIX
setuid/world-write escalation; Windows READONLY/HIDDEN/SYSTEM changes; file -> symlink
`type_changed`; symlink target change; same-hash rename hint; missing root; incomplete scan gives
exit 4 and `complete: false`; hostile names (bidi, ANSI escape, newline, invalid bytes on POSIX)
render escaped in table and JSON; cp1252 stream does not crash; JSON output validated against a
documented schema (hand-written checks, no new dependency); exit-code precedence table test.
**Definition of done:** full CLI flow `init-key` -> `baseline` -> change files -> `check` works in a
temp dir with correct findings; gate green; report written.

### Phase 5 - JSONL, CSV, `watch`, `demo` (size: M)
Depends on: D9, D12.
**Scope:** `render/jsonl.py` (D12 shape), `render/csv_out.py`; `app/watch.py` (delta output,
resolved events, per-cycle re-verification, `--max-cycles`, `--repeat`, append-log output);
`fs/sandbox.py` + `app/demo.py` (temp dir, throwaway key inside it, baseline, scripted changes
including a hostile filename where the OS allows it, check, table output, cleanup in `finally`,
read-only bits cleared before delete on Windows, verify the directory is gone); CLI `watch`,
`demo`; `docs/siem-mapping.md`.
**Tests:** JSONL: every line valid JSON, no key named `path`, <= 64 attrs after mini-siem-style
flattening, every value <= 1 024 chars, line < 65 536 bytes, no lone surrogates, long paths
truncated with `path_sha256`; CSV: formula prefixes, quoting, escaped newlines; watch with fake
clock and sleeper: interval timing, no overlap, delta and resolved logic, baseline tampered
mid-watch -> critical event and exit 3, KeyboardInterrupt handled; demo: leaves nothing behind
(also when a step raises), never touches a path outside its temp dir (guard fixture), output
contains each expected finding kind.
**Manual check (pasted into the report):** ingest the demo's JSONL into mini-siem with its real
`ingest` command and show the resulting events.
**Definition of done:** all four formats and `watch`/`demo` work from the CLI; mini-siem ingest
shown with real output; gate green; report written.

### Phase 6 - Hardening, measurement, docs, release (size: M)
Depends on: everything above.
**Scope:** `scripts/bench.py` (temp trees of 1k/10k/100k files and a few large files; wall time,
MB/s hashed, peak Python memory via `tracemalloc`) -> `docs/performance.md` with machine details;
re-check D11 defaults against measurements; `docs/threat-model.md`; README (install, quick start,
real pasted `fim demo` and `fim check` output, claim-to-evidence table, "What the tool reads and
writes", Limitations, mini-siem link); CHANGELOG `1.0.0`; release checks per CLAUDE.md section 10.
**Tests:** README claim table: every row's test node exists (via pytest collection) or doc path
exists; drift tests for limits, exit codes, defaults and watch interval in README/docs; a final
review pass of the four security-critical modules with any fixes test-first.
**Limitations section must include at least:** polling misses short-lived changes; no Windows
ACL/owner, ADS, POSIX ACL/xattr/capabilities; same-privilege attacker can forge baselines;
rollback detectable only via the anchor, which an attacker who can delete files in the key
directory can remove (warned, not refused); atime may update; confusable glyphs; key ACL not verified on Windows;
mapped network drives not detected as such.
**Definition of done:** release checks pass in a temp venv outside the repo with pasted output;
README contains only real output and measured numbers; gate green on the full suite; final phase
report written. Tagging and pushing are yours.

---

## 5. Changelog of this plan
- v0.1 (2026-10-08): first draft, decisions D1-D13 open.
- v0.2 (2026-10-08): all decisions approved. D1, D2, D4, D5, D6, D7, D8, D9, D12 as written.
  Amendments: D3 rollback anchor file next to the key (signed sequence + payload digest; `check`
  and `watch` exit 3 on mismatch, warn when missing; Phase 3); D10 per-component escaping and
  root-relative "/" record paths, no doubled backslashes on Windows (test required); D11 Phase 6
  measures peak memory near `MAX_BASELINE_BYTES` and may lower the ceiling; D13 `.venv` built
  with Python 3.13 explicitly. Consistency edits following from the D3 amendment: Phase 3 scope,
  Phase 6 Limitations list and the threat-model rollback row now describe the anchor and its
  residual risk instead of "rollback undetectable".
- v0.2.1 (2026-10-08): Phase 1 implementation notes, deviations ACCEPTED by the owner on 2026-10-08
  (details in docs/phase-reports.md): D10 escaping also covers lone surrogates outside U+DC80..U+DCFF;
  `..` refused in every user-supplied path; the architecture checker bans a little more than
  CLAUDE.md lists (ctypes, builtins, sys.modules, `.open()` outside fs/, more archive and
  database modules outside fs/, literal os.open flags in observe.py); .gitattributes pins LF;
  exit-code precedence and the validated Limits dataclass were built in Phase 1; the pytest path
  guard for fs/ modules is deferred to Phases 2 and 3 because those modules do not exist yet.
- v0.2.1 acceptance (2026-10-08): the owner accepted every deviation listed in v0.2.1 above
  (items 1-9 of the Phase 1 report). The pytest path guard for fs/ modules is built with
  fs/observe.py in Phase 2 and fs/safe_files.py in Phase 3.
- v0.3 (2026-10-08): D14 added and approved: record paths are stored exactly and serialised only
  by canonical JSON with `ensure_ascii=True`; the sanitiser is display-only. D10 amended to match
  (the "escaped storage" reasoning is withdrawn) and the D3 bullet about baseline paths follows.
  Phase 1 known gap 2 (Unicode tables) is closed by D14.
- v0.3.1 (2026-10-08): dev tools are pinned to compatible ranges in pyproject.toml (pytest and
  pytest-cov to one major, ruff and mypy to one minor series, types-PyYAML to one major), so CI
  cannot break without a code change (Phase 1 known gap 5). A test holds the pins.
- v0.3.2 (2026-10-08): Phase 2 implementation notes, deviations recorded for your acceptance
  (details in docs/phase-reports.md): (1) core/canonical.py (canonical JSON, needed by D14 and
  the policy digest) and the policy digest in core/policy.py were built in Phase 2, with
  canonical.py refusing floats and non-text keys; (2) Windows FILE_ATTRIBUTE_RECALL_ON_OPEN
  counts as offline together with OFFLINE and RECALL_ON_DATA_ACCESS, because opening such a file
  also downloads it; (3) glob clarifications to section 1.6: a trailing "**" matches the
  directory itself, "[...]" is the only way to match a metacharacter, patterns with a leading or
  trailing "/" or a backslash are refused, include applies to non-directory entries only
  (directories are always recorded and walked unless excluded), and max_patterns counts all
  patterns of the configuration together; (4) the configuration loader takes the config bytes,
  because reading the file belongs to fs/safe_files.py (Phase 3), and it already refuses a
  key_file inside a monitored root; (5) a configured root that is a symlink, junction or other
  reparse point is a root_unavailable scan issue with the "configure the real path" hint instead
  of an exception, so Phase 3 must make `baseline` refuse while a root_unavailable issue exists;
  (6) the scanner reads the filesystem through a small FileSystemView interface (default:
  fs/observe.py), so every branch is tested on a virtual tree on every OS; (7) a directory
  record keeps mode, uid and gid but size 0 and nlink 1, so directory churn is not a finding;
  (8) a directory reached twice (same device and inode) is entered once and marks the run
  incomplete; (9) a pytest marker `requires_non_root` was added next to the three named in
  CLAUDE.md, for chmod-based tests that the superuser would pass for the wrong reason.
