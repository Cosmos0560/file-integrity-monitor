# file-integrity-monitor (`fim`)

A defensive file integrity monitor for home labs and endpoints you own. `fim` records the state
of the paths you configure in an HMAC-signed baseline and later tells you what changed: a file
modified, deleted or created, a permission weakened, a file swapped for a link, or the baseline
itself tampered with or rolled back. It only ever reads the files it monitors.

Version 1.0.0. Python 3.11 or newer, one runtime dependency (PyYAML), Windows and Linux.
Released under the MIT licence.

## What it is, and what it is not

It is:

- a **detective** control: it tells you that something changed, with what evidence and how sure
  it is;
- **read-only** on everything it monitors, enforced by the code layout and checked in CI;
- a polling tool: `check` once, or `watch` on an interval, emitting JSONL for a SIEM;
- small enough to audit: one runtime dependency, no network, no subprocess, no plug-ins.

It is not:

- an intrusion prevention or response tool: it never restores, quarantines or blocks anything;
- a real-time monitor: it polls, so a change made and undone between two runs is missed;
- protection against an attacker who has the tool's own privileges: such an attacker can read the
  key and forge a baseline ([Limitations](#limitations));
- a replacement for backups, an antivirus, or an EDR agent.

## Install

`fim` is not published to PyPI. Install it from a checkout or a release archive, into a virtual
environment of your own:

```
python -m venv .venv
.venv\Scripts\python.exe -m pip install .          # Windows
.venv/bin/python -m pip install .                  # Linux
fim --version
```

```
$ fim --version
fim 1.0.0
[exit code 0]
```

## Quick start: `fim demo`

`fim demo` runs the whole workflow on throw-away files in a new temporary directory and removes
it again: it creates a key and a signed baseline, shows a clean check, changes the files the way
an intruder might (including a file whose name tries to abuse the terminal), shows what `check`
reports, and shows that a baseline with one changed byte is refused. It takes no options and
touches nothing else.

```
$ fim demo
fim demo: a throw-away copy of the whole workflow on files made for it.
workspace: <TMP>\fim-demo-uwcpwt7o (removed when the demo ends)

step 1: create a key and record a signed baseline
  fim init-key   -> key id 5e619bcf1fd0a321
  fim baseline   -> 10 entries, sequence 1, signed

step 2: check before anything changes
  fim check      -> 0 findings, exit code 0

step 3: change the watched files the way an intruder might
  modified config/app.conf
  deleted  docs/old-notes.txt
  created  bin/helper.sh
  created  a file named payroll\u202e\u200btxt.bak
  made notes.txt read-only

step 4: check again (the file names below are shown escaped, never raw)
  fim check: baseline sequence 1 made 2026-10-10T18:55:19Z (key id 5e619bcf1fd0a321)
  checked 2026-10-10T18:55:19Z with fim 1.0.0

  SEVERITY  CONFIDENCE  KIND                PATH
  high      high        created             <TMP>\fim-demo-uwcpwt7o\watched\bin\helper.sh
                                            new file, 13 bytes, sha256 d7ac283f0efbed24...
  high      high        modified            <TMP>\fim-demo-uwcpwt7o\watched\config\app.conf
                                            sha256 differs (e049009aabc94ce6... -> f06f932399f121dc...); size 34 -> 37
  high      high        deleted             <TMP>\fim-demo-uwcpwt7o\watched\docs\old-notes.txt
                                            file is no longer present
  high      high        permission_changed  <TMP>\fim-demo-uwcpwt7o\watched\notes.txt
                                            win_attrs none -> READONLY
  high      high        created             <TMP>\fim-demo-uwcpwt7o\watched\payroll\u202e\u200btxt.bak
                                            new file, 5 bytes, sha256 efe2a5c09e6d49d7...

  5 findings (high 5)
  by kind: created 2, modified 1, deleted 1, permission_changed 1
  complete: yes
  exit code 1

step 5: tamper with the baseline file itself (one byte)
  fim check      -> refused, exit code 3: the baseline is not trustworthy: the MAC does not verify: the file was changed or damaged after writing

the temporary directory was removed
[exit code 0]
```

The block above is the real output of `fim demo` on Windows 11 with Python 3.13. The temporary
directory name is random; `<TMP>` stands for the system temporary directory in every block of
this README. Lines after `[stderr]` went to the error stream, and `[exit code N]` is the shell's
status, not something the tool prints.

## A first real run

Make a key outside every monitored path, a configuration, and a baseline; then check.

`fim.yaml`:

```yaml
version: 1
host_label: "lab-01"
key_file: "<TMP>\\keys\\fim.key"
paths:
  - path: "<TMP>\\lab"
    severity: high
```

```
$ fim init-key --key-file <TMP>\keys\fim.key --config <TMP>\state\fim.yaml
key file written: <TMP>\keys\fim.key
key id: e83aca1dd8cbfa20
Keep the key outside every monitored path, make a backup, and do not share it. Anyone who can read it can forge a baseline.
[exit code 0]
```

```
$ fim baseline --config <TMP>\state\fim.yaml --baseline <TMP>\state\lab.baseline
baseline written: <TMP>\state\lab.baseline
  records: 8
  sequence: 1
  key id: e83aca1dd8cbfa20
  complete: yes
  rollback anchor created: <TMP>\keys\fim.key.f81f360a9ca54c59.fim-anchor
[exit code 0]
```

```
$ fim check --baseline <TMP>\state\lab.baseline --key-file <TMP>\keys\fim.key
fim check: baseline sequence 1 made 2026-10-10T18:55:05Z (key id e83aca1dd8cbfa20)
checked 2026-10-10T18:55:06Z with fim 1.0.0

no changes found

0 findings
complete: yes
[exit code 0]
```

After a file is edited, one is deleted, one is added and one is made read-only:

```
$ fim check --baseline <TMP>\state\lab.baseline --key-file <TMP>\keys\fim.key
fim check: baseline sequence 1 made 2026-10-10T18:55:05Z (key id e83aca1dd8cbfa20)
checked 2026-10-10T18:55:06Z with fim 1.0.0

SEVERITY  CONFIDENCE  KIND                PATH
high      high        created             <TMP>\lab\bin\helper.sh
                                          new file, 13 bytes, sha256 d7ac283f0efbed24...
high      high        deleted             <TMP>\lab\data\notes.txt
                                          file is no longer present
high      high        modified            <TMP>\lab\etc\app.conf
                                          sha256 differs (e049009aabc94ce6... -> 58749731276250c5...); size 34 -> 41
high      high        permission_changed  <TMP>\lab\etc\users.list
                                          win_attrs none -> READONLY

4 findings (high 4)
by kind: created 1, modified 1, deleted 1, permission_changed 1
complete: yes
[exit code 1]
```

Every finding has a **severity** (how much the change matters, from the path's rule) and a
**confidence** (how sure the observation is), and the evidence that supports it. A changed
modification time with an identical hash is not a finding; it is counted in the summary.

The same findings as one JSON object per line (`--format jsonl`, also what `watch` prints), ready
for a log shipper. `path_sha256` is the SHA-256 of the real path text, so it does not match the
`<TMP>` shown here:

```
$ fim check --baseline <TMP>\state\lab.baseline --key-file <TMP>\keys\fim.key --format jsonl
{"timestamp":"2026-10-10T18:55:07Z","host":"lab-01","message":"fim created [high] <TMP>\\lab\\bin\\helper.sh: new file, 13 bytes, sha256 d7ac283f0efbed24...","event_type":"fim.created","fim":{"kind":"created","severity":"high","confidence":"high","path":"<TMP>\\lab\\bin\\helper.sh","path_sha256":"2bb042da99c3bea625267b273481fb8b36efb126bf04c17a0ca2ed12d3a81d3a","path_truncated":"false","evidence":"new file, 13 bytes, sha256 d7ac283f0efbed24...","finding_id":"7350bca05780505c","baseline_sequence":1,"tool_version":"1.0.0","schema":"fim-event/1"}}
{"timestamp":"2026-10-10T18:55:07Z","host":"lab-01","message":"fim deleted [high] <TMP>\\lab\\data\\notes.txt: file is no longer present","event_type":"fim.deleted","fim":{"kind":"deleted","severity":"high","confidence":"high","path":"<TMP>\\lab\\data\\notes.txt","path_sha256":"67f8d7f791af002510f482cab0fc4a8bae571fadfa32fa0aff22a1f8fb66ee54","path_truncated":"false","evidence":"file is no longer present","finding_id":"c06ef44b248c59c9","baseline_sequence":1,"tool_version":"1.0.0","schema":"fim-event/1"}}
{"timestamp":"2026-10-10T18:55:07Z","host":"lab-01","message":"fim modified [high] <TMP>\\lab\\etc\\app.conf: sha256 differs (e049009aabc94ce6... -> 58749731276250c5...); size 34 -> 41","event_type":"fim.modified","fim":{"kind":"modified","severity":"high","confidence":"high","path":"<TMP>\\lab\\etc\\app.conf","path_sha256":"db3efb1acda682df6923218da2897cc32a17b82405b4a5f48f7e4b0121eef214","path_truncated":"false","old_sha256":"e049009aabc94ce6cffdf75adff1fbeeaf79408a52a73c684d7a7170454c27a9","new_sha256":"58749731276250c50c6eb683eddd729318f64b46a52f1c6216dcaf0633f9eb51","old_size":"34","new_size":"41","evidence":"sha256 differs (e049009aabc94ce6... -> 58749731276250c5...); size 34 -> 41","finding_id":"83a082ae5632e841","baseline_sequence":1,"tool_version":"1.0.0","schema":"fim-event/1"}}
{"timestamp":"2026-10-10T18:55:07Z","host":"lab-01","message":"fim permission_changed [high] <TMP>\\lab\\etc\\users.list: win_attrs none -> READONLY","event_type":"fim.permission_changed","fim":{"kind":"permission_changed","severity":"high","confidence":"high","path":"<TMP>\\lab\\etc\\users.list","path_sha256":"dedc9e5318e267f6971a1287e6d060ea7e2bf2d7a6fd1dd7df4c6aff22fca840","path_truncated":"false","old_attrs":"none","new_attrs":"READONLY","evidence":"win_attrs none -> READONLY","finding_id":"27ec0adef368dfb6","baseline_sequence":1,"tool_version":"1.0.0","schema":"fim-event/1"}}
[exit code 1]
```

A baseline that was changed after it was written, or made with another key, is refused and
nothing in it is parsed (exit code 3). A missing baseline is an error, never "no changes":

```
$ fim check --baseline <TMP>\state\tampered.baseline --key-file <TMP>\keys\fim.key
[stderr]
fim: error: the baseline is not trustworthy: the MAC does not verify: the file was changed or damaged after writing
[exit code 3]
```

```
$ fim check --baseline <TMP>\state\nothing.baseline --key-file <TMP>\keys\fim.key
[stderr]
fim: error: baseline file '<TMP>\state\nothing.baseline' does not exist
[exit code 2]
```

### The same on Linux

On Linux (Ubuntu in WSL, Python 3.14) the files `fim` writes are mode `0600`, and a permission
change is read from the POSIX mode. The session below made a script world-writable and replaced a
file with a symbolic link:

```
$ fim baseline --config <TMP>/state/fim.yaml --baseline <TMP>/state/lab.baseline
baseline written: <TMP>/state/lab.baseline
  records: 5
  sequence: 1
  key id: 7a346fe4ee57456b
  complete: yes
  rollback anchor created: <TMP>/keys/fim.key.99003722ac1a38ea.fim-anchor
[exit code 0]
```

The modes of the three files `fim` wrote, read with `os.lstat` right after the command above:

```
-rw-------  <TMP>/keys/fim.key
-rw-------  <TMP>/state/lab.baseline
-rw-------  <TMP>/keys/fim.key.99003722ac1a38ea.fim-anchor
```

```
$ fim check --baseline <TMP>/state/lab.baseline --key-file <TMP>/keys/fim.key
fim check: baseline sequence 1 made 2026-10-10T18:55:41Z (key id 7a346fe4ee57456b)
checked 2026-10-10T18:55:41Z with fim 1.0.0

SEVERITY  CONFIDENCE  KIND                PATH
critical  high        permission_changed  <TMP>/lab/bin/run.sh
                                          mode 0755 -> 0777; more dangerous than before
critical  high        type_changed        <TMP>/lab/etc/app.conf
                                          type changed from file to symlink

2 findings (critical 2)
by kind: permission_changed 1, type_changed 1
complete: yes
[exit code 1]
```

Both changes are `critical`: a type change is one step more severe than the path's rule, and so
is a permission change that adds world-write.

## Commands

Every command exits with one of the [exit codes](#exit-codes) below. Monitored paths in a
configuration must be absolute or start with `~`; file paths on the command line may be relative.
No path may be a UNC or device path, a URL, or contain `..`, and the Windows name rules apply to
Windows paths only (see [What the tool reads and writes](#what-the-tool-reads-and-writes)).
There are no abbreviated options.

### `fim init-key`

Creates a random 32-byte HMAC key in a **new** file (mode `0600` on POSIX).

| Option | Meaning |
|---|---|
| `--key-file PATH` | Where to create the key file (required). |
| `--config FILE` | Optional: refuse a key path inside the monitored paths of this configuration. |
| `--force` | Replace an existing key file. |

The key is only ever passed around as a file path: never in argv, the environment, a log or an
error message. Keep it outside every monitored path, make a backup, and do not share it.

### `fim baseline`

Scans the monitored paths of a configuration, writes an HMAC-signed baseline, then updates the
rollback anchor next to the key.

| Option | Meaning |
|---|---|
| `--config FILE` | The configuration file (required). |
| `--baseline PATH` | The baseline file to write (required). |
| `--key-file PATH` | The key file; overrides `key_file` in the configuration. |
| `--force` | Replace an existing baseline. |
| `--allow-incomplete` | If a limit or the time budget stops the scan, still write the baseline, marked incomplete (exit code 4). |

Without `--allow-incomplete`, an incomplete scan writes nothing and leaves an existing baseline
and anchor untouched. A monitored path that is missing, unreadable, a symbolic link or a
reparse point is refused before anything is scanned.

### `fim check`

Verifies the baseline (signature first, then the rollback anchor), rescans the paths **the
baseline names** and reports what changed.

| Option | Meaning |
|---|---|
| `--baseline PATH` | The baseline to check against (required). |
| `--key-file PATH` | The key file; overrides `key_file` in the configuration. |
| `--config FILE` | Optional: the key location, and a `policy_drift` finding if its policy differs from the baseline's. It never changes what is scanned. |
| `--format table\|json\|jsonl\|csv` | Report format (default `table`). |
| `--output PATH` | Write the report to this new file instead of standard output. |
| `--force` | Replace an existing `--output` file. |
| `--min-severity info\|low\|medium\|high\|critical` | Hide findings below this severity (default `info`: nothing hidden). The exit code follows what is shown. |

A baseline that was itself made from an incomplete scan makes every check exit with code 4,
because it cannot prove the absence of changes.

### `fim watch`

Repeats `check` on an interval until it is stopped (Ctrl-C), and reports only what is new.

| Option | Meaning |
|---|---|
| `--baseline PATH` | The baseline to check against (required). |
| `--key-file PATH` | The key file; overrides `key_file` in the configuration. |
| `--config FILE` | Optional: the key location and the policy drift check. |
| `--interval SECONDS` | Pause between cycles, measured from the end of one cycle to the start of the next, so cycles never overlap (default `300`; 10 to 86 400). |
| `--max-cycles N` | Stop after N cycles (default: run until stopped). |
| `--repeat` | Report every finding in every cycle, not only new ones. |
| `--format jsonl\|csv` | Event format (default `jsonl`). |
| `--output PATH` | Append events to this new log file instead of standard output (no rotation). |
| `--force` | Replace an existing `--output` file. |
| `--min-severity info\|low\|medium\|high\|critical` | Hide findings below this severity (default `info`). |

The first cycle reports every finding; later cycles report only findings that are new, plus a
`resolved` event for each one that is no longer reported. The baseline file is verified again at
the start of every cycle: if it stops verifying, one critical `baseline_integrity` event is
raised, the last verified baseline stays in use, and the exit code is 3.

```
$ fim watch --baseline <TMP>\state\lab.baseline --key-file <TMP>\keys\fim.key --interval 10 --max-cycles 2
{"timestamp":"2026-10-10T18:55:07Z","host":"lab-01","message":"fim created [high] <TMP>\\lab\\bin\\helper.sh: new file, 13 bytes, sha256 d7ac283f0efbed24...","event_type":"fim.created","fim":{"kind":"created","severity":"high","confidence":"high","path":"<TMP>\\lab\\bin\\helper.sh","path_sha256":"2bb042da99c3bea625267b273481fb8b36efb126bf04c17a0ca2ed12d3a81d3a","path_truncated":"false","evidence":"new file, 13 bytes, sha256 d7ac283f0efbed24...","finding_id":"7350bca05780505c","baseline_sequence":1,"tool_version":"1.0.0","schema":"fim-event/1"}}
[3 more events, same shape, omitted here]
[stderr]
fim watch finished: 2 cycles, 4 events written
[exit code 1]
```

### `fim demo`

No options. See [Quick start](#quick-start-fim-demo).

### `fim --version`, `fim --help`

Print the version, or the usage. `fim COMMAND --help` describes one command.

## Configuration

```yaml
version: 1                      # required, the number 1
host_label: "lab-01"            # optional, stored in the baseline and in every event
key_file: "~/.config/fim/fim.key"
symlinks: never                 # never (default) | files
one_file_system: true           # default; do not descend into another device below a root
exclude: ["*.tmp", "**/__pycache__/**"]   # globs must be quoted: * starts a YAML alias
paths:
  - path: "/etc"
    severity: high              # info | low | medium (default) | high | critical
    exclude: ["mtab"]
  - path: "/home/lab/bin"
    severity: critical
    include: ["*"]
limits:
  max_files: 100000             # may only lower a value, or raise it up to its ceiling
```

- Roots must be absolute or start with `~` or `~/`; there is no environment-variable expansion
  and no default root: nothing is scanned that you did not name.
- The configuration is **not authenticated**. `check` and `watch` scan with the policy stored in
  the signed baseline; a configuration that differs only produces a `policy_drift` finding. Make
  a new baseline after you change the configuration on purpose.
- The loader refuses YAML aliases, anchors, tags, merge keys, duplicate keys and more than one
  document, and rejects unknown keys and values that YAML 1.1 turned into something else (an
  unquoted `yes`, `0755`, a date).
- Patterns match the path relative to its root with `/` separators. A pattern without `/`
  matches the base name at any depth; `**` spans directories; matching is case-sensitive on POSIX
  and case-insensitive on Windows. Excludes win over includes, and an excluded directory is not
  entered.
- `symlinks: never` records a link as a link (its text is compared); `files` also hashes a link
  that points at a regular file, but never enters a linked directory. Windows junctions and other
  reparse points are never followed or entered.
- Nested roots: every file is recorded once, under the most specific root.

### Limits

Every bound is a named constant with a hard ceiling in `fim/core/limits.py`. A configuration may
lower a value or raise it up to its ceiling, never above. Hitting a limit during a scan marks the
run incomplete (exit code 4); it is never reported as clean.

| Constant | Default | Hard ceiling |
|---|---|---|
| `MAX_ROOTS` | 64 | 64 |
| `MAX_FILES` (entries including directories) | 200 000 | 1 000 000 |
| `MAX_DEPTH` | 64 | 128 |
| `MAX_PATH_CHARS` | 4 096 | 4 096 |
| `MAX_HASH_FILE_BYTES` | 256 MiB | 4 GiB |
| `HASH_CHUNK_BYTES` | 1 MiB | - |
| `MAX_RUN_SECONDS` | 900 | 3 600 |
| `MAX_BASELINE_BYTES` | 128 MiB | 128 MiB |
| `MAX_CONFIG_BYTES` | 256 KiB | 256 KiB |
| `MAX_PATTERNS` / `MAX_PATTERN_CHARS` | 256 / 512 | same |
| `MAX_FINDINGS_REPORTED` | 10 000 | 10 000 |
| `MAX_EVIDENCE_CHARS` | 1 024 | 1 024 |
| `MAX_KEY_FILE_BYTES` | 4 096 | 4 096 |
| watch interval min / default / max | 10 / 300 / 86 400 s | - |

A test compares this table with the code. Files larger than `MAX_HASH_FILE_BYTES` are recorded
by size and modification time only, with lower confidence. `MAX_BASELINE_BYTES` is 128 MiB
because of a measurement: see [docs/performance.md](docs/performance.md). The limits are stored in
every baseline, so a baseline made under a limit above a ceiling is refused.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean and complete. |
| 1 | Findings were reported. |
| 2 | Usage, configuration or I/O error (including a missing baseline). |
| 3 | Baseline integrity failure: tampered, wrong key, unknown format, or rolled back. |
| 4 | Incomplete: a limit or the time budget stopped the run. |

Precedence when more than one applies: 3 > 2 > 4 > 1 > 0. An incomplete run still prints its
findings and says `complete: no`.

## Output formats

| Format | Where | Shape |
|---|---|---|
| `table` | `check` | Human-readable, shown above. Hostile names are escaped. |
| `json` | `check` | One document, `fim-report/1`: [docs/report-schema.md](docs/report-schema.md). |
| `jsonl` | `check`, `watch` | One JSON object per finding, `fim-event/1`, ASCII only: [docs/siem-mapping.md](docs/siem-mapping.md). |
| `csv` | `check`, `watch` | One row per finding, every cell quoted and formula-neutralised; lossy by design. |

For `jsonl` and `csv` the notes and warnings go to standard error, so standard output stays a
clean data stream.

## How the JSONL feeds mini-siem

`fim` was built beside a sibling project, mini-siem, and its JSONL shape is made to fit
mini-siem's generic JSON parser without changing mini-siem: `timestamp`, `host` and `message`
fill the typed fields, `event_type` becomes `fim.<kind>`, and every field under `fim` is
flattened into searchable attributes (`fim.kind`, `fim.severity`, `fim.path`, `fim.finding_id`,
and so on). `fim watch --output events.jsonl` writes an append log; mini-siem's `ingest --format
json` reads it.

[docs/siem-mapping.md](docs/siem-mapping.md) lists every field, the limits it was built to, and
the real ingest. A test keeps that document and the code in step. The mapping was checked
**once, by hand, on 2026-10-10** against mini-siem's parser as it was then; a later change in
mini-siem is not detected by anything in this repository.

## What the tool reads and writes

**Reads.** These, and nothing over the network.

| What | How | Bound |
|---|---|---|
| Monitored files and directories | Directories are listed; each entry is `lstat`ed; only regular files are opened, read-only, in 1 MiB chunks (POSIX: `O_NOFOLLOW`, `O_NONBLOCK`, `O_CLOEXEC`, and `O_NOATIME` on Linux when allowed). The open descriptor is compared with the earlier `lstat`. Link text is read with `readlink`. FIFOs, sockets and devices are described by `lstat` and never opened. | `MAX_FILES`, `MAX_DEPTH`, `MAX_HASH_FILE_BYTES`, `MAX_RUN_SECONDS` |
| The configuration file (`--config`) | No-follow read of a regular file. | `MAX_CONFIG_BYTES` |
| The key file | No-follow read; POSIX: refused unless only its owner can access it and the owner is the current user. | `MAX_KEY_FILE_BYTES` |
| The baseline file | No-follow read; size cap first, then the MAC, then the parser. | `MAX_BASELINE_BYTES` |
| The anchor file | No-follow read next to the key. | 1 024 bytes |
| Environment | `HOME` (POSIX) or `USERPROFILE` (Windows) for a leading `~`, and the machine name for the default host label. Never a key. | - |

Monitored files are **only read**. The tool never modifies, moves, renames, changes the mode of,
truncates or deletes one, and `fs/observe.py`, the only module that touches them, has no call that
could (the architecture check fails the build if one appears). Reading can update a file's access
time: on Linux the tool asks for `O_NOATIME`, which the kernel allows only for files you own, so
for other files, and on Windows, the file system's own access-time policy decides.

**Writes.** Only its own files, and only the ones you name.

| What | When | Mode | Rules |
|---|---|---|---|
| The key file | `init-key` | `0600` (POSIX) | New file; an existing one needs `--force`. |
| The baseline file | `baseline` | `0600` (POSIX) | New file; an existing one needs `--force`. |
| The rollback anchor `<key file>.<baseline id>.fim-anchor` | `baseline` | `0600` (POSIX) | Next to the key; replaced on every baseline; bound to the baseline file's path. |
| A report file | `check --output` | `0600` (POSIX) | New file; `--force` to replace. |
| An event log | `watch --output` | `0600` (POSIX) | New file, opened for append; `--force` to replace; no rotation. |
| A temporary file `.fim-<random>.tmp` | during any write above | `0600` (POSIX) | In the target's directory; removed afterwards. |
| The demo's directory | `demo` | - | One new directory under the system temporary directory; removed, and the removal verified. |

Every write: the path is checked first (no UNC, device or URL-like path, no reserved name, no
`..`, not inside a monitored root); data goes to a temporary file in the same directory that is
created exclusively and fsynced; **without `--force`** it is published with a hard link, which
fails if the target exists (no check-then-write race); **with `--force`** it replaces the target
with `os.replace`; a symbolic link or reparse point at the target is refused even with
`--force`, and nothing is ever written through a link. The tool's own output may not lie inside a
monitored path. On a file system without hard links (FAT, exFAT) the file is created directly
with an exclusive create and an fsync: still no clobbering, but not atomic.

On Windows the mode bits above are only the read-only attribute; the file inherits its ACL from
its directory, and the tool does not read or set ACLs.

## Security properties and the evidence for them

Each row names a test that holds the claim in place, or a document. A test checks that every
named test exists. The [threat model](docs/threat-model.md) puts the rows in context.

| Claim | Evidence |
|---|---|
| Monitored files are only read: never modified, moved, renamed, chmod-ed, truncated or deleted. | `tests/test_architecture_rules.py::test_a007_write_or_mutate_api_in_observe`, `tests/test_scanner_real.py::test_scanning_changes_nothing_about_any_file_or_directory`, `tests/test_check.py::test_check_never_changes_a_monitored_file_or_adds_one`, `tests/test_watch.py::test_the_watch_never_changes_a_monitored_file` |
| Only regular files are opened; FIFOs, sockets and devices are recorded by type. | `tests/test_scanner_virtual.py::test_special_files_are_described_and_never_opened`, `tests/test_observe.py::test_a_descriptor_that_is_not_a_regular_file_is_never_read`, `tests/test_observe.py::test_a_fifo_swapped_in_is_not_read_and_does_not_block` |
| Links, junctions and reparse points are recorded, never followed or entered. | `tests/test_scanner_real.py::test_symlinks_are_recorded_as_links_and_never_entered`, `tests/test_scanner_real.py::test_a_junction_is_a_reparse_point_that_is_never_entered`, `tests/test_check.py::test_a_file_replaced_by_a_symlink_is_a_type_change` |
| The tool's own files are written atomically, never through a link, and never over an existing file without `--force`. | `tests/test_safe_files.py::test_no_clobber_uses_a_hard_link_and_force_uses_replace`, `tests/test_safe_files.py::test_writing_never_goes_through_a_symlink_even_with_force`, `tests/test_safe_files.py::test_a_file_created_after_the_check_is_not_overwritten`, `tests/test_safe_files.py::test_the_temporary_file_is_removed_when_a_step_fails` |
| Hostile paths (UNC, device, URL-like, drive-relative, `..`) are refused before any I/O. | `tests/test_app_baseline.py::test_hostile_command_line_paths_are_refused_before_any_io`, `tests/test_safe_files.py::test_hostile_and_unsupported_paths_are_refused_everywhere`, `tests/test_safe_files.py::test_refusals_never_touch_the_filesystem` |
| A baseline that does not verify is refused with exit code 3 and is never parsed first. | `tests/test_baseline_codec.py::test_the_payload_parser_is_never_called_before_the_mac_verifies`, `tests/test_baseline_codec.py::test_one_flipped_byte_anywhere_in_the_payload_is_refused`, `tests/test_check.py::test_a_tampered_baseline_is_exit_3_through_the_cli` |
| A missing baseline is an error, never "no changes". | `tests/test_check.py::test_a_missing_baseline_is_exit_2_never_no_changes`, `tests/test_app_baseline.py::test_a_missing_baseline_is_an_error_never_no_changes` |
| An older, validly signed baseline put back is detected through the anchor; a deleted anchor is a warning only. | `tests/test_check.py::test_an_older_validly_signed_baseline_put_back_is_exit_3_a_rollback`, `tests/test_check.py::test_a_deleted_anchor_is_only_a_warning_and_the_check_runs`, `tests/test_baseline_codec.py::test_an_anchor_for_another_baseline_is_refused` |
| The configuration cannot narrow what `check` watches: the policy comes from the signed baseline. | `tests/test_check.py::test_a_configuration_that_adds_an_exclude_does_not_hide_changes_and_reports_drift` |
| The key never appears in argv, the environment, output, logs, errors, the baseline or the anchor; a key inside a monitored path is refused. | `tests/test_cli_commands.py::test_no_option_takes_a_key_value`, `tests/test_cli_commands.py::test_no_environment_variable_supplies_the_key`, `tests/test_app_baseline.py::test_the_key_appears_in_no_output_exception_baseline_anchor_or_log`, `tests/test_check.py::test_the_key_never_appears_in_any_output`, `tests/test_app_baseline.py::test_a_key_file_inside_a_monitored_root_is_refused_on_the_command_line` |
| On POSIX a key that group or others can access is refused. | `tests/test_safe_files.py::test_a_key_that_group_or_others_can_access_is_refused`, `tests/test_keystore.py::test_a_new_key_file_is_mode_0600_and_a_group_readable_one_is_refused` |
| Every file name, link target and other filesystem string is escaped before it is shown. | `tests/test_sanitize.py::test_every_codepoint_escapes_safely_and_round_trips`, `tests/test_check.py::test_a_hostile_file_name_is_escaped_in_the_table_and_the_json`, `tests/test_render_events.py::test_a_hostile_name_is_one_line_with_no_raw_control_or_bidi_character` |
| CSV cells that a spreadsheet could read as a formula are neutralised. | `tests/test_render_events.py::test_a_cell_that_could_be_a_formula_is_neutralised` |
| A file that changes, is swapped or vanishes while it is hashed becomes an issue (`unstable`, `vanished`), never a crash or a silent skip. | `tests/test_observe.py::test_a_file_replaced_by_another_during_the_scan_is_unstable`, `tests/test_observe.py::test_two_changed_passes_in_a_row_are_unstable_and_give_no_hash`, `tests/test_scanner_virtual.py::test_an_entry_that_disappears_between_listing_and_stat_is_vanished` |
| Every bound is a named limit with a hard ceiling; hitting one is exit code 4, never "clean". | `tests/test_limits.py::test_one_above_the_ceiling_is_refused`, `tests/test_scanner_virtual.py::test_hitting_a_limit_is_never_reported_as_complete_for_any_limit`, `tests/test_check.py::test_a_scan_that_hits_a_limit_is_exit_4_and_says_so` |
| The configuration loader refuses aliases, anchors, tags and other YAML tricks, and `yaml.load` is banned in the source. | `tests/test_config.py::test_expansion_bombs_never_get_far_enough_to_expand`, `tests/test_config.py::test_aliases_are_refused_with_a_hint_about_quoting_stars`, `tests/test_architecture_rules.py::test_a010_banned_module_builtin_or_api` |
| The source has no network, subprocess, `pickle`, `eval` or dynamic import, and the layers import only downwards. | `tests/test_architecture_rules.py::test_a010_banned_module_builtin_or_api`, `tests/test_architecture_core.py::test_the_real_source_tree_passes` |
| `fim demo` touches only its own temporary directory and removes it, also when a step fails. | `tests/test_demo.py::test_the_demo_touches_only_its_own_directory_and_leaves_the_base_as_it_found_it`, `tests/test_demo.py::test_a_step_that_raises_still_removes_the_directory`, `tests/test_demo.py::test_smoke_demo_runs_finds_the_changes_refuses_the_tampered_baseline_and_cleans_up` |
| `watch` reports new findings once, resolves them, never overlaps cycles, and raises a baseline that stops verifying. | `tests/test_watch.py::test_the_first_cycle_reports_every_finding_and_later_cycles_only_new_ones`, `tests/test_watch.py::test_cycles_are_one_interval_apart_and_never_overlap`, `tests/test_watch.py::test_a_tampered_baseline_mid_watch_is_one_critical_event_and_exit_3` |
| The documented JSON, JSONL and CSV fields are exactly the ones the code writes. | `tests/test_render.py::test_the_schema_document_lists_exactly_the_fields_the_code_writes`, `tests/test_render_events.py::test_the_document_lists_exactly_the_fields_the_code_writes`, `tests/test_render_events.py::test_the_document_lists_exactly_the_csv_columns` |
| The limits, exit codes, defaults and watch interval quoted in this README are those of the code. | `tests/test_docs.py::test_the_readme_limits_table_matches_limits_py`, `tests/test_docs.py::test_the_readme_exit_codes_match_the_code`, `tests/test_docs.py::test_every_cli_option_and_default_is_documented_in_the_readme` |
| No key, baseline, anchor, log, email address or bidi, zero-width or control character is in the repository. | `tests/test_hygiene.py::test_no_key_baseline_or_secret_file_is_tracked_or_visible`, `tests/test_hygiene.py::test_repository_files_have_no_hostile_characters_or_emails`, `tests/test_hygiene.py::test_commit_messages_have_no_email_addresses` |
| The performance numbers were measured, with the machine and the command stated, and the README quotes only those. | `docs/performance.md`, `scripts/bench.py`, `tests/test_docs.py::test_performance_md_states_its_machine_and_a_command_for_every_table`, `tests/test_docs.py::test_the_numbers_in_the_readme_performance_table_appear_in_performance_md` |
| The threat model's controls each name a test that exists. | `docs/threat-model.md`, `tests/test_docs.py::test_every_test_named_in_the_documents_exists` |

## Limitations

These are the things `fim` does not do or cannot promise. They are also listed, with the
reasoning, in [docs/threat-model.md](docs/threat-model.md).

- **Polling.** `check` and `watch` compare two moments. A change made and undone between two
  runs, or a file that exists only for a few seconds, is never seen. The default interval is
  300 seconds.
- **What is recorded.** Type, size, modification time, SHA-256, POSIX permission bits, uid and
  gid, link count, link target. Not recorded: Windows ACLs and owners, NTFS alternate data
  streams, POSIX ACLs, extended attributes, file capabilities, SELinux labels. A change to
  one of those is invisible. On Windows only the READONLY, HIDDEN and SYSTEM attributes are kept.
- **A same-privilege attacker can forge baselines.** Whoever can read the key can write a
  baseline that verifies, and an anchor to match. Run the monitor and keep the key under a
  separate account or on separate media.
- **The rollback anchor is a warning, not a wall.** An attacker who can write to the key
  directory can delete the anchor; `check` then warns that none was found and goes on, so an
  older validly signed baseline put back in place goes unnoticed. The same warning appears
  when a baseline file is moved or renamed, because the anchor is bound to the baseline's path
  (the next `fim baseline` writes a new one).
- **`key_file` in the configuration is trusted.** Someone who can edit the configuration and the
  baseline can point `check` at a key of their own. Pass `--key-file` from a place the watched
  account cannot write.
- **Access times.** Reading a file can update its access time (see above); this is documented,
  not hidden.
- **Confusable and blank-looking glyphs.** Names are escaped for controls, bidi and
  zero-width characters, separators and unassigned code points, but a Cyrillic "a" in a Latin
  name still looks like the Latin one, and a few letters and symbols render blank (Hangul
  filler U+3164, Braille blank U+2800). The escaped table is for reading; `path_sha256` in the
  JSONL identifies the exact path.
- **The key file's ACL is not verified on Windows.** On POSIX a key that others can access is
  refused; on Windows the tool cannot judge, so keep the key in a directory only you can read.
- **Temporary files.** A crash (power loss, `kill -9`) between creating a temporary file and
  removing it can leave a `.fim-<random>.tmp` file in the target's directory. For a key, that is
  a copy of the key.
- **File systems without hard links (FAT, exFAT).** The no-clobber write falls back to an
  exclusive create: a crash can leave a partial file.
- **A parent directory swapped between the checks and the write** is a documented residual
  race; on Windows the open of a monitored file follows links and relies on the device and
  inode comparison, which reports a swap as `unstable`.
- **Mapped network drives** are not recognised as such, so `one_file_system` does not stop at
  them. A path on a hung network mount can hang the scan.
- **Hashing limits.** A file above `MAX_HASH_FILE_BYTES` is compared by size and time only.
  Windows cloud placeholders (offline files) are never opened.
- **Memory.** A baseline is loaded whole and needs about six times its size in memory while it
  is parsed: a `check` with a 119.1 MiB baseline (400,409 records) peaked at 740.8 MiB, which is
  why `MAX_BASELINE_BYTES` is 128 MiB. `watch` pays that peak every cycle.
- **The first baseline of many new files can exceed the time budget.** On the measured machine,
  with real-time malware protection on, the first baseline of 100,000 files that had just been
  written took 1212.18 s (about 12 ms a file) and the default budget of 900 s stopped it as
  incomplete (exit code 4, nothing written). Raise `max_run_seconds` in the configuration (up to
  3 600) for such a first run.
- **`watch` log.** The append log is fsynced once per batch and never rotated; a power cut can
  lose the batch in flight. `watch` keeps at most `MAX_FINDINGS_REPORTED` finding ids; beyond that
  the extra findings cannot be tracked as new or resolved, and a note says so.
- **The mini-siem mapping was verified once, by hand, on Windows**, on 2026-10-10. A test keeps
  the document in step with this repository's code; nothing watches mini-siem.
- **Platforms.** Windows 11 and Ubuntu are tested; macOS is not. CI runs Python 3.11 to 3.13 on
  both operating systems. The Linux checks I ran in WSL use Python 3.14 only, so they find
  operating-system differences, not Python-version ones.
- **Measured on one machine.** Every number in this README comes from one laptop (see
  [docs/performance.md](docs/performance.md)); yours will differ.

## Performance

Measured on one Windows 11 laptop (Intel Core Ultra 7 155U, 31.5 GiB RAM, NVMe SSD, Python
3.13.14) on 2026-10-10 with `python scripts/bench.py all`. The tables, the method and the commands
are in [docs/performance.md](docs/performance.md); the numbers below are copied from there, and a
test checks that each one appears there.

| What | Measured |
|---|---|
| Later `baseline` and `check` of 100,000 files of 1 KiB (101,021 records), median of three | 25.46 s and 27.49 s: 3,968 and 3,675 records a second |
| The first `baseline` of those files, just written, with real-time malware protection on | 1212.18 s: longer than the default 900 s budget, which stops it as incomplete (exit code 4) |
| `baseline` of one 256 MiB file, median of three | 0.28 s: 905 MiB/s |
| Python memory (`tracemalloc` peak), `baseline` and `check` of 100,000 files | 143.8 MiB and 165.7 MiB |
| Peak working set of a `check` with a 119.1 MiB baseline (400,409 records) | 740.8 MiB |
| Peak working set of loading a 238.2 MiB baseline, under the old 256 MiB limit | 1453.6 MiB, which is why the limit is now 128 MiB |

These are small files on warm caches on one machine: they show the order of magnitude, not a
promise.

## Development

```
uv venv --python 3.13 .venv              # or: py -3.13 -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[dev]"
python scripts/gate.py                   # fast gate (ruff, mypy, architecture, pytest, coverage)
python scripts/gate.py --full            # everything, as CI runs it
python scripts/bench.py all              # the measurements in docs/performance.md
```

The gate runs `ruff check`, `ruff format --check`, `mypy --strict` for Linux and Windows, an
architecture checker that enforces the layer rules and the "filesystem APIs only in `fs/`" rule,
and `pytest` with branch coverage (85 % minimum). The working rules are in
[CLAUDE.md](CLAUDE.md), the design and its decisions in [PLAN.md](PLAN.md), the history of each
phase in [docs/phase-reports.md](docs/phase-reports.md).

## Documents

- [docs/threat-model.md](docs/threat-model.md): assets, actors, controls, residual risk.
- [docs/performance.md](docs/performance.md): measured throughput and memory, with the commands.
- [docs/report-schema.md](docs/report-schema.md): the JSON report.
- [docs/siem-mapping.md](docs/siem-mapping.md): the JSONL and CSV fields and mini-siem.
- [CHANGELOG.md](CHANGELOG.md), [SECURITY.md](SECURITY.md), [LICENSE](LICENSE).

## Licence

MIT, see [LICENSE](LICENSE).
