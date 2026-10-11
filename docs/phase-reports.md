# Phase reports

One entry per phase, newest last, each ending with the five-line report required by CLAUDE.md
section 2. The last entry is what a new session reads first.

## In progress

Nothing is in progress. Phase 6 is complete, pushed, and CI run #9 was green on all six jobs.
The release-readiness pass of 2026-10-11 (last entry) answers the five open questions at the end
of the Phase 6 entry and is committed locally; nothing was pushed or tagged. What is left is
yours: push, check Actions, tag v1.0.0 and publish the release. Before any later phase or fix
is reported done: the full gate on Windows and, through WSL, on Linux (CLAUDE.md section 3).

Accepted by the owner: the deviations of v0.3.7 and v0.3.6 (on 2026-10-10, PLAN.md changelog
v0.3.8), the Phase 3 deviations of v0.3.4 except the incomplete-scan one (changed in v0.3.5), all
Phase 2 deviations (v0.3.2, v0.3.3).

Resolved in Phase 6, Step 0: the wording of invariant 3 (Windows name rules apply to
Windows paths only).

## Phase 1 - Foundation, gate, CI, pure core (2026-10-08)

Built: git repo on main with the approved plan (PLAN.md v0.2, CLAUDE.md fixed: the raw U+202E is now the six characters \u202e); .venv on Python 3.13; pyproject.toml (hatchling, MIT, PyYAML as the only runtime dependency, ruff, mypy strict checked for 3.11 on linux and win32, pytest markers, branch coverage 85%); scripts/gate.py (six steps in order, keeps going after a failure, --full, --log); scripts/check_architecture.py (layer table, import cycles including function-level and TYPE_CHECKING imports, filesystem default-deny, read-only observe.py, clock access, third-party and banned APIs, assert, print, core purity, sandbox importer restriction, fails closed; rule ids A001-A015); .github/workflows/ci.yml (ubuntu-24.04 and windows-latest x Python 3.11/3.12/3.13, read-only permissions, concurrency cancel, 15 min timeout, runs gate --full); `fim --version`; core/limits.py (D11 values, hard ceilings, validated overrides), core/errors.py (error hierarchy, ExitCode, precedence 3>2>4>1>0), core/clock.py (Clock and Sleeper protocols), core/sanitize.py (D10 reversible escaping, scrub, clip, CSV neutralising), core/pathrules.py (UNC, device, reserved-name, drive-relative, ADS, URL-like refusal for both OS flavours; containment; root-relative "/" record paths and display without doubled backslashes), core/models.py (PLAN section 2 as self-checking frozen dataclasses); README and SECURITY stubs without claims; LICENSE.
Tests added: 907 collected (905 in the default gate, 2 slow): architecture checker 185 (every rule id has planted violations and allowed-code counterexamples, the real tree passes, mutation-checked: with the usage rules disabled, 134 of the 151 rule tests fail and only the 17 must-stay-clean ones pass), sanitiser 137 (escape table, injectivity over an adversarial alphabet, seeded round trips, 27 non-canonical inputs refused, exhaustive sweep of all 1,114,112 code points as slow), pathrules 205, models 93 (including drift of vocabularies and field names against PLAN.md), limits 83 (including drift of the D11 table), errors 49 (including drift of section 1.5 and the full precedence table), hygiene 86 (bidi/zero-width/control/BOM/surrogate characters, secret names and headers, email patterns, planted git repos; run on the real repo including CLAUDE.md and PLAN.md), CI policy 28 (parsed workflow plus 21 planted violations), project config 14, gate 12, CLI 8, clock 7.
Real coverage: 100.00% branch coverage (670 statements, 202 branches, 0 missing) as printed by the gate on the default run; the gate enforces a minimum of 85%. It measures src/fim only, which so far is the pure core and the CLI; there is no I/O code yet. Default gate (this machine, Windows, Python 3.13.14): 905 passed, 24.9 s in total of which pytest 21.4 s (earlier runs 21-25 s); full gate (CI mode): 907 passed, 47.7 s and 50.9 s in total in two runs.
Known gaps: (1) CI not yet run: locally only Windows with Python 3.13.14 was exercised; Python 3.11/3.12 and Linux are covered only by mypy (python_version 3.11, --platform linux) because the single-venv rule forbids a second venv. (2) Escaping of unassigned (Cn) and newly assigned format characters depends on the running Python's Unicode tables, so a baseline written under one Python could escape such a character differently under another; decide before Phase 3 (record unicodedata.unidata_version in the baseline header, or embed a frozen table). (3) The test guard that fails any test passing a path outside the pytest temp base to fs/observe.py and fs/safe_files.py is not built because those modules do not exist yet (Phases 2 and 3); the table-output test for "no doubled backslashes" belongs to Phase 4 (Phase 1 tests the display function it will use). (4) The architecture checker is a static, name-based lint, not a sandbox: it cannot see getattr on non-os objects or a shadowed builtin, and its `.open()` rule can flag harmless methods. (5) ruff and mypy versions are not pinned, so an upstream rule change can fail CI without a code change; there is no lockfile. (6) Policy, RootPolicy and BaselineHeader shapes are untested against a real configuration and may be refined in Phase 2. (7) Hygiene detection of the rollback anchor file (D3 amendment) arrives with Phase 3.
Deviations from PLAN.md: all awaiting your acceptance, also recorded in the PLAN.md changelog (v0.2.1): (1) escape also covers lone surrogates outside U+DC80..U+DCFF as \uXXXX, which D10 does not list; reason: JSON ensure_ascii would emit them and mini-siem rejects lone surrogates. (2) `..` components are refused in every user-supplied path; reason: a lexical check cannot know whether the part before `..` is a symlink; side effect: `--output ../x.json` must be written without `..`. (3) The checker bans slightly more than CLAUDE.md lists: ctypes, builtins, sys.modules, `.open()` calls outside fs/, more archive/database modules outside fs/, and literal integer flags in os.open inside observe.py. (4) Added .gitattributes (eol=lf) so Windows and Linux checkouts hash and scan identical bytes. (5) core/errors.py has the exit-code precedence function and core/limits.py has the validated Limits dataclass, both earlier than the phases that use them. (6) Ruff ignore S311 for tests only (seeded random.Random for reproducible data). (7) Tests read the repository read-only for the hygiene and drift checks, which CLAUDE.md section 6 requires and its "never scan the repo" rule does not distinguish. (8) CI action majors are as in D13 (checkout v4, setup-python v5) and unverified against newer ones. (9) Consistency edits to Phase 3 scope, the Phase 6 Limitations list and the threat-model rollback row to match the D3 amendment (already in changelog v0.2).

## Phase 2 - Config, globs, observation and scanning (2026-10-08)

Preparatory commits (owner's STEP 1): v0.2.1 deviations marked accepted in the PLAN.md changelog; decision D14 added (record paths are stored exactly and serialised only by canonical JSON with ensure_ascii, the sanitiser is display-only) with D10 and D3 amended, `core/canonical.py`, `FileRecord.path` and `link_target` now exact text, and a test that storage keys are identical under simulated Unicode 14.0, 15.0 and 15.1 tables (15 code points that were unassigned in the older versions; the tables are simulated by patching `unicodedata.category`, because only one Python is installed); dev tools pinned to compatible ranges with a test; `*.log` was already ignored and no log was tracked, a hygiene test now holds both.

Built: core/globs.py (segment-wise matcher, state simulation instead of backtracking, `**`, sets, case rule per OS); core/perms.py (raw st_mode, Windows attributes and reparse tags to EntryType, tracked attribute bits, offline test); core/canonical.py; core/policy.py (policy digest, rule compilation, nested roots, most specific owner) and `expand_tilde` in core/pathrules.py; platform/clock.py (SystemClock, SystemSleeper); services/config.py (strict SafeLoader subclass driven directly, no aliases, anchors, tags, merge keys or duplicate keys, size cap, invisible-character scan, strict schema, limits only up to their ceilings, key_file not inside a monitored root); fs/observe.py (read-only lstat, stat, readlink, bounded sorted listing, hashing with fstat identity check, one retry, budget callback, injectable ReadOps); services/scanner.py (iterative walk, sorted entries, links and reparse points recorded and never followed, mount boundary, loop guard, nested roots, include and exclude pruning, file/depth/path/time limits that mark the run incomplete, every per-entry error a ScanIssue); the pytest path guard for fs/ (tests/path_guard.py, installed by an autouse fixture) with a test that proves it trips; tests/fakefs.py (virtual tree) and tests/winhelp.py (junctions and attributes, test-only).
Tests added: 1497 collected now against 907 after Phase 1, so 590 more (1477 pass and 16 skip in the default gate, 4 slow run only with --full: 1481 pass in the full gate). New files: config 153 (every invalid shape refused with a clear message), globs 100 (table, case rules, refused patterns, fnmatch oracle on 3000 seeded cases, exponential patterns), scanner on a virtual tree 83 (every branch, every HashStatus and IssueKind produced), observe 67 (real files, scripted descriptors, open flags checked on every OS), perms 61 (synthetic ints), policy 46 (pinned digest, nesting), scanner on real trees 31 (read-only invariant comparing content hash, size, mtime_ns, ctime, mode, link count and attributes before and after, junctions, failures injected into the real reader, 20k files as slow), canonical 23 (including D14), path guard 14, platform clock 4, plus edits to models, pathrules, hygiene and project-config tests.
Real coverage: 100.00% branch coverage (1616 statements, 546 branches, 0 missing) as printed by the gate on the default run, Windows, Python 3.13.14; the platform-specific branches of observe.py are reached on this machine by substituting sys.platform and os.open in tests, and the symlink and POSIX-only paths by the virtual tree, so the number does not show that the real symlink and POSIX tests passed (see gaps). Default gate, last two runs before the documentation commit: 21.5 s and 25.1 s in total, pytest 17.3 s and 21.1 s (earlier runs in this phase took 22 to 46 s when the machine was busy); full gate: 231.6 s in total, pytest 226.5 s, 1481 passed.
Known gaps: (1) 16 tests are skipped on this machine (8 requires_symlinks because this account cannot create symlinks, 8 posix_only: FIFO, chmod 000, setuid bits, undecodable file names, listing a locked directory); the scanner's link handling is covered here only by the virtual tree and by `observe` unit tests with substituted flags, so the first real run of those tests is the Linux CI job. (2) The 20k-file slow test takes about 210 s here: the scan itself is not the cost. Measured with ad hoc scripts (not yet in docs/performance.md, which is Phase 6): creating 20,000 files took 9.3 s, the first scan took 195 s of which `os.open` was 4.6 ms per freshly created file (cProfile on 2,000 files: 9.2 of 10.1 s inside nt.open; Windows Defender real-time protection is on), and a second scan of the same files took 0.17 s for 2,021 entries. (3) A root that is a link is only an issue so far; `baseline` must refuse in Phase 3. (4) Windows long paths over 260 characters and file systems without stable file ids are not specially handled: the (device, inode) identity check compares what lstat and fstat report, and a loop guard is skipped when the inode is 0. (5) The path guard checks the path as given, so a link inside the temporary directory that points outside is not caught when `files` policy hashing follows it. (6) Display escaping still depends on the running Python's Unicode tables, by design (D14); only storage is table-independent. (7) A root path containing an invisible or control character is refused by the path rules, so such a directory cannot be monitored directly. (8) The architecture checker's SAME_LAYER_ALLOWED table gained entries for canonical, globs, perms and policy; the checker still is a static lint, not a sandbox. (9) Phase 1 known gaps 2 and 5 are closed (D14, pinned dev tools); gap 3 is closed for observe.py and stays open for safe_files.py until Phase 3; gap 6 (shapes untested against a real configuration) is closed for Policy and RootPolicy by the config and scanner tests.
Deviations from PLAN.md: all awaiting your acceptance, also recorded in the PLAN.md changelog (v0.3.2): (1) core/canonical.py and the policy digest were built now because D14 and the digest need them; (2) RECALL_ON_OPEN counts as offline too; (3) glob and config clarifications: trailing `**` matches the directory itself, `[...]` is the only way to match a metacharacter, leading or trailing `/` and backslash are refused, include applies to non-directories only, max_patterns counts all patterns together; (4) the config loader takes bytes and checks key_file against the roots already; (5) a link or reparse point as a root is a root_unavailable issue, not an exception; (6) the FileSystemView seam in the scanner; (7) directory records keep mode, uid, gid but size 0 and nlink 1; (8) a directory reached twice is entered once and the run is incomplete; (9) the `requires_non_root` marker. Process lapse, reported plainly: while committing the first preparatory change I redirected the gate output to /dev/null once, against the GATE DISCIPLINE rule; I noticed at once and re-ran the gate plainly before the commit. Every other gate run was plain or used --log.

CI follow-up to Phase 2: the first CI run was green on Linux (3.11, 3.12, 3.13) and red on
Windows (all three Pythons, 3 tests, the first real Windows run of the symlink tests): `os.readlink`
returns an absolute target with the extended-length prefix. Fixed by the D6/D14 rule that link
targets are stored exactly and the prefix is stripped only for display
(`core/pathrules.display_link_target`, with a pure unit test file that runs on every OS). The three
tests now assert the real Windows value. With Windows Developer Mode enabled the 8 symlink tests
run on the development machine; 8 POSIX-only tests are still skipped there.

## Phase 3 - Key, baseline format, `init-key` and `baseline` (2026-10-09)

Step 0, gate speed (before any Phase 3 code). The default gate measured 47.6 s in total (pytest 38.6 s) at the start of the session. `pytest --durations` (run directly, because the gate has no durations option and its output must not be filtered) shows no slow test: the slowest is 0.83 s (`test_config.py::test_absurd_nesting_is_a_config_error_not_a_crash`), the next 0.30 s, so nothing qualified for `@pytest.mark.slow`. The cost was fixture setup: 15.3 s of the roughly 19 s of measured test time was `setup`, over 1381 tests. The symlink tests are not the cause (about 16 of 1500 tests, each quick). Windows Defender is the likely reason that setup is expensive here (the autouse fixture created and later deleted six directories per test, thousands of directories per run, and pytest deletes the previous run's directories at the start of the next), but I did not turn Defender off to prove it. Change, in `tests/conftest.py`: the fake home directories are created once per run (session scope), every test only points the environment variables at them, and a teardown check fails any test that wrote into them. Measured back to back, pytest alone without coverage went from 22.5 s to 12.7 s (two runs: 12.50 s and 12.88 s); the gate total was 24.5 s right after the change. Gate totals on this machine vary a lot between runs (21 to 50 s in Phase 2), so compare the pytest-only numbers, not the totals. Process lapse, reported plainly: for that first Step 0 run I piped the gate through `tail -25`, which the GATE DISCIPLINE forbids; the summary it printed is the gate's own, and every later gate run was plain or used `--log`. Committed on its own as 63b996c.

Built: `fs/safe_files.py` (the only reader and writer of the tool's own files: path rules first, monitored-root refusal compared as text and after resolving links in the directory part, `lstat` then no-follow open then descriptor identity check, size cap before reading, POSIX private-file check, exclusive 0600 temporary file, hard-link publish without `--force` and `os.replace` with it, links and reparse points refused even with `--force`, temporary file removed on every path, `ensure_can_write` for early failure); `services/keystore.py` (strict key file grammar, redacted `Key` type, `key_id`, `init_key`, `load_key`, anchor file bytes); `services/baseline_codec.py` (envelope plus canonical payload, MAC with domain separation, decode order: size cap, envelope, format and version, key id, constant-time MAC, and only then the payload parser, every failure a `BaselineIntegrityError`; the rollback anchor as signed text with `decode_anchor`, `next_sequence` and `verify_against_anchor`); `platform/hostinfo.py`; `app/baseline.py` (`run_init_key`, `run_baseline`, `read_config`, `read_verified_baseline`); CLI `init-key` and `baseline` with `--force`, exit codes 0/2/3/4 mapped from the error classes, stdout and stderr set to `backslashreplace`; `core/perms.private_file_problem`, `core/pathrules.display_user_path`, error classes `FileAccessError` and `FileMissingError`; the hygiene tests recognise the anchor by its header and `.gitignore` lists `*.fim-anchor`. Real run in a temp directory: `init-key`, `baseline` (sequence 1, anchor created), a second `baseline` (exit 2, "already exists; use --force"), `baseline --force` (sequence 2, anchor updated).
Tests added: 1949 collected now against 1518 at the start of this session, so 431 more (1932 pass and 12 skip in the default gate, 5 slow; the only new slow test is the subprocess end-to-end one). New files: baseline codec 150 (one byte flipped at every position of the envelope and of the payload, every payload field mutated, truncation, trailing bytes, wrong key, unknown version and format, oversize, the parser spy proving it never runs before the MAC verifies and that JSON is applied only to the 1 KiB envelope before that, a signature rebuilt from the documented formula, the golden file, anchor cases including domain separation and rollback), safe_files 95, app baseline 59 (real temp trees: symlink, junction, missing roots, existing baseline without `--force` with the scan proven not to run, outputs and keys inside a root, incomplete scan, oversize baseline, tampered and wrong-key anchors, anchor write failure and repair, the key never in outputs, exceptions, files, logs, environment or argv), keystore 50, CLI commands 28 (including a proof that no option takes a key value and that environment variables are not a key source), hostinfo 16; additions to perms (+23), hygiene (+4), pathrules (+6) and errors (+2).
Real coverage: 100.00% branch coverage (2352 statements, 730 branches, 0 missing) as printed by the gate on the default run, Windows, Python 3.13.14. 4 of the 12 skipped tests are new and POSIX-only, so the POSIX-only lines of `safe_files.py` (mode 0600 on disk, the real group-readable refusal, the FIFO) are reached here only through substituted `sys.platform`, `os.geteuid` and flag values, not through a real POSIX run. Default gate (the three runs after the last code change, plain or with --log): 30.4 s, 35.0 s and 36.4 s in total, pytest 29 to 31 s with coverage; pytest alone without coverage 16.7 s and 18.1 s. The default gate stays well under the 60 s target.
Known gaps: (1) 12 tests are skipped on this machine (8 from Phase 2 and 4 new, all `posix_only`); the first real run of those is the Linux CI job. While reading the Linux paths I found and fixed one test bug (key files written with plain `write_bytes` would be mode 0644 and be refused as not private before their content was checked), but I could not run the fix on Linux. (2) The golden file test pins the canonical bytes for Python 3.13 only here; Python 3.11 and 3.12 are checked by CI, not by me. (3) The hard-link publish needs a file system with hard links: a key or baseline on FAT or exFAT (the removable media that D2 recommends) fails with "the file system may not support hard links" instead of falling back; this needs your decision. (4) One anchor per key: two baselines sharing a key make `check` report a rollback mismatch for the one that was not written last; use one key per baseline (the error message says so, the README does not yet). (5) `baseline` notices an unavailable root only after the scan, so a huge tree is scanned before the refusal. (6) A parent directory swapped for a link between the checks and the rename is a documented residual risk, and the monitored-root check compares text and resolved directory parts, not 8.3 short names. (7) The Windows key ACL is not verified (D7), and the anchor file, unlike the key, is not required to be private. (8) The tamper cases exit 3 at the app level (`read_verified_baseline`), and the error-to-exit-code mapping is tested through the CLI by injection; a real `fim check` against a tampered baseline file arrives with Phase 4, and the only real exit 3 through the CLI today is a tampered anchor during `baseline --force`. (9) The baseline is built and parsed fully in memory; memory near `MAX_BASELINE_BYTES` is a Phase 6 measurement (D11 amendment). (10) Phase 2 gaps still stand, except that gap 3 (a root that is a link) and the `safe_files` half of gap 9 are now closed. (11) Commit size: the work was done in one pass and the gate was green only on the whole tree, so Phase 3 is one code commit instead of several small slices.
Deviations from PLAN.md: all awaiting your acceptance, also recorded in the PLAN.md changelog (v0.3.4): (1) the anchor is one file per key, named after the key file plus `.fim-anchor`, in a five-line text format instead of JSON, so it is parsed without a JSON parser before its MAC verifies; (2) `baseline` refuses (exit 2) for every `root_unavailable` issue, not only links, as v0.3.2 item 5 asked; (3) an incomplete scan still writes the baseline (header `complete: false`) and exits 4; (4) the baseline is written before the anchor, so a failure between them is repaired by `fim baseline --force`; (5) strict key grammar (LF only, lower-case hex) and no error quotes file content; (6) `init-key --config` is optional and only refuses a key inside the monitored paths, `--key-file` overrides the configuration, argparse abbreviations are off; (7) the append-log writer of section 1.4 waits for `watch` in Phase 5; (8) no fallback for file systems without hard links (gap 3); (9) `read_verified_baseline` was built ahead of Phase 4; (10) small additions: `FileAccessError`, `FileMissingError`, `private_file_problem`, `display_user_path`, `platform/hostinfo.py`; (11) the session-scoped fake home in the test fixtures, and the golden payload under `tests/data`.

## Phase 4 - Diff, `check`, table and JSON output (2026-10-09)

Step 1, preparatory commits (each through the gate, after the Phase 3 push): (a) `fd8ba5b` the gate guard hook. `.claude/settings.json` registers one PreToolUse hook, matcher `Bash`, command `python "$CLAUDE_PROJECT_DIR/scripts/hooks/guard_gate.py"`; the script reads the hook JSON from stdin and exits 2 with a clear message when a command that runs `scripts/gate.py` also has a pipe, a redirect (including `2>&1`), `|| true`, `; true`, or tail, head, tee, Select-String and their kin; text inside quotes is data, so `python scripts/gate.py && git commit -m "..."` with a message that mentions a pipe is allowed, and a quoted `bash -c "... gate.py | tail"` is still caught. 71 tests (allowed and blocked commands, protocol, the settings file). The hook fired on my own commands several times in this session (it also caught a false positive on `guard_gate.py` containing "gate.py", fixed by matching the whole file name). (b) `911297c` incomplete scan: `fim baseline` writes nothing and exits 4 by default, `--allow-incomplete` writes the baseline with `complete: false` and still exits 4 (PLAN.md v0.3.5). (c) `4785638`, `731493b` anchor per baseline: the anchor is `<key file>.<baseline id>.fim-anchor`, the id is the first 16 hex of SHA-256 over the baseline file's identity (absolute path, links in the directory part resolved, case-folded on Windows) and is inside the signed record (`FIM-ANCHOR v2`), so one key protects several baselines and an anchor copied to another baseline's name is refused; moving a baseline file leaves it without an anchor, which is a warning. (d) `6056857` FAT/exFAT: when the hard-link publish fails with a "no hard links" error the final file is created directly with `O_CREAT | O_EXCL` and an fsync (no-clobber kept, atomicity not, documented in PLAN.md section 1.4 and Limitations); other link failures and `--force` never fall back. (e) `18ef27b` `fim baseline` checks every root (exists, file or directory, not a link or reparse point) before the key, the anchor or the scan.

Built (Phase 4, commit `5a5e20c`): `core/diff.py` (section 2 rules, D8 severity and confidence, rename hints, unavailable roots counted as suppressed, low confidence for a missing file when the scan was incomplete or a parent directory was unreadable, scan problems as `unreadable`/`unstable`/`vanished` findings, policy drift, finding ids from the exact unescaped facts, `build_report` with `--min-severity` filtering, deterministic order and exact counts when the list is cut at `MAX_FINDINGS_REPORTED`); `render/table.py` and `render/json_out.py` (pure, scrubbed, ASCII-only JSON); `docs/report-schema.md`; `app/check.py` (key, then size cap, MAC and rollback anchor via `read_verified_baseline`, then scan with the baseline's policy, drift against `--config`, atomic `--output`); CLI `check` with `--format table|json`, `--output`, `--force`, `--min-severity`. A real run in a temp directory (a modified, a deleted and a created file) printed a three-finding table with single-backslash Windows paths and exit 1, and the JSON form.
Tests added: 2255 collected now against 1949 after Phase 3, so 306 more (2235 pass and 14 skip in the default gate, 6 slow). New or extended files: diff 102 (one test per finding kind and per severity/confidence rule, setuid, setgid and world-write escalation, Windows READONLY on a SYSTEM file, file to symlink, link target change, same-hash rename, missing root, incomplete scan, hostile names, finding id stability), render 34 (table, JSON, validation against the documented schema with hand-written checks, a drift test between docs/report-schema.md and the code, and the D10 test that a Windows path never shows doubled backslashes), check 51 (the full flow init-key, baseline, change files, check with the expected findings and exit codes; exit 3 through the CLI for a tampered baseline, every damage kind, wrong key, wrong key id, oversize, rollback to an older signed baseline and a tampered anchor; missing anchor as a warning; missing baseline exit 2; exit 4; policy drift without hiding changes; `--output` rules; hostile names; cp1252 console), guard hook 71, plus additions to safe_files (+16), app baseline (+14), keystore, codec and scanner virtual tests.
Real coverage: 100.00% branch coverage (2855 statements, 886 branches, 0 missing) as printed by the gate on the default run, Windows, Python 3.13.14. Default gate: 53.2 s in total (pytest 47.4 s) in the last run; pytest alone about 28 s. No single test is slow (the slowest is 1.3 s, the rest is spread over about 2250 tests and Windows file-system cost), but the total is near the 60 s target.
Known gaps: (1) 14 tests are skipped on this machine (POSIX-only: 8 from Phase 2, 4 from Phase 3, 2 new in check for a newline and an undecodable file name); their first real run is Linux CI. (2) The hook covers the Bash tool only (the PowerShell tool is not matched), it is a lexical check that variables or `eval` could evade, and I could verify it only inside this session. (3) A baseline made on one OS family checked on another (Windows roots on Linux) is not specially handled: the roots come out as unavailable and are reported, but that path has no test. (4) `check` hashes every file every time (no incremental mode); the throughput is a Phase 6 measurement. (5) A file touched back to the same content is invisible by design (only its mtime changed, counted in `mtime_only_changes`). (6) The default gate drifts toward 60 s. (7) Phase 3 gaps 1 and 2 (POSIX tests, Python 3.11/3.12 golden bytes) still wait for CI; Phase 2 gaps stand. (8) Process lapses, plainly: the first hook commit `fd8ba5b` was staged before `ruff format` and so lacks two formatting changes that landed in `4785638` (the gate had passed on the working tree); I staged once with `git add -A <directories>` against the explicit-paths rule (it staged exactly the intended files); I ran the gate once with the machine's Python 3.14 instead of the venv (all steps failed harmlessly, nothing committed); I ran the 20k-file slow test by accident once while testing; Phase 4 is one code commit because the gate was green only on the whole tree.
Deviations from PLAN.md: all awaiting your acceptance, also recorded in PLAN.md changelog v0.3.5 and v0.3.6: (1) a root that is one regular file is still accepted by the pre-scan root check, wider than "is a directory"; (2) the open points of D8 settled as listed in v0.3.6 (policy drift low severity and exit 1, low confidence for rename hints and for deletions in an incomplete or partly unreadable scan, directories compared by permissions only); (3) `check` exits 4 for a baseline that was itself incomplete; (4) exit 1 follows the findings shown after `--min-severity`; (5) the anchor format changed to `FIM-ANCHOR v2` (the Phase 3 v1 format was never released and is refused with a message); (6) `docs/report-schema.md` and its drift test were added; (7) CLAUDE.md section 3 now mentions the hook.

## Step 0 and Step 1 before Phase 5: the Linux CI failure and the gate time (2026-10-10)

Step 0, the Linux failure of CI run #5 (commit `0216fca`). Root cause confirmed: the test built
`OSError(0, "function is not valid", None, 1)`; the fourth argument is the Win32 error and only
Windows keeps it (and derives errno from it), so on POSIX the exception had errno 0 and no
`winerror`, and `_hard_links_unsupported` rightly did not recognise it. Fix: `winerror` is read only
under `sys.platform == "win32"` (a plain `if`/`else`, which mypy accepts on both platforms), the
errno values (EPERM, ENOTSUP, EOPNOTSUPP, ENOSYS, EINVAL, EMLINK) and the Win32 codes (1, 50) are
documented where they are listed, errno cases run everywhere, Win32-code cases run under
`windows_only`, a `posix_only` test proves that a `winerror` alone raises instead of falling back,
and two tests run the decision itself on every OS with the platform substituted. Step 3, the
search of the suite for other Windows-only fakes: the only other `OSError` built with a winerror
was the ERROR_ACCESS_DENIED case of the same file (now a class-attribute `winerror` that means the
same on both systems); `FakeStat` with `st_file_attributes` is meaningful on every OS because the
production code reads those attributes with `getattr`; the `pretend(...)` platform substitution
tests and the `os.mkfifo` tests are marked or guarded; no test asserts an errno name that is an
alias on one OS only (ENOTSUP and EOPNOTSUPP appear only as inputs). Gate evidence: a full gate
before the commit showed the two lint/type findings of my own change (ruff N818, mypy
`unreachable` on win32), which I fixed; its pytest step was 2248 passed, 16 skipped; the commit
went through the default gate (2242 passed, 100.00%). The first real run of the 5 new
`posix_only` tests is the next Linux CI run. Process lapse, plainly: that commit first carried a
`Co-Authored-By` trailer (CLAUDE.md section 1 forbids any address in a commit message); I amended
it before anything was pushed and the final message has no trailer.

Step 1, gate time (commit `d3615e5`). Measured, not guessed. `pytest --durations=0` shows no slow
test (the slowest was 1.6 s without coverage) and that the 2250 tests cost about 21 s of
call+setup without coverage and about 29 s with it; the branch-coverage tracer adds about 15 to 19 s
of the total; Windows file operations cost about 3 ms per open (Defender), which dominates the
end-to-end files (`test_check` 51 tests 5 to 6.5 s, `test_app_baseline` 73 tests 4 to 5.8 s); a
`cProfile` run showed `inspect.signature` called 58 884 times by the path guard installed for
every test (about 1.5 s). Run-to-run noise on this machine is +-5 s, so the comparison is three
interleaved runs each way from exported copies of the old and new trees: pytest under coverage
44.4 s (45.75, 47.96, 39.27, 44.53) before and 40.3 s (44.99, 40.24, 35.73) after. Changes: the
path guard caches signatures; the seeded sweeps run a smaller sample by default and the full
size as `slow` (sanitiser round trip 300/5000 and scrub 200/2000, glob oracle 300/3000, YAML
nesting 2500/20000 levels, with an assertion that the default depth is past twice the recursion
limit); two tests became `slow` with a stated reason (the real-tree architecture test, repeated
by the gate's own step, and the 256 KiB at-the-limit configuration); and `scripts/gate.py` starts
the pytest step first and prints its output after the quick steps, so ruff, mypy and the
architecture check (5 to 8 s) no longer add to the total (a deterministic test proves the
overlap without a wall-clock assertion). No test was deleted or weakened. Gate totals after the
change: 41.6 s and 39.3 s (before: 53.5 s in your report, 52 to 56 s in four of my runs).
Rejected on the evidence: `COVERAGE_CORE=sysmon` (not supported with branch coverage on Python
3.13, and `filterwarnings = error` turns the fallback warning into a failure),
`tmp_path_retention_policy=failed` (one test error, no measurable gain), and disabling pytest
plugins (no measurable gain).

## Phase 5 - JSONL, CSV, `watch`, `demo` (2026-10-10)

Commits: `d28f63b` renderers, mapping document and the two watch-only events; `8efc0c0` the append
log; `dd201c8` `watch` and the jsonl/csv formats of `check`; `7779903` the sandbox and `demo`;
`b47d8cd` test setup once per run. Each slice went through the gate on its own tree (the later
slices were set aside with `git stash --keep-index --include-untracked` while it ran).

Manual mini-siem check, real output. mini-siem at `<MINI-SIEM>`, run from its own
virtual environment (`.venv`, Python 3.13.14) with `python -B` and
`PYTHONDONTWRITEBYTECODE=1`, working directory and `--data-dir` in a temporary directory outside
both repositories; its source tree was only read. Before the run a marker file was created;
afterwards no file in mini-siem (including its `.venv`) was newer than the marker and
`git status` there printed nothing. mini-siem's `ingest` and `search` did not need to write into
its folder, so there was no reason to skip the check. The demo file was the JSONL that
`fim watch --max-cycles 2 --interval 10 --output events.jsonl` wrote for a tree with a modified,
a deleted, a permission-changed and two created files (one with a right-to-left override and a
zero-width space in its name): 5 events.

```
$ mini-siem ingest --data-dir <temp>/siem-work/data --format json <temp>/siem-demo/out/events.jsonl
<temp>/siem-demo/out/events.jsonl: format json, 5 line(s), 5 record(s), 0 blank, 0 over-long
events: 5 parsed, 5 newly stored, 0 already stored
parse failures: 0 (dead-letter file: <temp>/siem-work/data/deadletter.jsonl), over-long lines: 0
alerts: 0 stored (0 allowlisted), 0 duplicate(s) suppressed by cooldown
$ mini-siem search --data-dir <temp>/siem-work/data --limit 10 --json ""   (summarised)
json_event  json  host=lab-01 url_path=None  attrs=12 declared_event_type=fim.deleted fim.kind=deleted
json_event  json  host=lab-01 url_path=None  attrs=14 declared_event_type=fim.permission_changed fim.kind=permission_changed
json_event  json  host=lab-01 url_path=None  attrs=12 declared_event_type=fim.created fim.kind=created
json_event  json  host=lab-01 url_path=None  attrs=16 declared_event_type=fim.modified fim.kind=modified
json_event  json  host=lab-01 url_path=None  attrs=12 declared_event_type=fim.created fim.kind=created
```

The stored attributes of the modified event are listed in `docs/siem-mapping.md`.

Built: `render/jsonl.py` (D12 shape, one compact ASCII line per finding, values clipped, path cut at 1 000 characters with `path_sha256` and `path_truncated`) and `render/csv_out.py` (all cells quoted, formula-neutralised, control characters already escaped); `core/diff.baseline_integrity_finding` and `resolved_finding`; `core/sanitize.clip_already_escaped`; `fs/safe_files.open_append_log` and `AppendLog`; `app/watch.py` (delta output, resolved events, per-cycle baseline and anchor verification, rollback by sequence, `--max-cycles`, `--repeat`, append-log output, KeyboardInterrupt, exit code 3 > 4 > 1 > 0); `fs/sandbox.py` and `app/demo.py` (temporary directory, throw-away key, signed baseline, clean check, scripted changes with hostile names, a check that finds them, a tampered baseline that is refused, removal in `finally` and verified); CLI `watch`, `demo` and `check --format jsonl|csv`; `docs/siem-mapping.md` with drift tests. Real runs: `python -m fim demo` printed the transcript (5 findings, exit codes 0, 1 and 3) and left nothing behind; `fim watch --max-cycles 2 --interval 10 --format csv` took 10.3 s, printed a header and 5 rows and exited 1.
Tests added: 2443 collected now (2413 pass and 18 skip in the default gate, 12 slow run only with --full) against 2255 after Phase 4. New files: `test_watch.py` 36 (delta and resolved logic, interval and no-overlap on a fake clock, repeat, min severity, tampered, deleted, rolled-back and re-baselined files mid-watch, a baseline that never verified, incomplete scans, Ctrl-C during a pause and during a scan with the log closed, append log and csv, hostile names, the report limit, policy drift), `test_demo.py` 40 (every expected kind and the refusal, nothing outside the directory touched with an `os`-level audit and a bystander directory, removal when a step raises or staging fails, a demo that finds nothing or accepts a tampered baseline fails, hostile names escaped, sandbox path refusals, read-only files and directories, links and junctions removed without touching their targets), `test_render_events.py` 51 (the shape, limits applied with a copy of mini-siem's flattening rules, hostile and oversized values, CSV injection and quoting, the document against the code), `test_cli_watch.py` 19, plus additions to `test_safe_files` (+17 for the append log), `test_diff`, `test_sanitize`, `test_gate`, `test_config`, `test_globs`.
Real coverage: 100.00% branch coverage (3434 statements, 1000 branches, 0 missing) as printed by the gate on the default run, Windows, Python 3.13.14. The 18 POSIX-only tests are skipped here, so the POSIX-only lines are reached only through substituted platform values and the `hostile_names()` helper, not through a real Linux run. Default gate after Phase 5: 54.2, 55.2 and 48.8 s in total on three runs (pytest alone 44 to 55 s over six runs; the interleaved comparison with and without this phase's last trims gave 51.6 and 49.6 s); the full gate: 2425 passed, 18 skipped in 304 s (305 s with the quick steps). Phase 5 added about 9 s to the default gate.
Known gaps: (1) the 18 POSIX-only tests (8 from Phase 2, 4 from Phase 3, 2 from Phase 4, 2 from Step 0 and 2 new in Phase 5) have never run on Linux; the next CI run is their first, and also the first real run of the Linux side of the Step 0 fix. (2) The default gate is about 50 s again; per-test cost is mostly Windows file operations and the coverage tracer, so further savings mean moving the end-to-end watch and demo tests to `slow`, which I did not do without your say. (3) `watch` is polling: a change made and reverted between two cycles is missed (Limitations list, Phase 6). (4) `watch` keeps at most `MAX_FINDINGS_REPORTED` finding ids; with more findings than that, the ones not listed cannot be tracked and a note says so. (5) The append log has no rotation and is fsynced once per batch, so a power cut can lose the batch in flight. (6) `docs/siem-mapping.md` is checked against the code and was checked once against mini-siem's live parser by hand; a later change in mini-siem is not detected by a test here. (7) The mini-siem ingest was done on Windows only. (8) The hostile names in the demo are shown escaped; whether a given terminal shows the escapes the same way is not tested beyond the cp1252 test of Phase 4. (9) Phase 4 gaps and earlier gaps still stand, except gap (6) of Phase 4 (the default gate drifting towards 60 s), which Step 1 addressed and Phase 5 partly undid.
Deviations from PLAN.md: all awaiting your acceptance, also recorded in PLAN.md changelog v0.3.7: (1) `check --format jsonl|csv` and their notes on stderr; (2) `watch` options (`--format csv`, `--min-severity`, `--force`, `--config`) and the exit-code rule "3, else 4, else 1 if any finding was reported during the run, else 0"; (3) every failure to re-verify the baseline, including a validly signed baseline with a lower sequence number, is a `baseline_integrity` event raised once per distinct message, resolved when the baseline verifies again, with exit 3 sticky; a new valid baseline is adopted; (4) an incomplete scan reports no resolved events; (5) `resolved` events are `info` with the original's id; (6) the JSONL details listed in v0.3.7 item 7; (7) the append log's exact behaviour (one fsync per batch, no rotation); (8) the demo has one more step than PLAN.md lists (the tampered baseline) and no options; (9) the sandbox removes its tree with an lstat walk because `os.walk` enters junctions; (10) the architecture table edges and `clip_already_escaped`; (11) the gate runs pytest beside the quick steps (Step 1); (12) `docs/siem-mapping.md` carries the real ingest. Process lapses, plainly: the Step 0 commit trailer (amended before any push), and I wrote several test files through shell heredocs whose backslash handling turned `\u202e` into the real character three times; the hygiene test caught it each time before any commit and I replaced them with escape sequences; the guard hook also caught me piping the gate twice (both were blocked, nothing ran).

## After Phase 5: CI run #6, the Linux check in WSL, the gate time (2026-10-10)

Step 0, CI run #6 (3 failed, 2408 passed, all three Linux jobs; Windows green). The three failures
were `test_paths_that_could_leave_the_sandbox_are_refused` with `"C:/x"`, `"C:x"` and `"a:stream"`:
`fs/sandbox.py` refused a colon only when `os.sep != "/"`, so on POSIX it did not raise. Decision
of the owner: the rule is the same on every OS. `_bad_component` now refuses `:` everywhere (the
demo's paths are fixed strings and none contains a colon; no hostile name does either), the test is
unchanged. Commit `028516a`. The search for other name or path checks that apply on one platform
only is in PLAN.md changelog v0.3.8, item 2: the sandbox was the only one that consulted the
operating system inside non-pure code; the Windows name rules of `core/pathrules.py` are keyed on
the `Flavour` parameter, run in tests on every OS, and are kept Windows-only on purpose (a colon
is a legal name character on POSIX, for example `/sys/devices/pci0000:00`); the rest are
mechanisms (open flags, uid, hard-link error codes), not checks on names.

Step 1, the Linux check. WSL 2 with Ubuntu 26.04 is available and reaches PyPI. Its `python3` is
3.14.4 and the only interpreter there (3.11 to 3.13 would need `apt`, which I did not touch), and
it has no `ensurepip`. So the venv `~/.venvs/fim-linux` was made with `python3 -m venv
--without-pip`, and pip was bootstrapped from its own wheel downloaded from PyPI and checked
against the sha256 of the PyPI JSON (pip 26.2.1), then `pip install -e ".[dev]"` (ruff 0.16.10,
mypy 2.4.0, pytest 9.1.1, coverage 7.16.2, PyYAML 6.0.3). The repository is cloned to
`~/fim-linux-check` in the WSL home, not under `/mnt/c`; it is refreshed with `git fetch` and
`git reset --hard FETCH_HEAD`, which CLAUDE.md section 3 documents together with the rebuild
steps. Results of `python scripts/gate.py --full` there (Linux, Python 3.14.4):
- commit `028516a` (before the slow marks): 2411 passed, 17 skipped (16 `windows_only`, 1
  junction test), 100.00% branch coverage, 17.6 s in total. This is the first real run of the 18
  POSIX-only tests of Phases 2 to 5 and of the fix of the previous session; all pass.
- commit `0687421` (final code): 2411 passed, 17 skipped, 100.00%, 12.1 s in total.
Windows full gate on `0687421`: 2425 passed, 18 skipped (`posix_only`), 100.00%, 311.3 s in total
(pytest 310.2 s; it was about 230 s in Phase 2, before the end-to-end tests of Phases 3 to 5).
Commit `d14c343` holds the CLAUDE.md changes (sections 1 and 3).

Step 2, the owner's decisions are recorded in PLAN.md changelog v0.3.8: all deviations of v0.3.6
and v0.3.7 are accepted, including the gate's pytest step running beside the quick steps (CLAUDE.md
section 3 describes it now). The watch and demo end-to-end tests are `slow` (commit `0687421`):
55 tests, chosen by measured cost per test (every one that builds a real tree, key and signed
baseline and runs the whole watch, check or demo took 0.09 to 0.33 s; every argument refusal,
help text and sandbox test took 0.02 s or less and stays in the default gate). Default gate
before and after, three interleaved runs each on this machine, total seconds:

| | run 1 | run 2 | run 3 | mean | tests | default-run coverage |
|---|---|---|---|---|---|---|
| before | 50.8 | 54.5 | 56.6 | 54.0 | 2413 passed, 18 skipped, 12 deselected | 100.00% |
| after | 43.7 | 50.0 | 42.5 | 45.4 | 2357 passed, 17 skipped, 69 deselected | 94.88% |

The gate is about 9 s faster, not quite at "about 40 s": the best run was 42.5 s, and the machine's
run-to-run noise is 5 to 8 s. The cost is stated plainly in the changelog: the default run's
coverage fell from 100.00% to 94.88% because `app/watch.py` (28.24%) and `app/demo.py` (48.25%)
are now covered mostly by slow tests; the gate still enforces 85% there, and the full gate (CI)
still reports 100.00%. If the default run should keep a smoke test of the watch loop and of the
demo, say so: it costs about 0.3 s.

Process notes, plainly: the hook blocked one of my timing scripts because it redirected the
gate's output; I rewrote it to use `--log` and no redirect. The three interleaved timing runs
swapped the three test files in and out of `tests/`; the tree was restored afterwards and the
diff is exactly the 55 marks and 3 comments.

```
Built: nothing new in src beyond the sandbox rule; a Linux check in WSL (venv, clone, documented commands); 55 end-to-end tests marked slow
Tests added: 0 (2425 in the full gate on Windows, 2411 on Linux; the default gate runs 2357 and defers 69)
Real coverage: full gate 100.00% on Windows (2425 passed, 18 skipped) and on Linux (2411 passed, 17 skipped); default gate 94.88%
Known gaps: Linux ran on Python 3.14.4 only (3.11 to 3.13 are CI's); the default gate no longer covers most of app/watch.py and app/demo.py; invariant 3 wording; first CI run with these commits not yet seen
Deviations from PLAN.md: none new (the owner's decisions are changelog v0.3.8)
```

## Phase 6 - Hardening, measurement, docs, release (2026-10-10)

Commits (oldest first, each through the gate on its own tree; the later files were set aside
while it ran): `31fc13e` CLAUDE.md invariant 3; `314fe7b` smoke tests; `f597b1e` CI actions;
`fb242b5` `scripts/bench.py`; `207e1f0` `MAX_BASELINE_BYTES` to 128 MiB; `be90729` version 1.0.0
and the changelog; `b45cd2f` bench rows printed as they are measured; `8e7975b` the documents
and `tests/test_docs.py`; and the commit that adds this report. Nothing was pushed or tagged.

### Step 0

- **(a) Invariant 3.** CLAUDE.md now says the Windows name rules (reserved device names, a colon
  in a name, `<>"|?*`, trailing space or dot, `\` as a separator, drive-relative `C:foo`) are
  enforced for Windows paths only, and why; and, from reading `core/pathrules.py`, that both
  flavours refuse UNC and device syntax, a leading drive letter such as `C:` (on POSIX as "looks
  like a Windows drive path"), URL-like text, `..` and unsafe characters. My first wording was
  too broad (it said drive-relative paths were Windows-only); I corrected it from the code before
  committing.
- **(b) Smoke tests.** `test_smoke_watch_reports_a_change_once_and_stops_after_two_cycles` (0.10 s)
  and `test_smoke_demo_runs_finds_the_changes_refuses_the_tampered_baseline_and_cleans_up`
  (0.20 s) are in the default gate; the other end-to-end tests stay `slow`. The default run's
  branch coverage went from 94.88% back to 98.47% (`app/watch.py` 28.24% to 76.85%, `app/demo.py`
  48.25% to 95.61%).
- **(c) CI actions.** `actions/checkout@v5`, `actions/setup-python@v6`, the policy test updated,
  nothing else in the workflow changed. I cannot see GitHub from here, so whether the Node 20
  warning is gone is for you to confirm on CI.

### The measurements (`docs/performance.md`)

One machine: Intel Core Ultra 7 155U, 31.5 GiB, NVMe SSD, Windows 11, Python 3.13.14, real-time
protection on; `python scripts/bench.py all`, commit `b45cd2f`.

| What | Result |
|---|---|
| Later `baseline` / `check`, 100 000 files of 1 KiB (101 021 records) | 25.46 s / 27.49 s (3 968 / 3 675 records a second) |
| First `baseline` of those just-written files | 1212.18 s (12 ms a file); 14.41 s for 1 000, 123.78 s for 10 000 |
| One 256 MiB file | 0.28 s, 905 MiB/s (hashlib over memory: 1 825 MiB/s) |
| `tracemalloc` peak, `baseline` / `check` of 100 000 files | 143.8 MiB / 165.7 MiB |
| Peak working set, `check` with a 119.1 MiB baseline (400 409 records) | 740.8 MiB |

Things the run taught me that I did not expect, stated plainly:

- **The default 900 s time budget stopped the first baseline of the 100 000-file tree.** My
  first full run printed nothing: the script crashed on the tool's own `LimitReachedError`
  (exit code 4, nothing written) and printed its tables only at the end, so about 40 minutes
  were lost. I kept the error as evidence, made the script print each row as it is measured,
  gave its trees the ceiling budget (3 600 s) and ran again. The cause is most likely the
  system's real-time protection scanning each new file on first open (12 to 14 ms a file against
  0.25 to 0.34 ms later); I did not turn it off, because that is a security setting, so it is the
  likely cause, not a proven one. The README Limitations say so.
- **One later baseline run of the 100 000-file tree took 470.07 s** (the others 23.40 s and
  25.46 s). I do not know why; a rescan after a definition update would fit. The table shows the
  range and the doc says so.
- **Loading a baseline peaks at 6.1 to 6.5 times its size, and a whole `check` at the same
  figure.** The first design allowed 256 MiB: the largest measured size, 238.2 MiB, needed
  1453.6 MiB.

### D11 decision

`MAX_BASELINE_BYTES` is **128 MiB** (default and ceiling). Criterion, stated in
`docs/performance.md` so you can overrule it: under 1 GiB for the largest baseline the tool
accepts, because `watch` pays the peak every cycle on a laptop. After the change, a 119.1 MiB
baseline peaked at 740.8 MiB. Consequences: limits are in the policy digest and in every baseline,
so the golden payload, its file hash and the pinned digest were regenerated (the old and new
golden payloads differ in exactly three values: the limit in two places and the digest) and a
baseline written under 256 MiB is refused as above its ceiling (a test pins that). The
`MAX_FILES` ceiling of 1 000 000 is unchanged and can now be unreachable for a given tree (the
byte limit fires first, with a message and nothing written); I left it for your decision. I did
not optimise the load path: the code holds several copies of the file's bytes and the parsed
document next to the records, which could lower the peak without touching the limit, but it is
the most security-critical module and you asked for the ceiling.

### Review pass of the four security-critical modules

`fs/observe.py`, `fs/safe_files.py`, `services/baseline_codec.py` and `core/sanitize.py` were read
in full again with the questions: can a byte of a baseline reach a parser before the MAC verified
(no: `parse_payload` has one caller, `decode_baseline`, after `hmac.compare_digest`; a test
pins the order); can a write go through a link or over an existing file (no: exclusive create,
hard-link publish, `os.replace` on a link replaces the link, targets that are links are refused);
can a hostile name reach output unescaped (no); what happens when a file changes, is swapped, or
disappears mid-read (retry once, then `unstable`/`vanished`). **No code defect was found, so no
test-first fix was needed.** What the pass did find, now in the threat model, README Limitations
and PLAN changelog v0.4, and not changed:

1. On Windows the open of a monitored file has no no-follow flag; the device and inode
   comparison with the earlier `lstat` is the only guard against a link swapped in between.
2. A crash between creating and removing a temporary file leaves `.fim-<random>.tmp` in the
   target's directory; for a key that is a copy of the key.
3. `key_file` in the unauthenticated configuration is trusted: someone who can edit the
   configuration and the baseline can point `check` at a key of their own.
4. The sanitiser escapes by Unicode category, so letters and symbols that render blank (Hangul
   filler U+3164, Braille blank U+2800), combining marks and variation selectors pass through. That
   is D10 as written ("everything else stays readable") and is documented under "confusable
   glyphs"; escaping them would be a small decision for a later release (Unicode has a
   `Default_Ignorable_Code_Point` property for this; Python's `unicodedata` does not expose it).
5. Baselines made under a higher ceiling are refused after a ceiling is lowered (see above).

### Documents

README (what it is and is not, install, `fim demo`, a first real run, every command and option,
configuration, limits, exit codes, formats, the mini-siem section, "What the tool reads and
writes", a 24-row claim-to-evidence table, Limitations with every item you listed plus the PLAN's,
performance, development), `docs/threat-model.md` (17 threats, each with a test or an
explicit "not testable"), `docs/performance.md`, `CHANGELOG.md` 1.0.0, SECURITY.md updated.
Real output only: Windows transcripts and a short Linux one from WSL, the local temporary
directory shown as `<TMP>` everywhere (`tests/test_docs.py` fails if a document names a local
path or the user name). `docs/siem-mapping.md` carried a local path and a 0.1.0 sample line: the
sample line was regenerated from the 1.0.0 build and redacted, and the stored-attribute listing
redacted; the mini-siem ingest paste is unchanged and says it was done once, with 0.1.0.

### Release checks (temporary venv outside the repository, Python 3.11.15, deleted afterwards)

Commit `8e7975b`, cloned fresh. Python 3.11 was used on purpose: it is the lowest the wheel
claims. The script that ran it is not committed (it is a one-off driver); the output below is
its real output, with the long package and wheel lists shortened and marked.

```
===== clean checkout of the commit =====
$ git clone --quiet <REPO> <RELEASE>\src

[exit code 0]

===== commit =====
$ git -C <RELEASE>\src log --oneline -1
8e7975b docs: README, threat model, performance report and the tests that keep them true
[exit code 0]

===== status of the checkout =====
$ git -C <RELEASE>\src status --short

[exit code 0]

===== tool venv =====
$ <PYTHON-3.11.15> -m venv <RELEASE>\tools

[exit code 0]

===== install build, pip-audit, bandit =====
$ <RELEASE>\tools\Scripts\python.exe -m pip install --quiet build pip-audit bandit

[notice] A new release of pip is available: 24.0 -> 26.2.1
[notice] To update, run: <RELEASE>\tools\Scripts\python.exe -m pip install --upgrade pip
[exit code 0]

===== tool versions =====
$ <RELEASE>\tools\Scripts\python.exe -m pip list --format=freeze --disable-pip-version-check
[... 36 installed packages: build 1.6.1, pip-audit 2.10.1, bandit 1.9.4 and their dependencies ...]
[exit code 0]

===== python -m build =====
$ <RELEASE>\tools\Scripts\python.exe -m build <RELEASE>\src
Successfully built file_integrity_monitor-1.0.0.tar.gz and file_integrity_monitor-1.0.0-py3-none-any.whl
  - hatchling>=1.25
  - hatchling==1.32.4
  - hatchling>=1.25
  - hatchling==1.32.4
[exit code 0]

dist contents: ['file_integrity_monitor-1.0.0-py3-none-any.whl', 'file_integrity_monitor-1.0.0.tar.gz']

===== install venv =====
$ <PYTHON-3.11.15> -m venv <RELEASE>\install

[exit code 0]

===== install the wheel =====
$ <RELEASE>\install\Scripts\python.exe -m pip install --quiet <RELEASE>\src\dist\file_integrity_monitor-1.0.0-py3-none-any.whl

[notice] A new release of pip is available: 24.0 -> 26.2.1
[notice] To update, run: <RELEASE>\install\Scripts\python.exe -m pip install --upgrade pip
[exit code 0]

===== pip list in the install venv =====
$ <RELEASE>\install\Scripts\python.exe -m pip list --disable-pip-version-check
Package                Version
---------------------- -------
file-integrity-monitor 1.0.0
pip                    24.0
PyYAML                 6.0.3
setuptools             79.0.1
[exit code 0]

===== fim --version =====
$ <RELEASE>\install\Scripts\fim.exe --version
fim 1.0.0
[exit code 0]

===== fim demo =====
$ <RELEASE>\install\Scripts\fim.exe demo
fim demo: a throw-away copy of the whole workflow on files made for it.
workspace: <TMP>\fim-demo-8kkfkm0n (removed when the demo ends)

step 1: create a key and record a signed baseline
  fim init-key   -> key id b905de6f630a76de
  fim baseline   -> 10 entries, sequence 1, signed

[... middle of the transcript omitted: it is the one in the README ...]

the temporary directory was removed
[exit code 0]

===== init-key =====
$ <RELEASE>\install\Scripts\fim.exe init-key --key-file <RELEASE>\play\keys\fim.key --config <RELEASE>\play\state\fim.yaml
key file written: <RELEASE>\play\keys\fim.key
key id: 267a93825f4f560d
Keep the key outside every monitored path, make a backup, and do not share it. Anyone who can read it can forge a baseline.
[exit code 0]

===== baseline =====
$ <RELEASE>\install\Scripts\fim.exe baseline --config <RELEASE>\play\state\fim.yaml --baseline <RELEASE>\play\state\lab.baseline
baseline written: <RELEASE>\play\state\lab.baseline
  records: 3
  sequence: 1
  key id: 267a93825f4f560d
  complete: yes
  rollback anchor created: <RELEASE>\play\keys\fim.key.d6d4543e5207c98a.fim-anchor
[exit code 0]

===== check, clean (expect 0) =====
$ <RELEASE>\install\Scripts\fim.exe check --baseline <RELEASE>\play\state\lab.baseline --key-file <RELEASE>\play\keys\fim.key
fim check: baseline sequence 1 made 2026-10-10T19:09:01Z (key id 267a93825f4f560d)
checked 2026-10-10T19:09:01Z with fim 1.0.0

no changes found

0 findings
complete: yes
[exit code 0]

===== check, after a change (expect 1) =====
$ <RELEASE>\install\Scripts\fim.exe check --baseline <RELEASE>\play\state\lab.baseline --key-file <RELEASE>\play\keys\fim.key
fim check: baseline sequence 1 made 2026-10-10T19:09:01Z (key id 267a93825f4f560d)
checked 2026-10-10T19:09:02Z with fim 1.0.0

SEVERITY  CONFIDENCE  KIND      PATH
high      high        modified  <RELEASE>\play\lab\a.txt
                                sha256 differs (4a31f8a329cdbbab... -> 28db9c894b4bee55...); size 7 -> 15
high      high        created   <RELEASE>\play\lab\c.txt
                                new file, 5 bytes, sha256 9f5d1ba48d2fd5c3...

2 findings (high 2)
by kind: created 1, modified 1
complete: yes
[exit code 1]

===== check, tampered (expect 3) =====
$ <RELEASE>\install\Scripts\fim.exe check --baseline <RELEASE>\play\state\lab.baseline --key-file <RELEASE>\play\keys\fim.key
fim: error: the baseline is not trustworthy: the MAC does not verify: the file was changed or damaged after writing
[exit code 3]

===== python -m fim --version =====
$ <RELEASE>\install\Scripts\python.exe -m fim --version
fim 1.0.0
[exit code 0]

===== pip-audit on the installed environment, as the venv was made =====
$ <RELEASE>\tools\Scripts\python.exe -m pip_audit --path <RELEASE>\install\Lib\site-packages --progress-spinner off
Name       Version ID              Fix Versions
---------- ------- --------------- ------------
pip        24.0    PYSEC-2026-1795 25.3
pip        24.0    PYSEC-2026-1796 26.0
pip        24.0    PYSEC-2026-2875 26.1
pip        24.0    PYSEC-2026-2876 26.1
pip        24.0    PYSEC-2026-196  26.1.2
pip        24.0    PYSEC-2026-1795 25.3
pip        24.0    PYSEC-2026-1796 26.0
pip        24.0    PYSEC-2026-196  26.1.2
pip        24.0    PYSEC-2026-2875 26.1
pip        24.0    PYSEC-2026-2876 26.1
pip        24.0    PYSEC-2026-3721 26.2
pip        24.0    PYSEC-2026-3721 26.2.0
setuptools 79.0.1  PYSEC-2026-3447 83.0.0
setuptools 79.0.1  PYSEC-2026-3447 83.0.0

Name                   Skip Reason
---------------------- -------------------------------------------------------------------------------------
file-integrity-monitor Dependency not found on PyPI and could not be audited: file-integrity-monitor (1.0.0)
Found 14 known vulnerabilities in 2 packages
[exit code 1]

===== upgrade the venv's own bootstrap packages (not fim's dependencies) =====
$ <RELEASE>\install\Scripts\python.exe -m pip install --quiet --upgrade pip setuptools

[exit code 0]

===== pip list after the upgrade =====
$ <RELEASE>\install\Scripts\python.exe -m pip list --disable-pip-version-check
Package                Version
---------------------- -------
file-integrity-monitor 1.0.0
pip                    26.2.1
PyYAML                 6.0.3
setuptools             84.0.0
[exit code 0]

===== pip-audit on the installed environment, after the upgrade =====
$ <RELEASE>\tools\Scripts\python.exe -m pip_audit --path <RELEASE>\install\Lib\site-packages --progress-spinner off
Name                   Skip Reason
---------------------- -------------------------------------------------------------------------------------
file-integrity-monitor Dependency not found on PyPI and could not be audited: file-integrity-monitor (1.0.0)
No known vulnerabilities found
[exit code 0]

===== bandit -r src =====
$ <RELEASE>\tools\Scripts\python.exe -m bandit -r <RELEASE>\src\src
Run started:2026-10-10 19:09:33.652328+00:00

Test results:
	No issues identified.

Code scanned:
	Total lines of code: 5789
	Total lines skipped (#nosec): 0
	Total potential issues skipped due to specifically being disabled (e.g., #nosec BXXX): 0

Run metrics:
	Total issues (by severity):
		Undefined: 0
		Low: 0
		Medium: 0
		High: 0
	Total issues (by confidence):
		Undefined: 0
		Low: 0
		Medium: 0
		High: 0
Files skipped (0):
[main]	INFO	profile include tests: None
[main]	INFO	profile exclude tests: None
[main]	INFO	cli include tests: None
[main]	INFO	cli exclude tests: None
[main]	INFO	running on Python 3.11.15
[exit code 0]

===== nosec comments in src =====
(none)

===== wheel contents =====
file_integrity_monitor-1.0.0-py3-none-any.whl: 44 files
  [file list omitted: 38 modules under fim/, py.typed, and dist-info]

sdist: file_integrity_monitor-1.0.0.tar.gz, 333475 bytes
sdist members: 110
key, log, baseline or anchor files in the sdist: none
top-level entries in the sdist: ['.gitignore', 'CHANGELOG.md', 'CLAUDE.md', 'LICENSE', 'PKG-INFO', 'PLAN.md', 'README.md', 'SECURITY.md', 'docs', 'pyproject.toml', 'scripts', 'src', 'tests']

FAILED STEPS: none

removed fim-release-gatntfdy: exists=False
```

### Gates

| Gate | Result |
|---|---|
| Windows default, final tree | 2375 passed, 17 skipped, 70 deselected; 98.47% branch coverage; **41.2 s** total (pytest 40.17 s). Other runs this phase ranged from 38.9 s to 60.8 s (machine noise) |
| Windows `--full`, commit `8e7975b` | 2444 passed, 18 skipped (`posix_only`); **100.00%** branch coverage; 317.1 s total |
| Linux `--full` in WSL (Ubuntu, Python 3.14.4), commit `8e7975b` | 2430 passed, 17 skipped (16 `windows_only`, 1 junction test); **100.00%**; 11.4 s total |

Repository hygiene, checked independently of the hygiene tests with a script over the 112 tracked
and untracked-not-ignored files: no email-like string, no bidi, zero-width, control or C1
character, no key, baseline or anchor file or header, no `*.key`, `*.pem`, `.env*` name; no commit
message since Step 0 carries a trailer or an address; the sdist holds no key, log, baseline or
anchor; no build output is tracked (`dist/` is ignored and was never made in the repository).

### Process notes, plainly

- The pre-tool hook blocked me five times for putting a pipe, `grep` or `tail` in the same
  command as the gate; nothing ran.
- My shell heredocs again collapsed a double backslash to a single one, several times. Each case
  was caught before anything was committed: by a syntax error, by a failed assertion in my own
  patch script, or (once, a real backspace character that a `\b` in a regular expression of a
  test had become) by `cat -A`; the hygiene test would have caught that one too. After that I
  used the editor tool for any text with backslashes.
- To gate each commit on its own tree I moved `tests/test_docs.py` out while the earlier commits
  were gated and put it back before its own.
- The Phase 1 test that pinned the placeholder README ("work in progress", no measured numbers)
  contradicted the phase's purpose; I replaced it with one that forbids absolute claims and
  placeholders, and the new README tests cover the numbers. That is a deliberate test change, in
  `8e7975b`.
- The bench's first complete run is described above (40 minutes lost to my script printing at
  the end).

### Open questions for you

1. `Development Status :: 5 - Production/Stable` in `pyproject.toml` for 1.0.0: say if you prefer
   Beta.
2. The 128 MiB baseline limit and the unchanged `MAX_FILES` ceiling (above).
3. Whether to escape blank-looking letters (item 4 of the review) in a 1.0.x or 1.1.
4. Whether to lower the peak memory of loading a baseline (the copies in `decode_baseline`).
5. Linux was not benchmarked; if the numbers should cover it, `scripts/bench.py` runs there.

```
Built: scripts/bench.py and docs/performance.md (measured: machine, OS, Python, date and command per table); MAX_BASELINE_BYTES lowered 256 to 128 MiB on the D11 memory measurement; docs/threat-model.md; the real README (output pasted from runs, read/write section, 24-row claim table, Limitations); CHANGELOG and version 1.0.0; tests/test_docs.py; Step 0 (invariant 3, smoke tests, CI actions v5/v6); release checks pass (build, wheel install, demo and round trip, pip-audit, bandit)
Tests added: 19 (2443 collected after Phase 5, 2462 now): 12 in test_docs.py (every named test exists, limits table, exit codes, every option and default, version, no local paths, README numbers in performance.md), 4 in test_bench.py (the script on a tiny tree, the synthetic tree checks clean, its file system view, the fresh-process workers), 2 smoke tests (watch, demo), 1 in test_baseline_codec.py (a baseline under a higher ceiling is refused); one Phase 1 README test replaced
Real coverage: 100.00% branch coverage (3434 statements, 1000 branches, 0 missing) in the full gate on Windows (2444 passed, 18 skipped) and on Linux in WSL (2430 passed, 17 skipped); the default gate prints 98.47%
Known gaps: Linux ran on Python 3.14.4 only (CI covers 3.11 to 3.13, not seen yet for these commits); measurements are from one Windows machine with real-time protection on, one run outlier unexplained, Linux not benchmarked; the mini-siem ingest was done once by hand with 0.1.0; blank-looking letters are not escaped; a hard crash can leave a .fim-*.tmp copy of a key; key_file in the configuration is trusted; the load path uses about six times the baseline's size and was not optimised; the CWE ids were not re-checked against the live list (PyPI-only network)
Deviations from PLAN.md: (1) MAX_BASELINE_BYTES 256 MiB to 128 MiB, as D11 authorises, MAX_FILES ceiling left alone; (2) the golden payload, its file hash and the pinned policy digest regenerated for that change; (3) bench trees use the ceiling time budget, found necessary by a measurement; (4) Development Status Production/Stable and SECURITY.md "latest 1.x"; (5) the README test of Phase 1 replaced; (6) the review pass changed no code
```

## Release-readiness pass before v1.0.0 (2026-10-11)

No feature was added. The owner's decisions for the first public release, applied and recorded
(PLAN.md changelog v0.4.1):

| Phase 6 open question | Decision |
|---|---|
| 1. `Development Status` | `4 - Beta` in `pyproject.toml` (was `5 - Production/Stable`): measured on one machine, first public release. No test or document pinned the old value. |
| 2. 128 MiB baseline limit, unchanged `MAX_FILES` ceiling | Accepted, with the D11 measurement (peak memory 6.1 to 6.5 times the file size) as the reason. The `MAX_FILES` ceiling is unchanged; the byte limit is the effective bound for a configuration that raises `max_files` towards its ceiling. |
| 3. Escape blank-looking letters (U+3164, U+2800 and similar) | Deferred to 1.1. |
| 4. Lower the peak memory of loading a baseline | Deferred to 1.1. |
| 5. Linux benchmark | None for 1.0. |

Also changed, in the documents only:

- README Limitations: a hard crash during a write of the key or the baseline (or the anchor or a
  report, which use the same path) can leave a `.fim-<random>.tmp` file in the target's
  directory, mode `0600` on POSIX, which the user should delete; `key_file` in the configuration is
  trusted as given; the numbers come from one Windows machine with real-time antivirus on and
  nothing was measured on Linux.
- CHANGELOG.md: an `Unreleased` heading with "Planned for 1.1": the two deferred items and the
  automatic cleanup of stale `.fim-*.tmp` files, and nothing else.
- This file: two absolute local paths found by the independent hygiene scan of the pass (the
  mini-siem directory in the Phase 5 entry and the clone source in the Phase 6 release check) are
  shown as `<MINI-SIEM>` and `<REPO>`, like the other placeholders. `tests/test_docs.py` looks for
  a home-directory path and the user name, which these two did not contain, so it had not caught
  them.

Gates, on the working tree before this commit: Windows `--full`, 2444 passed, 18 skipped
(`posix_only`), 100.00% branch coverage (3434 statements, 1000 branches, 0 missing), 333.5 s. The
results on the committed tree, on Windows and on Linux in WSL, are in the pass's chat summary.

```
Built: nothing new; the owner's release decisions applied (Beta classifier, limits and deferrals recorded, Limitations wording, CHANGELOG "Planned for 1.1")
Tests added: 0 (2444 passed, 18 skipped in the full gate; no test pinned the classifier or the changed wording)
Real coverage: 100.00% branch coverage (3434 statements, 1000 branches, 0 missing), full gate on Windows, working tree before the commit
Known gaps: unchanged from Phase 6: Linux ran on Python 3.14.4 only and was not benchmarked; measurements are from one Windows machine with real-time protection on; blank-looking letters are not escaped; a hard crash can leave a .fim-*.tmp file; key_file in the configuration is trusted; the load path uses about six times the baseline's size
Deviations from PLAN.md: none; the classifier (v0.4 item 7) and the Phase 6 open questions are decided by the owner (v0.4.1)
```
