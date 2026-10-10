# CLAUDE.md - file-integrity-monitor

Working rules for Claude Code in this repository. Read this file fully at the start of every
session. Then read only the PLAN.md section for the current phase, Section 0 (decisions) and the
last entry of `docs/phase-reports.md`. Do not re-read the whole repository each session.

Project: a defensive File Integrity Monitor (`fim`) in Python for home labs and endpoints the
user owns. Commands: `init-key`, `baseline`, `check`, `watch`, `demo`. Project 3 of a portfolio;
the quality bar is network-scanner v1.0.0 (gate, CI matrix, measured docs, claim-to-evidence README).

---

## 1. Machine rules (verbatim, non-negotiable)

- Single .venv in the project folder.
- Never git push or create tags (I push myself).
- Stage files by explicit path only, never `git add -A` or `git add .`.
- Network access to PyPI only.
- Never touch the wordpress or dvwa Docker containers.
- No docker prune.
- Never use host port 8080.
- Never kill processes by image name.
- No email address in any file or commit message.
- Do not run /graphify.
- Do not touch the git identity.
- This folder may not be a git repo yet, so Phase 1 runs `git init -b main`.

How these apply here:
- "PyPI" means pypi.org and files.pythonhosted.org. No GitHub, no web search, no other hosts.
  `pip-audit` uses its default `pypi` vulnerability service, not OSV.
- The release check (section 10) uses a temporary venv outside the repo; it is deleted afterwards.
  The only other second venv allowed is the Linux check venv inside WSL (section 3), at
  `~/.venvs/fim-linux`, outside every repository and kept between runs. Its clone is
  `~/fim-linux-check` in the WSL home, never under `/mnt/c`. WSL may reach PyPI only, like
  everything else. Never touch the WSL distribution itself: no `wsl --unregister`, no `apt` or other
  system package change without asking.
- No email address anywhere: no `Co-Authored-By:` trailer (it contains an address), no email in
  `pyproject.toml` `authors`, LICENSE, SECURITY.md (use GitHub private vulnerability reporting),
  fixtures or test data. Test data that needs an address-like string builds it at runtime.
- Git identity: never run `git config user.*`, never pass `-c user.*`, `--author` or
  `GIT_AUTHOR_*`/`GIT_COMMITTER_*`. If a commit fails because no identity is set, stop and tell me.
- To stop a process you started, use its PID or Ctrl-C; never `taskkill /IM` or `pkill <name>`.
- This project needs no Docker and no network listener. Do not start either.

## 2. Session protocol

1. Check Section 0 of PLAN.md. Do not implement anything that depends on a decision not marked
   approved. Ask instead.
2. Work in small vertical slices (module + tests + gate), not big bangs. Commit at each green slice.
3. If PLAN.md and reality conflict, stop and ask. Never deviate silently. Record every accepted
   deviation in the phase report and in the PLAN.md changelog.
4. Never claim something works without running it. Report failures with the real output.
5. End every phase with exactly this 5-line report, shown in chat and appended to
   `docs/phase-reports.md`:
   ```
   Built: <what now exists>
   Tests added: <count from pytest output, and what they cover>
   Real coverage: <the number printed by the gate, not rounded up>
   Known gaps: <honest list, or "none known">
   Deviations from PLAN.md: <list with reason, or "none">
   ```
6. Token budget (Claude Pro weekly limit): run single test files while iterating, run the full
   gate before each commit, keep tool output short (`pytest -q`), do not dump large files into
   context, stop at a clean commit when a session nears its limit and note where to resume in
   `docs/phase-reports.md` under "In progress".

## 3. Commands

Windows (this machine) uses `.venv\Scripts\python.exe`; Linux CI uses the runner's Python. Always
run tools through the venv interpreter (`python -m pip`, `python -m pytest`), never a global one.

```
uv venv --python 3.13 .venv         # or: py -3.13 -m venv .venv  (never the machine default, 3.14)
.venv\Scripts\python.exe -m pip install -e ".[dev]"
python scripts/gate.py            # fast gate (excludes @pytest.mark.slow)
python scripts/gate.py --full     # everything, as CI runs it
```

Commit only like this (Bash tool / Git Bash):
```
python scripts/gate.py && git commit -m "<message>"
```
In Windows PowerShell 5.1 there is no `&&`; use:
`python scripts/gate.py; if ($LASTEXITCODE -eq 0) { git commit -m "<message>" }`

Linux check (WSL). Three CI runs in a row failed on Linux only, because the tests ran only on
Windows. Before reporting a phase as done, run the full gate once on Linux via WSL as well as on
Windows, on the committed code (the clone sees commits only, so commit first). Refresh and run, from
PowerShell, with no pipe or redirect on the gate:
```
wsl -d Ubuntu -e sh -c "cd ~/fim-linux-check && git fetch -q /mnt/c/Studies/Projects/file-integrity-monitor main && git reset -q --hard FETCH_HEAD && ~/.venvs/fim-linux/bin/python scripts/gate.py --full"
```
If `~/fim-linux-check` or `~/.venvs/fim-linux` is missing, rebuild them inside WSL: `git clone` the
repository from `/mnt/c/...` into `~/fim-linux-check`; `python3 -m venv --without-pip
~/.venvs/fim-linux` (Ubuntu's python3 has no `ensurepip`); fetch the `pip` wheel from PyPI, check its
sha256 against the PyPI JSON, run `<venv>/bin/python <wheel>/pip install pip`; then
`~/.venvs/fim-linux/bin/python -m pip install -e ".[dev]"` in the clone. The interpreter there is the
distribution's `python3` (3.14.4 on 2026-10-10), which is outside the CI matrix 3.11 to 3.13: the
run finds operating-system differences, not Python-version ones. If WSL cannot start or cannot reach
PyPI, say so in the report; do not install anything system-wide.

Gate rules:
- Never pipe, filter or redirect the gate output (no `| tail`, `| Select-String`, `| tee`,
  `2>&1 |`, `> file`). If a log is needed, use `python scripts/gate.py --log <file>`, which writes
  the log itself and keeps the exit status.
- A Claude Code PreToolUse hook (`.claude/settings.json`, script `scripts/hooks/guard_gate.py`)
  blocks any Bash command that runs `scripts/gate.py` together with a pipe, a redirect, `|| true`,
  `; true` or a filter such as tail, head, tee or Select-String. Run other commands separately.
- Gate steps, in order: `ruff check`, `ruff format --check`, `mypy --platform linux`,
  `mypy --platform win32`, `scripts/check_architecture.py`, `pytest` with branch coverage
  `--cov-fail-under=85`. The gate runs every step, prints a summary, and exits non-zero if any failed.
- Never lower a threshold, add a broad ignore, or delete a test to make the gate pass.
  `# noqa`, `# type: ignore` and `# pragma: no cover` need a reason on the same line and are rare.
- Stage files by explicit path, then commit. Commit messages: imperative subject, no trailers
  with addresses.

## 4. Security invariants (each one has a test)

1. The tool never modifies, moves, renames, chmods, truncates or deletes a monitored file. It only
   reads. (Reading can update atime; that is documented, not hidden.)
2. The tool writes only its own files: baseline, key, report outputs. Writes are atomic
   (temp file in the same directory, fsync, rename), never through a symlink or reparse point,
   never overwrite an existing file without `--force`.
3. Every user-supplied path (config roots, `--baseline`, `--key-file`, `--output`, `--config`)
   refuses UNC paths, `\\?\` and `\\.\` device paths, Windows reserved device names, drive-relative
   paths like `C:foo`, and anything URL-like (`scheme://`, `file:`).
4. A baseline whose HMAC does not verify (tampered or wrong key) is refused with exit code 3. It is
   never parsed before verification and never silently trusted. A missing baseline is an error,
   never "no changes".
5. The HMAC key never appears in argv, environment values, logs, output or the baseline. Only the
   key file path is passed around. Key files must not be inside a monitored root.
6. File names, paths, link targets and every other string from the filesystem are hostile. They
   pass through the single sanitiser (`core/sanitize.py`) before any output: table, JSON, JSONL,
   CSV, error messages and exceptions. CSV cells are also formula-neutralised.
7. TOCTOU is reported, not hidden: a file that changes, is swapped or disappears during hashing
   becomes a scan issue (`unstable`, `vanished`), never a crash and never a silent skip.
8. Bounded everything: limits live in `core/limits.py` as named constants. Config may lower them,
   never raise them above the hard ceilings. Hitting a limit marks the run incomplete (exit code
   4) and is never reported as "clean".
9. Only regular files are opened. FIFOs, sockets and devices are recorded by type and never opened.
10. Security invariants use explicit checks that raise, never `assert` (asserts vanish under
    `python -O`; bandit flags them).

## 5. Architecture rules (enforced by `scripts/check_architecture.py`)

Layers, low to high. A module may import only from lower layers (and same-layer modules explicitly
listed in the checker). Every module under `src/fim/` must be assigned a layer, or the check fails.

```
L0 core/      pure logic: models, limits, errors, sanitize, pathrules, globs, policy, diff,
              canonical serialisation, clock protocol. No I/O, no os, no pathlib, no time.
L1 fs/        observe.py     - the ONLY module that touches monitored files (read-only)
              safe_files.py  - the ONLY module that reads/writes the tool's own files
              sandbox.py     - the ONLY module that creates/changes/deletes files, inside the
                               demo's own temp directory; importable only by app/demo.py
   platform/  clock.py (system clock and sleeper), hostinfo.py
   render/    table, json, jsonl, csv renderers: pure, return text
L2 services/  config loader (only importer of yaml), scanner, baseline codec + HMAC, keystore
L3 app/       use cases: baseline, check, watch, demo
L4 cli/       argparse, exit codes, wiring, the only place that prints
```

The checker also enforces:
- No import cycles (all internal imports, including function-level and `TYPE_CHECKING` imports).
- Filesystem APIs are default-deny: `open`, `io.open`, `os.*` file functions, `pathlib`, `shutil`,
  `tempfile`, `glob` are allowed only in the three `fs/` modules above. `observe.py` may contain
  no write/mutate API and no write `O_*` flags.
- `time.*` / `datetime.now` / `sleep` only in `platform/clock.py`. Everything else gets an
  injected `Clock`.
- Third-party imports: only `yaml`, only in the config loader. Banned in `src/`: `subprocess`,
  `socket`, `urllib`, `http`, `pickle`, `marshal`, `shelve`, `random`, `__import__`, `importlib`,
  `eval`, `exec`, `yaml.load` / `yaml.unsafe_load`, `assert`, `print` outside `cli/`.
- The checker fails closed: a syntax error or unresolvable internal import is a failure.

Platform code collects raw facts (`st_mode`, `st_uid`, `st_file_attributes`, reparse tag) and
`core/` interprets them as plain ints, so the interpretation is tested on every OS. Use
`sys.platform == "win32"` / `!= "win32"` guards (mypy understands them), never `os.name` or
`platform.system()`. Avoid `# type: ignore` for platform differences; they become "unused ignore"
errors on the other platform.

## 6. Testing rules

- Tests and the demo only touch temporary directories they create (`tmp_path`). Never scan or
  write the real home, system, project or repo directories. An autouse fixture points `HOME`,
  `USERPROFILE`, `APPDATA`, `LOCALAPPDATA` and `XDG_CONFIG_HOME` at `tmp_path`, and a guard wraps
  the public functions of `fs/observe.py` and `fs/safe_files.py` to fail any test that passes a
  path outside the pytest temp base.
- Deterministic: injected fake `Clock` and `Sleeper`; no `time.sleep`; no wall-clock assertions;
  mtimes set explicitly with `os.utime(..., ns=...)` in tests; random data from a fixed seed.
- A flaky test is a bug: find the root cause. No retries, no `rerunfailures`, no widened timeouts.
- Slow tests (> ~1 s: large trees, subprocess end-to-end, exhaustive Unicode sweeps) get
  `@pytest.mark.slow`. The default gate excludes them, `--full` and CI include them. Target: the
  default gate under 60 s on this machine; if it exceeds 90 s, move tests to `slow` first.
  Coverage of the default (non-slow) run must itself reach 85%.
- Skips only through named markers with a reason (`requires_symlinks`, `posix_only`,
  `windows_only`). CI runs pytest with `-rs` so skips are visible.
- Repository hygiene tests (Phase 1, run on tracked and untracked-not-ignored files):
  - fail on bidi controls, zero-width characters, BOM and control characters other than
    `\n`, `\r`, `\t`. Test data writes such characters as escapes (`"\u202e"`), never raw.
  - fail if any key or secret file is tracked or staged: `*.key`, `*.pem`, `*.p12`, `*.pfx`,
    `id_rsa*`, `.env*`, fim key files (by header) and fim baseline files (by header).
  - fail on email-address patterns in tracked files.
- Every security invariant in section 4 has at least one named test; negative tests (the attack
  is refused) matter more than happy paths. Do not chase test counts.
- CLI tests call `main(argv)` in-process. Only a few `slow` end-to-end tests use a subprocess,
  always with `cwd=tmp_path`.

## 7. Code style

- Python 3.11+ (CI: 3.11, 3.12, 3.13). Type hints everywhere; mypy `strict`.
- Frozen dataclasses (`slots=True`) for models; enums for closed vocabularies.
- Errors: a small hierarchy in `core/errors.py`, each mapped to one exit code in `cli/`.
  No bare `except`; catch `OSError` narrowly and turn it into a recorded scan issue.
- Stdlib first. Adding a runtime dependency needs a decision in PLAN.md Section 0.
- Comments explain why, not what. Docstrings on public functions, short.

## 8. Scope guards (v1)

Do not build: kernel/eBPF/inotify/ReadDirectoryChangesW hooks, auto-remediation or restore,
a network agent, a server, a GUI, ATT&CK mapping, Windows ACL/owner reading, alternate data
streams. A changed file is an observation, not a technique: use CWE only where precise, and only
for the tool's own defensive controls in docs. If a feature seems needed, propose it; do not add it.

## 9. Documentation rules

- Measured numbers only, in `docs/performance.md`, each with machine, OS, Python version, date and
  the exact command (`scripts/bench.py`). No estimates anywhere else; README quotes only these.
- Documented constants (limits, defaults, exit codes) have drift tests against `core/limits.py`
  and the CLI.
- README at release: real pasted output only (from actual runs), a claim-to-evidence table where
  every row names an existing test node or doc (a test checks this), a Limitations section, and a
  "What the tool reads and writes" section.
- `docs/siem-mapping.md` documents the JSONL fields against mini-siem's real parser.

## 10. Release checks (Phase 6)

In a temporary venv outside the repo, deleted afterwards:
1. `python -m build` (sdist and wheel) from a clean checkout of the commit.
2. Install the wheel, run `fim --version`, `fim demo`, and a baseline/check round trip in a temp dir.
3. `pip-audit` on the installed environment.
4. `bandit -r src` with no findings suppressed without a written reason.
5. Paste the real outputs into the phase report. Tags and pushes are mine.
