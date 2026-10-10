# Changelog

All notable changes to `fim`. The format follows [Keep a Changelog](https://keepachangelog.com/),
and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-10

First release. Everything below is new.

### Commands

- `fim init-key`: create the HMAC key file (32 random bytes, mode `0600` on POSIX).
- `fim baseline`: scan the configured paths and write an HMAC-signed baseline and, next to the
  key, a signed rollback anchor.
- `fim check`: verify the baseline (size cap, then signature, then parse, then anchor), rescan
  under the baseline's own policy, and report. Formats `table`, `json`, `jsonl` and `csv`;
  `--min-severity`; `--output` to a new file.
- `fim watch`: `check` on an interval (10 to 86 400 seconds, default 300) with delta output,
  `resolved` events, per-cycle baseline verification and an append log.
- `fim demo`: the whole workflow on throw-away files in a temporary directory, removed afterwards.

### Security properties

- Monitored files are only read; the only module that touches them has no write call.
- The tool's own files are written atomically and never through a link; an existing file needs
  `--force`.
- A baseline that does not verify is refused with exit code 3 before it is parsed; a missing
  baseline is an error, never "no changes".
- Rollback to an older signed baseline is caught by the anchor; a missing anchor is a warning.
- The configuration cannot narrow the scan: `check` and `watch` use the policy stored in the
  signed baseline and report `policy_drift`.
- The key is passed only as a file path; it is never in argv, the environment, output or an
  error message, and a key inside a monitored path is refused.
- Every file name, link target and other filesystem string is escaped before display; JSON and
  JSONL are ASCII-only; CSV cells are formula-neutralised.
- Every bound is a named constant with a hard ceiling; hitting one is exit code 4, never clean.
- No network, subprocess, `pickle`, `eval` or dynamic import in the source; one runtime
  dependency (PyYAML).

### Documentation

- README with real output, "What the tool reads and writes", a claim-to-evidence table checked
  by a test, and a Limitations section.
- `docs/threat-model.md`, `docs/performance.md` (measured, with the commands),
  `docs/report-schema.md` (`fim-report/1`), `docs/siem-mapping.md` (`fim-event/1`).

### Measured limits

- `MAX_BASELINE_BYTES` is 128 MiB (default and ceiling), not 256 MiB as first planned: loading a
  baseline, and a whole `check`, peaked at 6.1 times the file's size (a 238 MiB baseline took
  1.4 GiB). See `docs/performance.md`. The limits are stored in every baseline, so a baseline
  made by a pre-release build under the old limit is refused ("above its hard ceiling") and must
  be made again.
