"""The ``watch`` use case (PLAN.md D9): ``check`` repeated on an interval, reporting what changed.

Each cycle is a full ``check``: the baseline file is read again, its signature and the rollback
anchor are verified, the paths of the baseline's policy are scanned and compared. The first cycle
reports every finding; later cycles report only findings that are new (a finding's id is stable
while the facts behind it are), plus a ``resolved`` event for every finding that is gone.
``repeat`` reports everything every cycle.

If the baseline stops verifying mid-run (replaced, edited, rolled back, deleted), ``watch`` does
not stop and does not trust it: it raises one critical ``baseline_integrity`` event, keeps
checking against the last baseline that did verify (held in memory), and exits with code 3 when
it is stopped. A baseline that never verified at the start is an error before any cycle runs.

The interval is measured from the end of one cycle to the start of the next, so cycles never
overlap. A scan that did not finish (a limit, the time budget) reports no ``resolved`` events:
the missing findings may only be the files it never reached.

Exit code when stopped: 3 if the baseline ever failed to verify, else 4 if any scan was
incomplete, else 1 if any finding was reported, else 0 (a stopped watch has no "last" report, so
"something was reported during the run" is the useful reading for scripts and ``--max-cycles``).

Nothing here prints or sleeps by itself: events go to ``emit`` (stdout, wired by the CLI) or to an
append-only log file, warnings go to ``notify``, and the pause is the injected ``Sleeper``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from fim import __version__
from fim.app.baseline import (
    read_config,
    read_verified_baseline,
    resolve_key_path,
    resolve_path_argument,
)
from fim.core.clock import Clock, Sleeper
from fim.core.diff import (
    baseline_integrity_finding,
    build_report,
    compare,
    policy_drift_finding,
    resolved_finding,
)
from fim.core.errors import BaselineIntegrityError, ExitCode, FimError, UsageError, worst
from fim.core.limits import (
    DEFAULT_LIMITS,
    WATCH_INTERVAL_DEFAULT_SECONDS,
    WATCH_INTERVAL_MAX_SECONDS,
    WATCH_INTERVAL_MIN_SECONDS,
    Limits,
)
from fim.core.models import Baseline, Finding, IssueKind, ScanIssue, Severity
from fim.fs import safe_files
from fim.platform import hostinfo
from fim.render.csv_out import csv_header, csv_rows
from fim.render.jsonl import EventContext, event_lines
from fim.services import keystore
from fim.services.keystore import Key
from fim.services.scanner import FileSystemView, scan

__all__ = [
    "WATCH_FORMATS",
    "WatchOutcome",
    "WatchRequest",
    "run_watch",
]

WATCH_FORMATS = ("jsonl", "csv")


@dataclass(frozen=True, slots=True)
class WatchRequest:
    baseline_path: str
    key_file: str | None  # overrides key_file in the configuration
    config_path: str | None  # optional: key location and policy drift
    interval_seconds: float = WATCH_INTERVAL_DEFAULT_SECONDS
    max_cycles: int | None = None  # None: run until stopped
    repeat: bool = False  # report every finding every cycle, not only the new ones
    output_format: str = "jsonl"
    output_path: str | None = None  # an append log; None: events go to ``emit``
    force: bool = False  # replace an existing output file
    min_severity: Severity = Severity.INFO


@dataclass(frozen=True, slots=True)
class WatchOutcome:
    cycles: int  # cycles that ran to the end
    events: int  # lines written, including resolved and integrity events
    findings_reported: int  # events other than resolved ones
    interrupted: bool  # stopped by KeyboardInterrupt
    baseline_failed: bool  # the baseline stopped verifying at some point
    incomplete: bool  # some cycle did not finish its scan
    exit_code: ExitCode


def _validate(request: WatchRequest) -> None:
    if request.output_format not in WATCH_FORMATS:
        raise UsageError(f"--format for watch must be one of: {', '.join(WATCH_FORMATS)}")
    interval = request.interval_seconds
    if not WATCH_INTERVAL_MIN_SECONDS <= interval <= WATCH_INTERVAL_MAX_SECONDS:
        raise UsageError(
            f"--interval must be between {WATCH_INTERVAL_MIN_SECONDS} and "
            f"{WATCH_INTERVAL_MAX_SECONDS} seconds"
        )
    if request.max_cycles is not None and request.max_cycles < 1:
        raise UsageError("--max-cycles must be at least 1")


def _scan_notes(issues: tuple[ScanIssue, ...], baseline: Baseline) -> list[str]:
    notes = [
        f"the scan stopped early: {issue.detail}"
        for issue in issues
        if issue.kind in (IssueKind.LIMIT_REACHED, IssueKind.TIME_BUDGET)
    ]
    if not baseline.header.complete:
        notes.append(
            "the baseline was made from an incomplete scan, so changes beyond its limit "
            "cannot be detected"
        )
    return notes


class _Watcher:
    """One run of ``watch``: the verified baseline in use, what was reported, the counters."""

    def __init__(
        self,
        request: WatchRequest,
        clock: Clock,
        sleeper: Sleeper,
        view: FileSystemView | None,
        write: Callable[[list[str]], None],
        notify: Callable[[str], None],
    ) -> None:
        self.request = request
        self.clock = clock
        self.sleeper = sleeper
        self.view = view
        self.write = write
        self.notify = notify
        self.told: set[str] = set()  # a standing condition is said once, not every cycle
        self.previous: dict[str, Finding] = {}
        self.cycles = 0
        self.events = 0
        self.findings_reported = 0
        self.baseline_failed = False
        self.incomplete = False

    def tell(self, message: str) -> None:
        if message not in self.told:
            self.told.add(message)
            self.notify(message)

    def run(
        self,
        baseline: Baseline,
        key_id: str,
        reread: Callable[[], tuple[Baseline, str, tuple[str, ...]]],
        drift: list[Finding],
    ) -> None:
        """Cycle until ``max_cycles``; ``reread`` verifies the baseline file again each time."""
        while True:
            extra = list(drift)
            if self.cycles > 0:
                try:
                    fresh, fresh_key_id, warnings = reread()
                    if fresh.header.sequence < baseline.header.sequence:
                        raise BaselineIntegrityError(
                            f"the baseline is sequence {fresh.header.sequence}, older than "
                            f"{baseline.header.sequence} in use: possible rollback"
                        )
                except FimError as exc:
                    self.baseline_failed = True
                    message = (
                        "the baseline no longer verifies; still checking against the last "
                        f"verified one: {exc.message}"
                    )
                    extra.append(baseline_integrity_finding(message))
                    self.tell(message)
                else:
                    baseline, key_id = fresh, fresh_key_id
                    for warning in warnings:
                        self.tell(warning)
            self.cycle(baseline, key_id, extra)
            if self.request.max_cycles is not None and self.cycles >= self.request.max_cycles:
                return
            self.sleeper.sleep(self.request.interval_seconds)

    def cycle(self, baseline: Baseline, key_id: str, extra: list[Finding]) -> None:
        request = self.request
        result = scan(baseline.header.policy, self.clock, view=self.view)
        complete = result.complete and baseline.header.complete
        report = build_report(
            compare(baseline, result),
            extra=extra,
            header=baseline.header,
            key_id=key_id,
            generated_at=self.clock.now(),
            tool_version=__version__,
            complete=complete,
            min_severity=request.min_severity,
            max_findings=baseline.header.policy.limits.max_findings_reported,
        )
        if not complete:
            self.incomplete = True
            for note in _scan_notes(result.issues, baseline):
                self.tell(note)
        if report.truncated:
            self.tell(
                f"more findings than the {len(report.findings)} that can be listed: a watch "
                "cannot track the ones that are not listed"
            )
        current = {finding.finding_id: finding for finding in report.findings}
        if request.repeat or self.cycles == 0:
            reported = list(report.findings)
        else:
            reported = [item for key, item in current.items() if key not in self.previous]
        if complete:
            gone = [self.previous[key] for key in sorted(self.previous.keys() - current.keys())]
            resolved = [resolved_finding(original) for original in gone]
            self.previous = current
        else:
            resolved = []
            self.previous = {**self.previous, **current}
        context = EventContext(
            timestamp=report.generated_at,
            host=baseline.header.host,
            baseline_sequence=baseline.header.sequence,
            tool_version=report.tool_version,
        )
        events = [*reported, *resolved]
        if request.output_format == "csv":
            self.write(csv_rows(events, context))
        else:
            self.write(event_lines(events, context))
        self.events += len(events)
        self.findings_reported += len(reported)
        self.cycles += 1


def run_watch(
    request: WatchRequest,
    clock: Clock,
    sleeper: Sleeper,
    *,
    emit: Callable[[str], None],
    notify: Callable[[str], None],
    view: FileSystemView | None = None,
) -> WatchOutcome:
    """Verify the baseline, then check on an interval until stopped or ``max_cycles`` is reached."""
    _validate(request)
    home = hostinfo.home_directory()
    config = read_config(request.config_path) if request.config_path is not None else None
    key_path = resolve_key_path(request.key_file, config, home)
    config_roots = tuple(root.path.text for root in config.policy.roots) if config else ()
    limits: Limits = config.policy.limits if config is not None else DEFAULT_LIMITS
    baseline_path = resolve_path_argument(request.baseline_path, home)
    output_path = (
        resolve_path_argument(request.output_path, home)
        if request.output_path is not None
        else None
    )

    key: Key = keystore.load_key(key_path, avoid_roots=config_roots)
    verified = read_verified_baseline(baseline_path, key, key_path, limits=limits)
    baseline = verified.decoded.baseline
    roots = tuple(root.path.text for root in baseline.header.policy.roots)
    safe_files.ensure_outside_roots(key_path, roots, label="key file")
    drift: list[Finding] = []
    if config is not None and config.policy.digest != baseline.header.policy.digest:
        drift.append(policy_drift_finding(baseline.header.policy.digest, config.policy.digest))

    log = (
        safe_files.open_append_log(
            output_path, force=request.force, avoid_roots=roots, label="event log"
        )
        if output_path is not None
        else None
    )

    def write(lines: list[str]) -> None:
        if not lines:
            return
        if log is not None:
            log.append(lines)
        else:
            emit("".join(lines))

    def reread() -> tuple[Baseline, str, tuple[str, ...]]:
        fresh = read_verified_baseline(baseline_path, key, key_path, limits=limits)
        return fresh.decoded.baseline, fresh.decoded.key_id, fresh.warnings

    watcher = _Watcher(request, clock, sleeper, view, write, notify)
    interrupted = False
    try:
        for warning in verified.warnings:
            watcher.tell(warning)
        if request.output_format == "csv":
            write([csv_header()])
        watcher.run(baseline, verified.decoded.key_id, reread, drift)
    except KeyboardInterrupt:
        interrupted = True
    finally:
        if log is not None:
            log.close()
    codes = [ExitCode.OK]
    if watcher.baseline_failed:
        codes.append(ExitCode.INTEGRITY)
    if watcher.incomplete:
        codes.append(ExitCode.INCOMPLETE)
    if watcher.findings_reported:
        codes.append(ExitCode.FINDINGS)
    return WatchOutcome(
        cycles=watcher.cycles,
        events=watcher.events,
        findings_reported=watcher.findings_reported,
        interrupted=interrupted,
        baseline_failed=watcher.baseline_failed,
        incomplete=watcher.incomplete,
        exit_code=worst(codes),
    )
