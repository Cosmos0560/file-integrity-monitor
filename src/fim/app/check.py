"""The ``check`` use case (PLAN.md section 1.2): rescan and compare with the signed baseline.

Order, fixed on purpose:

1. read the configuration (optional: only for the key location and for policy drift);
2. load the key, then read the baseline: size cap, MAC, only then parse, then the rollback anchor
   (a mismatch is exit code 3, a missing anchor a warning) via ``read_verified_baseline``;
3. refuse a key inside one of the baseline's monitored paths, and an output file inside one;
4. scan with the **baseline's** policy, never the configuration's (D4: the configuration is not
   authenticated, so it cannot narrow what is watched); a configuration whose policy digest differs
   gives a ``policy_drift`` finding;
5. compare, build the report, render it, write it (atomically, no clobber) or hand it back.

Exit code: 0 clean and complete, 1 findings at or above ``min_severity``, 4 incomplete (a limit,
the time budget, or a baseline that itself was incomplete), and the errors 2 and 3 as exceptions;
the highest-priority applicable code wins (3 > 2 > 4 > 1 > 0). A missing baseline is an error,
never "no changes".

Nothing here prints; the CLI shows ``text`` or the output path.
"""

from __future__ import annotations

from dataclasses import dataclass

from fim import __version__
from fim.app.baseline import (
    read_config,
    read_verified_baseline,
    resolve_key_path,
    resolve_path_argument,
)
from fim.core.clock import Clock
from fim.core.diff import build_report, compare, policy_drift_finding
from fim.core.errors import ExitCode, UsageError, worst
from fim.core.limits import DEFAULT_LIMITS
from fim.core.models import Finding, IssueKind, Report, ScanIssue, Severity
from fim.fs import safe_files
from fim.platform import hostinfo
from fim.render.csv_out import render_csv
from fim.render.json_out import render_json
from fim.render.jsonl import EventContext, render_jsonl
from fim.render.table import render_table
from fim.services import keystore
from fim.services.scanner import FileSystemView, scan

__all__ = [
    "FORMATS",
    "FORMATS_WITH_NOTES",
    "CheckOutcome",
    "CheckRequest",
    "exit_code_for",
    "run_check",
]

FORMATS = ("table", "json", "jsonl", "csv")
# These two carry the notes and warnings inside the text; jsonl and csv are data streams, so the
# CLI says them on stderr instead.
FORMATS_WITH_NOTES = ("table", "json")


@dataclass(frozen=True, slots=True)
class CheckRequest:
    baseline_path: str
    key_file: str | None  # overrides key_file in the configuration
    config_path: str | None  # optional: key location and policy drift
    output_format: str = "table"
    output_path: str | None = None
    force: bool = False
    min_severity: Severity = Severity.INFO


@dataclass(frozen=True, slots=True)
class CheckOutcome:
    report: Report
    notes: tuple[str, ...]
    text: str | None  # the rendered report, unless it was written to ``output_path``
    output_path: str | None
    exit_code: ExitCode
    notes_in_text: bool = True  # False for jsonl and csv: the notes must be shown separately


def exit_code_for(report: Report) -> ExitCode:
    """The exit code a verified report earns: findings (1) and/or incompleteness (4)."""
    codes: list[ExitCode] = [ExitCode.OK]
    if report.summary.by_kind:
        codes.append(ExitCode.FINDINGS)
    if not report.complete:
        codes.append(ExitCode.INCOMPLETE)
    return worst(codes)


def _incomplete_notes(issues: tuple[ScanIssue, ...], baseline_complete: bool) -> list[str]:
    notes = [
        f"the scan stopped early: {issue.detail}"
        for issue in issues
        if issue.kind in (IssueKind.LIMIT_REACHED, IssueKind.TIME_BUDGET)
    ]
    if not baseline_complete:
        notes.append(
            "the baseline was made from an incomplete scan, so changes beyond its limit "
            "cannot be detected"
        )
    return notes


def run_check(
    request: CheckRequest, clock: Clock, *, view: FileSystemView | None = None
) -> CheckOutcome:
    """Verify the baseline, rescan under its policy and report the differences."""
    if request.output_format not in FORMATS:
        raise UsageError(f"--format must be one of: {', '.join(FORMATS)}")
    home = hostinfo.home_directory()
    config = read_config(request.config_path) if request.config_path is not None else None
    key_path = resolve_key_path(request.key_file, config, home)
    config_roots = tuple(root.path.text for root in config.policy.roots) if config else ()
    limits = config.policy.limits if config is not None else DEFAULT_LIMITS
    baseline_path = resolve_path_argument(request.baseline_path, home)
    output_path = (
        resolve_path_argument(request.output_path, home)
        if request.output_path is not None
        else None
    )

    key = keystore.load_key(key_path, avoid_roots=config_roots)
    verified = read_verified_baseline(baseline_path, key, key_path, limits=limits)
    baseline = verified.decoded.baseline
    policy = baseline.header.policy
    roots = tuple(root.path.text for root in policy.roots)
    # The baseline's own roots are only known now that it is verified (CLAUDE.md invariant 5).
    safe_files.ensure_outside_roots(key_path, roots, label="key file")
    if output_path is not None:
        safe_files.ensure_can_write(
            output_path, force=request.force, avoid_roots=roots, label="report file"
        )

    result = scan(policy, clock, view=view)
    comparison = compare(baseline, result)
    extra: list[Finding] = []
    if config is not None and config.policy.digest != policy.digest:
        extra.append(policy_drift_finding(policy.digest, config.policy.digest))

    complete = result.complete and baseline.header.complete
    report = build_report(
        comparison,
        extra=extra,
        header=baseline.header,
        key_id=verified.decoded.key_id,
        generated_at=clock.now(),
        tool_version=__version__,
        complete=complete,
        min_severity=request.min_severity,
        max_findings=policy.limits.max_findings_reported,
    )
    notes = (
        *verified.warnings,
        *_incomplete_notes(result.issues, baseline.header.complete),
    )
    context = EventContext(
        timestamp=report.generated_at,
        host=baseline.header.host,
        baseline_sequence=baseline.header.sequence,
        tool_version=report.tool_version,
    )
    if request.output_format == "json":
        text = render_json(report, notes)
    elif request.output_format == "jsonl":
        text = render_jsonl(report.findings, context)
    elif request.output_format == "csv":
        text = render_csv(report.findings, context)
    else:
        text = render_table(report, notes)
    if output_path is not None:
        safe_files.write_own_file(
            output_path,
            text.encode("utf-8"),
            force=request.force,
            avoid_roots=roots,
            label="report file",
        )
        text_out = None
    else:
        text_out = text
    return CheckOutcome(
        report=report,
        notes=tuple(notes),
        text=text_out,
        output_path=output_path,
        exit_code=exit_code_for(report),
        notes_in_text=request.output_format in FORMATS_WITH_NOTES,
    )
