"""Command line entry point. This is the only place that prints.

Commands so far: ``init-key`` and ``baseline``. Every error the tool raises on purpose is a
``FimError`` and leaves through here as one line on stderr and its exit code (PLAN.md section
1.5); the code never lets a traceback carry a file name to the terminal. Everything printed from
the filesystem or the user's paths goes through the sanitiser first.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence

from fim import __version__
from fim.app.baseline import (
    BaselineOutcome,
    BaselineRequest,
    InitKeyOutcome,
    InitKeyRequest,
    run_baseline,
    run_init_key,
)
from fim.core.errors import ExitCode, FimError
from fim.core.pathrules import display_user_path
from fim.platform.clock import SystemClock
from fim.platform.hostinfo import path_flavour

PROG = "fim"
_MAX_ISSUES_SHOWN = 20
_MAX_SHOWN_PATH_CHARS = 1024


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser."""
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Defensive file integrity monitor (read-only on monitored files).",
        allow_abbrev=False,
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")

    init_key = commands.add_parser(
        "init-key",
        allow_abbrev=False,
        help="create the HMAC key file that protects baselines",
        description=(
            "Create a random 32-byte HMAC key in a new file (mode 0600 on POSIX). The key is "
            "only ever passed around as this file's path."
        ),
    )
    init_key.add_argument("--key-file", required=True, metavar="PATH", help="where to create it")
    init_key.add_argument(
        "--config",
        metavar="FILE",
        help="optional: refuse a key path inside the monitored paths of this configuration",
    )
    init_key.add_argument("--force", action="store_true", help="replace an existing key file")
    init_key.set_defaults(handler=_init_key)

    baseline = commands.add_parser(
        "baseline",
        allow_abbrev=False,
        help="record the state of the monitored paths in a signed baseline",
        description=(
            "Scan the monitored paths of a configuration and write an HMAC-signed baseline, "
            "then update the rollback anchor next to the key."
        ),
    )
    baseline.add_argument("--config", required=True, metavar="FILE", help="configuration file")
    baseline.add_argument("--baseline", required=True, metavar="PATH", help="baseline to write")
    baseline.add_argument(
        "--key-file",
        metavar="PATH",
        help="key file (overrides key_file in the configuration)",
    )
    baseline.add_argument("--force", action="store_true", help="replace an existing baseline")
    baseline.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="if a limit stops the scan, still write the baseline (marked incomplete, exit 4)",
    )
    baseline.set_defaults(handler=_baseline)
    return parser


def _shown(path: str) -> str:
    return display_user_path(path, path_flavour(), _MAX_SHOWN_PATH_CHARS)


def _warn(message: str) -> None:
    print(f"{PROG}: warning: {message}", file=sys.stderr)


def _init_key(args: argparse.Namespace) -> int:
    outcome: InitKeyOutcome = run_init_key(
        InitKeyRequest(key_file=args.key_file, config_path=args.config, force=args.force)
    )
    print(f"key file written: {_shown(outcome.key_path)}")
    print(f"key id: {outcome.key_id}")
    print(
        "Keep the key outside every monitored path, make a backup, and do not share it. "
        "Anyone who can read it can forge a baseline."
    )
    return int(ExitCode.OK)


def _print_baseline(outcome: BaselineOutcome) -> None:
    print(f"baseline written: {_shown(outcome.baseline_path)}")
    print(f"  records: {outcome.records}")
    print(f"  sequence: {outcome.sequence}")
    print(f"  key id: {outcome.key_id}")
    print(f"  complete: {'yes' if outcome.complete else 'no'}")
    state = "updated" if outcome.anchor_existed else "created"
    print(f"  rollback anchor {state}: {_shown(outcome.anchor_path)}")
    for issue in outcome.issues[:_MAX_ISSUES_SHOWN]:
        where = f"{issue.path}: " if issue.path else ""
        _warn(f"{issue.kind.value}: {where}{issue.detail}")
    hidden = len(outcome.issues) - _MAX_ISSUES_SHOWN
    if hidden > 0:
        _warn(f"... and {hidden} more scan issues")
    if not outcome.complete:
        _warn(
            "the scan was incomplete (a limit or the time budget was hit): the baseline covers "
            "only part of the monitored paths"
        )


def _baseline(args: argparse.Namespace) -> int:
    outcome = run_baseline(
        BaselineRequest(
            config_path=args.config,
            baseline_path=args.baseline,
            key_file=args.key_file,
            force=args.force,
            allow_incomplete=args.allow_incomplete,
        ),
        SystemClock(),
    )
    _print_baseline(outcome)
    return int(outcome.exit_code)


def _configure_streams() -> None:
    """A console that cannot encode a character must not crash the tool (PLAN.md D10)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return the process exit code (never raises SystemExit)."""
    _configure_streams()
    parser = build_parser()
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else list(argv))
    except SystemExit as exc:  # argparse exits for --version, --help and usage errors
        code = exc.code
        return code if isinstance(code, int) else int(ExitCode.ERROR)
    handler: Callable[[argparse.Namespace], int] | None = getattr(args, "handler", None)
    if handler is None:
        parser.print_usage(sys.stderr)
        return int(ExitCode.ERROR)
    try:
        return handler(args)
    except FimError as exc:
        print(f"{PROG}: error: {exc.message}", file=sys.stderr)
        return int(exc.exit_code)
