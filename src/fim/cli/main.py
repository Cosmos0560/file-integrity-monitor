"""Command line entry point. This is the only place that prints."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from fim import __version__

PROG = "fim"


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser. Subcommands arrive in later phases."""
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Defensive file integrity monitor (read-only on monitored files).",
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return the process exit code (never raises SystemExit)."""
    parser = build_parser()
    try:
        parser.parse_args(sys.argv[1:] if argv is None else list(argv))
    except SystemExit as exc:  # argparse exits for --version, --help and usage errors
        code = exc.code
        return code if isinstance(code, int) else 2
    parser.print_usage(sys.stderr)
    return 2
