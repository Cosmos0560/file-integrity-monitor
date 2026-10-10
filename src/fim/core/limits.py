"""Every bound in one place (PLAN.md D11).

Each limit has a default and a hard ceiling. Configuration may lower a value or raise it up to
its ceiling, never beyond. Hitting a limit during a run marks the run incomplete (exit code 4);
it is never reported as clean. Documentation quotes these values, and a drift test compares the
two.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields, replace
from typing import Any

from fim.core.errors import ConfigError

KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB

# name = default, NAME_CEILING = hard ceiling.
MAX_ROOTS = 64
MAX_ROOTS_CEILING = 64
MAX_FILES = 200_000  # entries including directories
MAX_FILES_CEILING = 1_000_000
MAX_DEPTH = 64
MAX_DEPTH_CEILING = 128
MAX_PATH_CHARS = 4096
MAX_PATH_CHARS_CEILING = 4096
MAX_HASH_FILE_BYTES = 256 * MIB
MAX_HASH_FILE_BYTES_CEILING = 4 * GIB
MAX_RUN_SECONDS = 900
MAX_RUN_SECONDS_CEILING = 3600
# Planned as 256 MiB and lowered after Phase 6 measured it (docs/performance.md, PLAN.md D11):
# reading and parsing a baseline peaked at about 6.1 times its size in memory, so 256 MiB would
# have needed about 1.5 GiB. 128 MiB keeps the peak under 1 GiB.
MAX_BASELINE_BYTES = 128 * MIB
MAX_BASELINE_BYTES_CEILING = 128 * MIB
MAX_CONFIG_BYTES = 256 * KIB
MAX_CONFIG_BYTES_CEILING = 256 * KIB
MAX_PATTERNS = 256
MAX_PATTERNS_CEILING = 256
MAX_PATTERN_CHARS = 512
MAX_PATTERN_CHARS_CEILING = 512
MAX_FINDINGS_REPORTED = 10_000
MAX_FINDINGS_REPORTED_CEILING = 10_000
MAX_EVIDENCE_CHARS = 1024
MAX_EVIDENCE_CHARS_CEILING = 1024
MAX_KEY_FILE_BYTES = 4096
MAX_KEY_FILE_BYTES_CEILING = 4096

# Fixed values with no ceiling to configure.
HASH_CHUNK_BYTES = 1 * MIB
WATCH_INTERVAL_MIN_SECONDS = 10
WATCH_INTERVAL_DEFAULT_SECONDS = 300
WATCH_INTERVAL_MAX_SECONDS = 86_400


_CEILING_BY_NAME: Mapping[str, int] = {
    "max_roots": MAX_ROOTS_CEILING,
    "max_files": MAX_FILES_CEILING,
    "max_depth": MAX_DEPTH_CEILING,
    "max_path_chars": MAX_PATH_CHARS_CEILING,
    "max_hash_file_bytes": MAX_HASH_FILE_BYTES_CEILING,
    "max_run_seconds": MAX_RUN_SECONDS_CEILING,
    "max_baseline_bytes": MAX_BASELINE_BYTES_CEILING,
    "max_config_bytes": MAX_CONFIG_BYTES_CEILING,
    "max_patterns": MAX_PATTERNS_CEILING,
    "max_pattern_chars": MAX_PATTERN_CHARS_CEILING,
    "max_findings_reported": MAX_FINDINGS_REPORTED_CEILING,
    "max_evidence_chars": MAX_EVIDENCE_CHARS_CEILING,
    "max_key_file_bytes": MAX_KEY_FILE_BYTES_CEILING,
}


def _check_value(name: str, value: object) -> None:
    # bool is an int subclass; True would silently mean 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"limit '{name}' must be an integer")
    if value < 1:
        raise ConfigError(f"limit '{name}' must be at least 1")
    ceiling = _CEILING_BY_NAME[name]
    if value > ceiling:
        raise ConfigError(f"limit '{name}' is {value}, above its hard ceiling of {ceiling}")


@dataclass(frozen=True, slots=True)
class Limits:
    """The effective limits of a run. Every field is between 1 and its hard ceiling."""

    max_roots: int = MAX_ROOTS
    max_files: int = MAX_FILES
    max_depth: int = MAX_DEPTH
    max_path_chars: int = MAX_PATH_CHARS
    max_hash_file_bytes: int = MAX_HASH_FILE_BYTES
    max_run_seconds: int = MAX_RUN_SECONDS
    max_baseline_bytes: int = MAX_BASELINE_BYTES
    max_config_bytes: int = MAX_CONFIG_BYTES
    max_patterns: int = MAX_PATTERNS
    max_pattern_chars: int = MAX_PATTERN_CHARS
    max_findings_reported: int = MAX_FINDINGS_REPORTED
    max_evidence_chars: int = MAX_EVIDENCE_CHARS
    max_key_file_bytes: int = MAX_KEY_FILE_BYTES

    def __post_init__(self) -> None:
        for field in fields(self):
            _check_value(field.name, getattr(self, field.name))

    def with_overrides(self, overrides: Mapping[str, Any]) -> Limits:
        """A copy with ``overrides`` applied; unknown names and out-of-range values are refused.

        The values come straight from the configuration file, so their type is checked here.
        """
        for name in overrides:
            if name not in _CEILING_BY_NAME:
                raise ConfigError(f"unknown limit '{name}'")
        return replace(self, **overrides)


CEILINGS = Limits(**_CEILING_BY_NAME)
DEFAULT_LIMITS = Limits()
