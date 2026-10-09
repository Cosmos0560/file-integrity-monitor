"""The ``init-key`` and ``baseline`` use cases, and the helpers ``check`` and ``watch`` share.

``run_baseline`` follows PLAN.md section 1.2: read the configuration through fs/safe_files.py,
build the policy, load the key, scan, refuse if a configured root is unavailable, encode and sign,
write the baseline atomically, then write the rollback anchor next to the key (D3 amendment).
The new sequence number is the verified anchor's plus one, or 1 when there is no anchor.

``read_verified_baseline`` is the other direction: read the baseline (the size cap is checked
before anything else), verify its MAC, then compare it with the anchor. A baseline that fails any
of that is a ``BaselineIntegrityError`` (exit code 3); a missing anchor is a warning and the run
goes on. Phase 4 wires it into ``check`` and ``watch``.

Nothing here prints: results are returned and the CLI shows them.
"""

from __future__ import annotations

from dataclasses import dataclass

from fim import __version__
from fim.core.clock import Clock
from fim.core.errors import (
    BaselineIntegrityError,
    ConfigError,
    ExitCode,
    LimitReachedError,
    UsageError,
)
from fim.core.limits import DEFAULT_LIMITS, Limits
from fim.core.models import Baseline, BaselineHeader, IssueKind, ScanIssue
from fim.core.pathrules import UserPath, expand_tilde, validate_user_path
from fim.fs import safe_files
from fim.platform import hostinfo
from fim.services import keystore
from fim.services.baseline_codec import (
    DecodedBaseline,
    decode_anchor,
    decode_baseline,
    encode_anchor,
    encode_baseline,
    next_sequence,
    verify_against_anchor,
)
from fim.services.config import Config, load_config
from fim.services.keystore import Key
from fim.services.scanner import FileSystemView, scan

__all__ = [
    "BaselineOutcome",
    "BaselineRequest",
    "InitKeyOutcome",
    "InitKeyRequest",
    "VerifiedBaseline",
    "read_config",
    "read_verified_baseline",
    "resolve_path_argument",
    "run_baseline",
    "run_init_key",
]

_MAX_ISSUES_IN_MESSAGE = 5


def resolve_path_argument(raw: str, home: UserPath | None = None) -> str:
    """A path from the command line, checked by the path rules, with a leading ``~`` expanded.

    Other paths are returned as given: safe_files applies the same rules again when it opens them.
    """
    path = validate_user_path(raw, hostinfo.path_flavour(), allow_tilde=True)
    if not path.tilde:
        return raw
    if home is None:
        raise UsageError("the path starts with '~' but the home directory is unknown")
    return expand_tilde(path, home).text


def read_config(path: str) -> Config:
    """Read the configuration file safely (no-follow, capped, path rules) and validate it."""
    home = hostinfo.home_directory()
    data = safe_files.read_own_file(
        resolve_path_argument(path, home),
        max_bytes=DEFAULT_LIMITS.max_config_bytes,
        label="configuration file",
    )
    return load_config(data, flavour=hostinfo.path_flavour(), home=home)


def _root_texts(config: Config) -> tuple[str, ...]:
    return tuple(root.path.text for root in config.policy.roots)


def _key_path(override: str | None, config: Config | None, home: UserPath | None) -> str:
    if override is not None:
        return resolve_path_argument(override, home)
    if config is not None and config.key_file is not None:
        return config.key_file.text
    raise UsageError("no key file: give --key-file, or set key_file in the configuration")


# ---- init-key ------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class InitKeyRequest:
    key_file: str
    config_path: str | None  # optional: only to refuse a key path inside its monitored paths
    force: bool


@dataclass(frozen=True, slots=True)
class InitKeyOutcome:
    key_path: str
    key_id: str
    anchor_path: str


def run_init_key(request: InitKeyRequest) -> InitKeyOutcome:
    """Create a key file. The key is never returned, only its id."""
    home = hostinfo.home_directory()
    roots: tuple[str, ...] = ()
    if request.config_path is not None:
        roots = _root_texts(read_config(request.config_path))
    path = resolve_path_argument(request.key_file, home)
    key = keystore.init_key(path, force=request.force, avoid_roots=roots)
    return InitKeyOutcome(key_path=path, key_id=key.key_id, anchor_path=keystore.anchor_path(path))


# ---- baseline ------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BaselineRequest:
    config_path: str
    baseline_path: str
    key_file: str | None  # overrides key_file in the configuration
    force: bool


@dataclass(frozen=True, slots=True)
class BaselineOutcome:
    baseline_path: str
    anchor_path: str
    key_id: str
    sequence: int
    records: int
    complete: bool
    issues: tuple[ScanIssue, ...]
    size_bytes: int
    anchor_existed: bool

    @property
    def exit_code(self) -> ExitCode:
        """INCOMPLETE if a limit or the time budget stopped the scan, else OK."""
        return ExitCode.OK if self.complete else ExitCode.INCOMPLETE


def _refuse_unavailable_roots(issues: tuple[ScanIssue, ...]) -> None:
    """A baseline of a root that is missing, a link or unreadable would be a false baseline."""
    unavailable = [issue for issue in issues if issue.kind is IssueKind.ROOT_UNAVAILABLE]
    if not unavailable:
        return
    shown = "; ".join(
        f"{issue.path}: {issue.detail}" for issue in unavailable[:_MAX_ISSUES_IN_MESSAGE]
    )
    more = len(unavailable) - _MAX_ISSUES_IN_MESSAGE
    suffix = f" (and {more} more)" if more > 0 else ""
    raise ConfigError(f"cannot make a baseline, a monitored path is unavailable: {shown}{suffix}")


def _load_anchor_sequence(key: Key, key_path: str) -> tuple[int, bool]:
    """The next sequence number and whether an anchor existed. A bad anchor raises (exit 3)."""
    raw = keystore.read_anchor_bytes(key_path)
    if raw is None:
        return next_sequence(None), False
    return next_sequence(decode_anchor(raw, key)), True


def run_baseline(
    request: BaselineRequest, clock: Clock, *, view: FileSystemView | None = None
) -> BaselineOutcome:
    """Scan the configured paths and write a signed baseline and its rollback anchor.

    Raises a FimError for everything that stops it: unreadable configuration or key, a monitored
    path that is unavailable, a bad anchor, an existing baseline without ``force``, a baseline
    that would exceed the size limit. An incomplete scan still writes the baseline (its header
    says ``complete: false``) and the outcome carries exit code 4.
    """
    home = hostinfo.home_directory()
    config = read_config(request.config_path)
    policy = config.policy
    roots = _root_texts(config)
    key_path = _key_path(request.key_file, config, home)
    baseline_path = resolve_path_argument(request.baseline_path, home)
    # Fail before the scan, not after it, for the cheap reasons.
    safe_files.ensure_can_write(
        baseline_path, force=request.force, avoid_roots=roots, label="baseline file"
    )
    key = keystore.load_key(key_path, avoid_roots=roots)
    sequence, anchor_existed = _load_anchor_sequence(key, key_path)

    result = scan(policy, clock, view=view)
    _refuse_unavailable_roots(result.issues)

    header = BaselineHeader(
        tool_version=__version__,
        created_at=clock.now(),
        sequence=sequence,
        host=config.host_label or hostinfo.default_host_label(),
        platform=hostinfo.platform_name(),
        policy=policy,
        complete=result.complete,
        limits=policy.limits,
    )
    encoded = encode_baseline(Baseline(header=header, records=result.records), key)
    if len(encoded.data) > policy.limits.max_baseline_bytes:
        raise LimitReachedError(
            f"the baseline would be {len(encoded.data)} bytes, above the "
            f"{policy.limits.max_baseline_bytes} byte limit; nothing was written. "
            "Narrow the monitored paths or add excludes"
        )
    safe_files.write_own_file(
        baseline_path,
        encoded.data,
        force=request.force,
        avoid_roots=roots,
        label="baseline file",
    )
    # The baseline is written first: if the anchor cannot be, the next run with --force repeats
    # the same sequence number and fixes it, whereas the other order would leave an anchor that
    # names a baseline that does not exist.
    keystore.write_anchor_bytes(key_path, encode_anchor(key, sequence, encoded.payload_sha256))
    return BaselineOutcome(
        baseline_path=baseline_path,
        anchor_path=keystore.anchor_path(key_path),
        key_id=encoded.key_id,
        sequence=sequence,
        records=len(result.records),
        complete=result.complete,
        issues=result.issues,
        size_bytes=len(encoded.data),
        anchor_existed=anchor_existed,
    )


# ---- reading a baseline back (used by check and watch in Phase 4) --------------------------------


@dataclass(frozen=True, slots=True)
class VerifiedBaseline:
    """A baseline that passed the MAC check and, if an anchor exists, the anchor check."""

    decoded: DecodedBaseline
    warnings: tuple[str, ...]


def read_verified_baseline(
    baseline_path: str,
    key: Key,
    key_path: str,
    *,
    limits: Limits = DEFAULT_LIMITS,
    avoid_roots: tuple[str, ...] = (),
) -> VerifiedBaseline:
    """Read, verify and anchor-check the baseline; raise BaselineIntegrityError (exit 3) if bad.

    The size cap is applied before reading, the MAC before parsing. A missing baseline file is a
    FileMissingError (exit 2), never "no changes". A missing anchor gives a warning only.
    """
    try:
        data = safe_files.read_own_file(
            baseline_path,
            max_bytes=limits.max_baseline_bytes,
            avoid_roots=avoid_roots,
            label="baseline file",
        )
    except safe_files.FileTooLargeError:
        raise BaselineIntegrityError(
            f"the baseline is not trustworthy: it is larger than the "
            f"{limits.max_baseline_bytes} byte limit"
        ) from None
    decoded = decode_baseline(data, key, max_bytes=limits.max_baseline_bytes)
    raw_anchor = keystore.read_anchor_bytes(key_path)
    if raw_anchor is None:
        warning = (
            f"no rollback anchor found next to the key ({keystore.anchor_path(key_path)}): "
            "an older baseline put back in place could not be detected"
        )
        return VerifiedBaseline(decoded, (warning,))
    verify_against_anchor(decode_anchor(raw_anchor, key), decoded)
    return VerifiedBaseline(decoded, ())
