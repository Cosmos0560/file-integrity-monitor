"""The effective policy (PLAN.md D4): building it, hashing it, and applying it to paths.

``build_policy`` is the only way a Policy gets its digest, which is SHA-256 over the canonical
JSON of everything that decides what a scan covers and how it is judged: roots (in the listed
order, because ``root_index`` refers to it), their severities, includes, excludes and
one-file-system flags, the global excludes, the symlink policy and the effective limits. The
baseline stores the policy; ``check`` trusts the baseline's copy and reports ``policy_drift``
when a configuration file hashes differently.

Rules are compiled once per run. A path belongs to its most specific root: nested roots are
scanned on their own, and the enclosing root skips them.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any

from fim.core.canonical import canonical_json
from fim.core.errors import ConfigError
from fim.core.globs import Pattern, compile_pattern
from fim.core.limits import Limits
from fim.core.models import Policy, RootPolicy, SymlinkPolicy
from fim.core.pathrules import Flavour, UserPath, is_within

__all__ = [
    "POLICY_DIGEST_VERSION",
    "RootRules",
    "build_policy",
    "compile_rules",
    "component_key",
    "compute_digest",
    "digest_is_valid",
    "owning_root",
    "policy_document",
]

POLICY_DIGEST_VERSION = "fim-policy/1"


def component_key(flavour: Flavour, drive: str, parts: Sequence[str]) -> tuple[str, ...]:
    """A comparable form of an absolute path: case-folded on Windows, exact on POSIX."""
    if flavour is Flavour.WINDOWS:
        return (drive.casefold(), *(part.casefold() for part in parts))
    return (drive, *parts)


def _root_key(path: UserPath) -> tuple[str, ...]:
    return component_key(path.flavour, path.drive, path.parts)


def _root_document(root: RootPolicy) -> dict[str, Any]:
    path = root.path
    return {
        "flavour": path.flavour.value,
        "drive": path.drive,
        "parts": list(path.parts),
        "severity": root.severity.label,
        "include": list(root.include),
        "exclude": list(root.exclude),
        "one_file_system": root.one_file_system,
    }


def policy_document(
    roots: Sequence[RootPolicy],
    exclude: Sequence[str],
    symlinks: SymlinkPolicy,
    limits: Limits,
) -> dict[str, Any]:
    """The plain-data form of a policy; the digest and the baseline payload are made from it."""
    return {
        "version": POLICY_DIGEST_VERSION,
        "roots": [_root_document(root) for root in roots],
        "exclude": list(exclude),
        "symlinks": symlinks.value,
        "limits": asdict(limits),
    }


def compute_digest(
    roots: Sequence[RootPolicy],
    exclude: Sequence[str],
    symlinks: SymlinkPolicy,
    limits: Limits,
) -> str:
    """64 lower-case hex characters identifying this exact policy."""
    document = policy_document(roots, exclude, symlinks, limits)
    return hashlib.sha256(canonical_json(document)).hexdigest()


def _validate_roots(roots: Sequence[RootPolicy], limits: Limits) -> None:
    if not roots:
        raise ConfigError("at least one monitored path is required")
    if len(roots) > limits.max_roots:
        raise ConfigError(f"more than {limits.max_roots} monitored paths")
    if len({root.path.flavour for root in roots}) != 1:
        raise ConfigError("monitored paths mix Windows and POSIX styles")
    seen: set[tuple[str, ...]] = set()
    for root in roots:
        key = _root_key(root.path)
        if key in seen:
            raise ConfigError(f"monitored path listed twice: '{root.path.display()}'")
        seen.add(key)


def build_policy(
    roots: Sequence[RootPolicy],
    exclude: Sequence[str],
    symlinks: SymlinkPolicy,
    limits: Limits,
) -> Policy:
    """Validate the pieces and return the Policy with its digest.

    Every pattern is compiled once here, so a bad pattern or too many patterns is a ConfigError
    before any scan starts.
    """
    _validate_roots(roots, limits)
    total = len(exclude) + sum(len(root.include) + len(root.exclude) for root in roots)
    if total > limits.max_patterns:
        raise ConfigError(f"more than {limits.max_patterns} include/exclude patterns")
    policy = Policy(
        roots=tuple(roots),
        exclude=tuple(exclude),
        symlinks=symlinks,
        limits=limits,
        digest=compute_digest(roots, exclude, symlinks, limits),
    )
    compile_rules(policy)
    return policy


def digest_is_valid(policy: Policy) -> bool:
    """True if ``policy.digest`` matches its content (a decoded baseline must pass this)."""
    expected = compute_digest(policy.roots, policy.exclude, policy.symlinks, policy.limits)
    return expected == policy.digest


# ---- applying the policy -------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RootRules:
    """What a scan of one root needs, compiled."""

    index: int
    root: RootPolicy
    include: tuple[Pattern, ...]
    exclude: tuple[Pattern, ...]  # global excludes first, then the root's own
    nested: frozenset[tuple[str, ...]]  # component_key of every root strictly below this one


def _compile_all(texts: Sequence[str], case_sensitive: bool, max_chars: int) -> tuple[Pattern, ...]:
    return tuple(
        compile_pattern(text, case_sensitive=case_sensitive, max_chars=max_chars) for text in texts
    )


def compile_rules(policy: Policy) -> tuple[RootRules, ...]:
    """Compile every pattern (case-insensitive on Windows) and work out the nested roots."""
    compiled: list[RootRules] = []
    limits = policy.limits
    for index, root in enumerate(policy.roots):
        sensitive = root.path.flavour is not Flavour.WINDOWS
        include = _compile_all(root.include, sensitive, limits.max_pattern_chars)

        nested = frozenset(
            _root_key(other.path)
            for other_index, other in enumerate(policy.roots)
            if other_index != index
            and is_within(other.path, root.path)
            and other.path.parts != root.path.parts
        )
        compiled.append(
            RootRules(
                index=index,
                root=root,
                include=include,
                exclude=_compile_all(policy.exclude, sensitive, limits.max_pattern_chars)
                + _compile_all(root.exclude, sensitive, limits.max_pattern_chars),
                nested=nested,
            )
        )
    return tuple(compiled)


def owning_root(policy: Policy, path: UserPath) -> int | None:
    """Index of the most specific root that contains ``path`` (or is it), or None."""
    best: int | None = None
    for index, root in enumerate(policy.roots):
        if not is_within(path, root.path):
            continue
        if best is None or len(root.path.parts) > len(policy.roots[best].path.parts):
            best = index
    return best
