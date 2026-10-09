"""A fixed, valid baseline and key for the codec, golden-file and app tests.

The key is the obvious test vector 00 01 02 ... 1f. It protects nothing; it exists so the golden
file test can pin exact bytes.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fim.core.limits import DEFAULT_LIMITS
from fim.core.models import (
    Baseline,
    BaselineHeader,
    EntryType,
    FileRecord,
    HashStatus,
    Policy,
    RootPolicy,
    Severity,
    SymlinkPolicy,
)
from fim.core.pathrules import Flavour, validate_user_path
from fim.core.policy import build_policy
from fim.services.keystore import Key

TEST_KEY = Key(bytes(range(32)))
CREATED = datetime(2026, 3, 4, 5, 6, 7, 890123, tzinfo=UTC)
SHA_A = "ab" * 32
SHA_B = "0123456789abcdef" * 4


def sample_policy() -> Policy:
    roots = [
        RootPolicy(
            path=validate_user_path("/srv/data", Flavour.POSIX),
            severity=Severity.HIGH,
            exclude=("*.tmp",),
        ),
        RootPolicy(
            path=validate_user_path("/etc", Flavour.POSIX),
            severity=Severity.CRITICAL,
            include=("*.conf",),
            one_file_system=False,
        ),
    ]
    return build_policy(roots, ("**/__pycache__/**",), SymlinkPolicy.NEVER, DEFAULT_LIMITS)


def sample_records() -> tuple[FileRecord, ...]:
    ns = 1_700_000_000_123_456_789
    return (
        FileRecord(
            path="",
            root_index=0,
            type=EntryType.DIR,
            size=0,
            mtime_ns=ns,
            sha256=None,
            hash_status=HashStatus.NOT_APPLICABLE,
            mode=0o755,
            uid=1000,
            gid=1000,
        ),
        FileRecord(
            path="docs/a.txt",
            root_index=0,
            type=EntryType.FILE,
            size=3,
            mtime_ns=ns,
            sha256=SHA_A,
            hash_status=HashStatus.OK,
            mode=0o644,
            uid=1000,
            gid=1000,
        ),
        FileRecord(
            # An undecodable POSIX name byte (a lone surrogate), a non-ASCII letter and a bidi
            # control: stored exactly, written by canonical JSON as escapes (PLAN.md D14).
            path="d\udc80ir/\u00e9\u202e.txt",
            root_index=0,
            type=EntryType.FILE,
            size=0,
            mtime_ns=ns + 1,
            sha256=SHA_B,
            hash_status=HashStatus.OK,
            mode=0o600,
            uid=0,
            gid=0,
            nlink=2,
        ),
        FileRecord(
            path="link",
            root_index=0,
            type=EntryType.SYMLINK,
            size=9,
            mtime_ns=ns,
            sha256=None,
            hash_status=HashStatus.NOT_APPLICABLE,
            mode=0o777,
            uid=1000,
            gid=1000,
            link_target="../target\\x",
        ),
        FileRecord(
            path="big.iso",
            root_index=1,
            type=EntryType.FILE,
            size=10**12,
            mtime_ns=ns,
            sha256=None,
            hash_status=HashStatus.SKIPPED_TOO_LARGE,
            mode=0o644,
            uid=0,
            gid=0,
        ),
        FileRecord(
            path="odd",
            root_index=1,
            type=EntryType.FILE,
            size=1,
            mtime_ns=ns,
            sha256=None,
            hash_status=HashStatus.UNREADABLE,
            mode=0o000,
            uid=0,
            gid=0,
            error="EACCES",
        ),
    )


def sample_baseline(sequence: int = 1) -> Baseline:
    policy = sample_policy()
    header = BaselineHeader(
        tool_version="0.1.0",
        created_at=CREATED,
        sequence=sequence,
        host="lab-01",
        platform="linux",
        policy=policy,
        complete=True,
        limits=DEFAULT_LIMITS,
    )
    return Baseline(header=header, records=sample_records())
