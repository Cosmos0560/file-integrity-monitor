"""The baseline file format, its HMAC, and the rollback anchor (PLAN.md D3).

A baseline file has two parts, verified before parsed:

1. Line 1, the envelope: canonical JSON of at most 1 KiB with ``format``, ``version``, ``mac_alg``,
   ``key_id`` and ``mac``, then a newline.
2. Everything after that newline, the payload: canonical JSON bytes (core/canonical.py, ASCII, so
   every path is exact and lossless, PLAN.md D14) holding the header and the records.

The MAC is HMAC-SHA256 over ``b"fim-baseline\\x00v1\\x00" + key_id + b"\\x00" + payload``, so the
format, the version and the key id are authenticated along with the payload. The order of
decoding is fixed: size cap, envelope (tiny, strictly checked), format and version, key id
("wrong key" is said as such), MAC with ``hmac.compare_digest`` over the exact bytes, and only
then the payload parser runs. Any failure is a ``BaselineIntegrityError`` (exit code 3); the
parser never sees bytes that did not verify, and nothing is re-canonicalised before the MAC.

The rollback anchor is a small text file: a header line and four ``name value`` lines (key id,
sequence, payload SHA-256, MAC). It is signed with a different domain prefix, so a baseline MAC
cannot be passed off as an anchor MAC or the other way round. ``verify_against_anchor`` is the
check ``check`` and ``watch`` run.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from fim.core.canonical import canonical_json
from fim.core.errors import BaselineIntegrityError, ConfigError, ModelError, PathRuleError
from fim.core.limits import DEFAULT_LIMITS, Limits
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
from fim.core.pathrules import Flavour, UserPath, validate_user_path
from fim.core.policy import POLICY_DIGEST_VERSION, compile_rules, digest_is_valid, policy_document
from fim.services.keystore import Key

__all__ = [
    "ANCHOR_HEADER",
    "BASELINE_FORMAT",
    "BASELINE_VERSION",
    "ENVELOPE_MAX_BYTES",
    "Anchor",
    "DecodedBaseline",
    "EncodedBaseline",
    "decode_anchor",
    "decode_baseline",
    "encode_anchor",
    "encode_baseline",
    "next_sequence",
    "parse_payload",
    "verify_against_anchor",
]

BASELINE_FORMAT = "fim-baseline"
BASELINE_VERSION = 1
MAC_ALGORITHM = "HMAC-SHA256"
ENVELOPE_MAX_BYTES = 1024
ANCHOR_HEADER = "FIM-ANCHOR v1"
_BASELINE_MAC_DOMAIN = b"fim-baseline\x00v1\x00"
_ANCHOR_MAC_DOMAIN = b"fim-anchor\x00v1\x00"
_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
_TIME_SHAPE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")
_HEX16 = re.compile(r"[0-9a-f]{16}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_MAX_SEQUENCE = 2**53
_ENVELOPE_KEYS = frozenset({"format", "version", "mac_alg", "key_id", "mac"})
_RECORD_KEYS = frozenset(
    {
        "path",
        "root_index",
        "type",
        "size",
        "mtime_ns",
        "sha256",
        "hash_status",
        "mode",
        "uid",
        "gid",
        "win_attrs",
        "nlink",
        "link_target",
        "reparse_tag",
        "error",
    }
)
_HEADER_KEYS = frozenset(
    {
        "tool_version",
        "created_at",
        "sequence",
        "host",
        "platform",
        "complete",
        "limits",
        "policy",
    }
)
_POLICY_KEYS = frozenset({"version", "roots", "exclude", "symlinks", "limits", "digest"})
_ROOT_KEYS = frozenset(
    {"flavour", "drive", "parts", "severity", "include", "exclude", "one_file_system"}
)
_LIMIT_NAMES = frozenset(asdict(DEFAULT_LIMITS))


def _refuse(reason: str) -> BaselineIntegrityError:
    return BaselineIntegrityError(f"the baseline is not trustworthy: {reason}")


# ---- encoding ------------------------------------------------------------------------------------


def _time_text(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime(_TIME_FORMAT)


def _record_document(record: FileRecord) -> dict[str, Any]:
    return {
        "path": record.path,
        "root_index": record.root_index,
        "type": record.type.value,
        "size": record.size,
        "mtime_ns": record.mtime_ns,
        "sha256": record.sha256,
        "hash_status": record.hash_status.value,
        "mode": record.mode,
        "uid": record.uid,
        "gid": record.gid,
        "win_attrs": record.win_attrs,
        "nlink": record.nlink,
        "link_target": record.link_target,
        "reparse_tag": record.reparse_tag,
        "error": record.error,
    }


def _header_document(header: BaselineHeader) -> dict[str, Any]:
    policy = header.policy
    return {
        "tool_version": header.tool_version,
        "created_at": _time_text(header.created_at),
        "sequence": header.sequence,
        "host": header.host,
        "platform": header.platform,
        "complete": header.complete,
        "limits": asdict(header.limits),
        "policy": {
            **policy_document(policy.roots, policy.exclude, policy.symlinks, policy.limits),
            "digest": policy.digest,
        },
    }


def payload_bytes(baseline: Baseline) -> bytes:
    """The canonical payload bytes of ``baseline`` (the part the MAC covers)."""
    document = {
        "header": _header_document(baseline.header),
        "records": [_record_document(record) for record in baseline.records],
    }
    return canonical_json(document)


def _baseline_mac(key: Key, key_id: str, payload: bytes) -> str:
    return key.mac(_BASELINE_MAC_DOMAIN + key_id.encode("ascii") + b"\x00" + payload).hex()


@dataclass(frozen=True, slots=True)
class EncodedBaseline:
    """The bytes of a baseline file, and what the anchor needs to know about it."""

    data: bytes
    payload_sha256: str
    key_id: str
    sequence: int


def encode_baseline(baseline: Baseline, key: Key) -> EncodedBaseline:
    """Serialise and sign ``baseline``: the envelope line, a newline, then the payload."""
    payload = payload_bytes(baseline)
    key_id = key.key_id
    envelope = canonical_json(
        {
            "format": BASELINE_FORMAT,
            "version": BASELINE_VERSION,
            "mac_alg": MAC_ALGORITHM,
            "key_id": key_id,
            "mac": _baseline_mac(key, key_id, payload),
        }
    )
    return EncodedBaseline(
        data=envelope + b"\n" + payload,
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        key_id=key_id,
        sequence=baseline.header.sequence,
    )


# ---- decoding ------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DecodedBaseline:
    """A baseline whose MAC verified, with the facts the anchor check needs."""

    baseline: Baseline
    key_id: str
    payload_sha256: str


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [name for name, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key")
    return dict(pairs)


def _read_envelope(line: bytes) -> Mapping[str, Any]:
    try:
        envelope = json.loads(line.decode("ascii"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _refuse("the envelope (first line) is damaged") from None
    if not isinstance(envelope, dict) or set(envelope) != _ENVELOPE_KEYS:
        raise _refuse("the envelope (first line) has the wrong fields")
    return envelope


def decode_baseline(data: bytes, key: Key, *, max_bytes: int) -> DecodedBaseline:
    """Verify, then parse, baseline file content. Raises BaselineIntegrityError for anything off.

    The payload parser is not called until the MAC has verified.
    """
    if len(data) > max_bytes:
        raise _refuse(f"it is larger than the {max_bytes} byte limit")
    newline = data.find(b"\n", 0, ENVELOPE_MAX_BYTES + 1)
    if newline < 0:
        raise _refuse("no envelope line in the first 1024 bytes (truncated or damaged)")
    envelope = _read_envelope(data[:newline])
    if envelope["format"] != BASELINE_FORMAT:
        raise _refuse("it is not a fim baseline (unknown format)")
    version = envelope["version"]
    if type(version) is not int or version != BASELINE_VERSION:
        raise _refuse("it has an unsupported version; this tool reads version 1 only")
    if envelope["mac_alg"] != MAC_ALGORITHM:
        raise _refuse("it uses an unsupported MAC algorithm")
    key_id, mac = envelope["key_id"], envelope["mac"]
    if not isinstance(key_id, str) or _HEX16.fullmatch(key_id) is None:
        raise _refuse("the envelope holds a malformed key id")
    if not isinstance(mac, str) or _HEX64.fullmatch(mac) is None:
        raise _refuse("the envelope holds a malformed MAC")
    if key_id != key.key_id:
        raise _refuse(
            f"it was made with a different key (baseline key id {key_id}, "
            f"this key's id is {key.key_id}): wrong key file"
        )
    payload = data[newline + 1 :]
    expected = _baseline_mac(key, key_id, payload)
    if not hmac.compare_digest(expected.encode("ascii"), mac.encode("ascii")):
        raise _refuse("the MAC does not verify: the file was changed or damaged after writing")
    return DecodedBaseline(
        baseline=parse_payload(payload),
        key_id=key_id,
        payload_sha256=hashlib.sha256(payload).hexdigest(),
    )


# ---- the payload parser (only ever called on verified bytes) -------------------------------------


def _int(value: object, where: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{where} must be an integer of at least {minimum}")
    return value


def _opt_int(value: object, where: str) -> int | None:
    return None if value is None else _int(value, where)


def _text(value: object, where: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{where} must be text")
    return value


def _opt_text(value: object, where: str) -> str | None:
    return None if value is None else _text(value, where)


def _flag(value: object, where: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{where} must be true or false")
    return value


def _text_list(value: object, where: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{where} must be a list")
    return tuple(_text(item, where) for item in value)


def _object(value: object, keys: frozenset[str], where: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{where} has the wrong fields")
    return value


def _moment(value: object) -> datetime:
    text = _text(value, "created_at")
    if _TIME_SHAPE.fullmatch(text) is None:
        raise ValueError("created_at is malformed")
    return datetime.strptime(text, _TIME_FORMAT).replace(tzinfo=UTC)


def _limits(value: object, where: str) -> Limits:
    document = _object(value, _LIMIT_NAMES, where)
    return Limits(**document)


def _record(value: object) -> FileRecord:
    fields = _object(value, _RECORD_KEYS, "a record")
    return FileRecord(
        path=_text(fields["path"], "path"),
        root_index=_int(fields["root_index"], "root_index"),
        type=EntryType(_text(fields["type"], "type")),
        size=_int(fields["size"], "size"),
        mtime_ns=_int(fields["mtime_ns"], "mtime_ns"),
        sha256=_opt_text(fields["sha256"], "sha256"),
        hash_status=HashStatus(_text(fields["hash_status"], "hash_status")),
        mode=_opt_int(fields["mode"], "mode"),
        uid=_opt_int(fields["uid"], "uid"),
        gid=_opt_int(fields["gid"], "gid"),
        win_attrs=_opt_int(fields["win_attrs"], "win_attrs"),
        nlink=_int(fields["nlink"], "nlink"),
        link_target=_opt_text(fields["link_target"], "link_target"),
        reparse_tag=_opt_int(fields["reparse_tag"], "reparse_tag"),
        error=_opt_text(fields["error"], "error"),
    )


def _root(value: object) -> RootPolicy:
    fields = _object(value, _ROOT_KEYS, "a root")
    try:
        flavour = Flavour(_text(fields["flavour"], "flavour"))
    except ValueError:
        raise ValueError("a root has an unknown path flavour") from None
    drive = _text(fields["drive"], "drive")
    parts = _text_list(fields["parts"], "parts")
    # Rebuild the path through the same rules a configured path passes, and demand the same parts.
    shown = UserPath(flavour, drive, True, False, parts).text
    try:
        path = validate_user_path(shown, flavour, require_absolute=True)
    except PathRuleError:
        raise ValueError("a root path breaks the path rules") from None
    if path.parts != parts or path.drive != drive:
        raise ValueError("a root path is not in normal form")
    return RootPolicy(
        path=path,
        severity=Severity.from_label(_text(fields["severity"], "severity")),
        include=_text_list(fields["include"], "include"),
        exclude=_text_list(fields["exclude"], "exclude"),
        one_file_system=_flag(fields["one_file_system"], "one_file_system"),
    )


def _policy(value: object) -> Policy:
    fields = _object(value, _POLICY_KEYS, "the policy")
    if fields["version"] != POLICY_DIGEST_VERSION:
        raise ValueError("the policy has an unknown version")
    roots = fields["roots"]
    if not isinstance(roots, list):
        raise ValueError("the policy roots must be a list")
    policy = Policy(
        roots=tuple(_root(item) for item in roots),
        exclude=_text_list(fields["exclude"], "exclude"),
        symlinks=SymlinkPolicy(_text(fields["symlinks"], "symlinks")),
        limits=_limits(fields["limits"], "the policy limits"),
        digest=_text(fields["digest"], "digest"),
    )
    if not digest_is_valid(policy):
        raise ValueError("the policy digest does not match the policy")
    compile_rules(policy)  # every stored pattern must still compile
    return policy


def _header(value: object) -> BaselineHeader:
    fields = _object(value, _HEADER_KEYS, "the header")
    return BaselineHeader(
        tool_version=_text(fields["tool_version"], "tool_version"),
        created_at=_moment(fields["created_at"]),
        sequence=_int(fields["sequence"], "sequence", minimum=1),
        host=_text(fields["host"], "host"),
        platform=_text(fields["platform"], "platform"),
        policy=_policy(fields["policy"]),
        complete=_flag(fields["complete"], "complete"),
        limits=_limits(fields["limits"], "the limits"),
    )


def parse_payload(payload: bytes) -> Baseline:
    """Parse payload bytes into a Baseline. Call only on bytes whose MAC has verified."""
    try:
        document = json.loads(payload.decode("ascii"))
        if not isinstance(document, dict) or set(document) != {"header", "records"}:
            raise ValueError("the payload has the wrong top-level fields")
        records = document["records"]
        if not isinstance(records, list):
            raise ValueError("the records must be a list")
        header = _header(document["header"])
        parsed = tuple(_record(item) for item in records)
        if len(parsed) > header.limits.max_files + len(header.policy.roots):
            raise ValueError("there are more records than the limits allow")
        for record in parsed:
            if record.root_index >= len(header.policy.roots):
                raise ValueError("a record refers to a root that does not exist")
        return Baseline(header=header, records=parsed)
    except (
        UnicodeDecodeError,
        ValueError,
        TypeError,
        KeyError,
        RecursionError,
        ModelError,
        ConfigError,
        PathRuleError,
    ) as exc:
        unreadable = isinstance(exc, UnicodeDecodeError | RecursionError)
        reason = "malformed payload" if unreadable else str(exc)
        raise _refuse(f"it is signed but its content is invalid ({reason})") from None


# ---- the rollback anchor -------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Anchor:
    """The signed record of the latest baseline: its sequence and payload digest."""

    key_id: str
    sequence: int
    payload_sha256: str


def _anchor_mac(key: Key, key_id: str, sequence: int, payload_sha256: str) -> str:
    message = b"\x00".join(
        (key_id.encode("ascii"), str(sequence).encode("ascii"), payload_sha256.encode("ascii"))
    )
    return key.mac(_ANCHOR_MAC_DOMAIN + message).hex()


def encode_anchor(key: Key, sequence: int, payload_sha256: str) -> bytes:
    """The anchor file content for a baseline with this sequence and payload digest."""
    if type(sequence) is not int or not 1 <= sequence <= _MAX_SEQUENCE:
        raise ModelError("an anchor needs a sequence of at least 1")
    if _HEX64.fullmatch(payload_sha256) is None:
        raise ModelError("an anchor needs a SHA-256 payload digest")
    key_id = key.key_id
    lines = (
        ANCHOR_HEADER,
        f"key_id {key_id}",
        f"sequence {sequence}",
        f"payload_sha256 {payload_sha256}",
        f"mac {_anchor_mac(key, key_id, sequence, payload_sha256)}",
    )
    return ("\n".join(lines) + "\n").encode("ascii")


def _anchor_fields(data: bytes) -> dict[str, str]:
    try:
        lines = data.decode("ascii").split("\n")
    except UnicodeDecodeError:
        raise _anchor_refusal("it is not plain ASCII text") from None
    if lines and lines[-1] == "":
        lines.pop()
    if not lines or lines[0] != ANCHOR_HEADER:
        raise _anchor_refusal(f"it does not start with the '{ANCHOR_HEADER}' line")
    names = ("key_id", "sequence", "payload_sha256", "mac")
    fields: dict[str, str] = {}
    for name, line in zip(names, lines[1:], strict=False):
        prefix, _, value = line.partition(" ")
        if prefix != name or value == "" or " " in value:
            raise _anchor_refusal("a line is malformed or out of order")
        fields[name] = value
    if len(lines) != len(names) + 1:
        raise _anchor_refusal("it must have exactly five lines")
    return fields


def _anchor_refusal(reason: str) -> BaselineIntegrityError:
    return BaselineIntegrityError(f"the rollback anchor is not trustworthy: {reason}")


def decode_anchor(data: bytes, key: Key) -> Anchor:
    """Parse and verify anchor file content; raise BaselineIntegrityError if it does not verify."""
    fields = _anchor_fields(data)
    key_id, digest, mac = fields["key_id"], fields["payload_sha256"], fields["mac"]
    sequence_text = fields["sequence"]
    if _HEX16.fullmatch(key_id) is None or _HEX64.fullmatch(digest) is None:
        raise _anchor_refusal("a field is malformed")
    if _HEX64.fullmatch(mac) is None or re.fullmatch(r"[1-9][0-9]{0,15}", sequence_text) is None:
        raise _anchor_refusal("a field is malformed")
    sequence = int(sequence_text)
    if sequence > _MAX_SEQUENCE:
        raise _anchor_refusal("the sequence is out of range")
    if key_id != key.key_id:
        raise _anchor_refusal(
            f"it was made with a different key (anchor key id {key_id}, "
            f"this key's id is {key.key_id}); if you replaced the key on purpose, "
            "move the old anchor file away and make a new baseline"
        )
    expected = _anchor_mac(key, key_id, sequence, digest)
    if not hmac.compare_digest(expected.encode("ascii"), mac.encode("ascii")):
        raise _anchor_refusal("its MAC does not verify: the file was changed or damaged")
    return Anchor(key_id=key_id, sequence=sequence, payload_sha256=digest)


def next_sequence(anchor: Anchor | None) -> int:
    """The sequence number of the next baseline: the anchor's plus one, or 1 without an anchor."""
    return 1 if anchor is None else anchor.sequence + 1


def verify_against_anchor(anchor: Anchor, decoded: DecodedBaseline) -> None:
    """Refuse (BaselineIntegrityError, exit 3) a baseline that is not the one the anchor names.

    ``check`` and ``watch`` call this with a verified baseline and a verified anchor: a different
    sequence or payload digest means an older baseline was put back, or a different one was
    substituted, or the key is shared with another baseline.
    """
    sequence = decoded.baseline.header.sequence
    if sequence != anchor.sequence:
        raise BaselineIntegrityError(
            f"the baseline (sequence {sequence}) does not match the rollback anchor "
            f"(sequence {anchor.sequence}): an older or different baseline may have been put in "
            "place, or this key is shared with another baseline"
        )
    if not hmac.compare_digest(
        decoded.payload_sha256.encode("ascii"), anchor.payload_sha256.encode("ascii")
    ):
        raise BaselineIntegrityError(
            f"the baseline has the anchor's sequence ({sequence}) but different content: "
            "it is not the baseline that was written last"
        )
