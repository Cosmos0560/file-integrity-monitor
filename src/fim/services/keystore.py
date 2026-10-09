"""The HMAC key and the files that sit next to it (PLAN.md D2 and the D3 rollback anchor).

Key file format: two ASCII lines, ``FIM-HMAC-KEY v1`` and 64 lower-case hex characters (32 bytes
from ``secrets.token_bytes``), at most ``MAX_KEY_FILE_BYTES``. Anything else is refused, and no
message ever repeats what the file contained, so a mistaken file that does hold a key cannot leak
it through an error.

The key exists as a value only inside a ``Key`` object whose text form is redacted. It is read
from a file path given on the command line or in the configuration, never from argv or the
environment, and a key file inside a monitored root is refused (CLAUDE.md invariant 5).

The rollback anchor lives in the key's directory, named after the key file with the suffix
``.fim-anchor``; this module only moves its bytes. Its format and signature are in
services/baseline_codec.py.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from fim.core.errors import ConfigError, FileMissingError
from fim.core.limits import MAX_KEY_FILE_BYTES
from fim.fs import safe_files

__all__ = [
    "ANCHOR_MAX_BYTES",
    "ANCHOR_SUFFIX",
    "KEY_BYTES",
    "KEY_HEADER",
    "Key",
    "anchor_path",
    "decode_key_file",
    "encode_key_file",
    "generate_key",
    "init_key",
    "load_key",
    "read_anchor_bytes",
    "write_anchor_bytes",
]

KEY_HEADER = "FIM-HMAC-KEY v1"
KEY_BYTES = 32
ANCHOR_SUFFIX = ".fim-anchor"
ANCHOR_MAX_BYTES = 1024
_KEY_ID_MESSAGE = b"fim key id v1"
_KEY_ID_CHARS = 16
_HEX_KEY = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class Key:
    """An HMAC key. Printing it, in any form, shows no key material."""

    secret: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.secret, bytes) or len(self.secret) != KEY_BYTES:
            raise ConfigError(f"a key must be exactly {KEY_BYTES} bytes")

    def __repr__(self) -> str:
        return f"Key(key_id={self.key_id})"

    __str__ = __repr__

    @property
    def key_id(self) -> str:
        """Names the key without revealing it: the first 16 hex of HMAC(key, "fim key id v1")."""
        digest = hmac.new(self.secret, _KEY_ID_MESSAGE, hashlib.sha256).hexdigest()
        return digest[:_KEY_ID_CHARS]

    def mac(self, message: bytes) -> bytes:
        """HMAC-SHA256 of ``message`` under this key."""
        return hmac.new(self.secret, message, hashlib.sha256).digest()


def generate_key(random_bytes: Callable[[int], bytes] = secrets.token_bytes) -> Key:
    """A new random key. ``random_bytes`` is replaceable so tests can use fixed bytes."""
    return Key(random_bytes(KEY_BYTES))


def encode_key_file(key: Key) -> bytes:
    """The key file content: the header line, then the key as 64 hex characters."""
    return f"{KEY_HEADER}\n{key.secret.hex()}\n".encode("ascii")


def decode_key_file(data: bytes) -> Key:
    """Parse key file content strictly; raise ConfigError without quoting any of it."""
    if len(data) > MAX_KEY_FILE_BYTES:
        raise ConfigError(f"the key file is larger than {MAX_KEY_FILE_BYTES} bytes")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise ConfigError("the key file is not plain ASCII text") from None
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()  # a final newline is normal
    if not lines or lines[0] != KEY_HEADER:
        raise ConfigError(f"the key file does not start with the '{KEY_HEADER}' header line")
    if len(lines) != 2:
        raise ConfigError("the key file must have exactly two lines: the header and the key")
    if _HEX_KEY.fullmatch(lines[1]) is None:
        raise ConfigError(
            f"the key must be {KEY_BYTES * 2} lower-case hex characters on the second line"
        )
    return Key(bytes.fromhex(lines[1]))


def init_key(
    path: str,
    *,
    force: bool,
    avoid_roots: Sequence[str] = (),
    random_bytes: Callable[[int], bytes] = secrets.token_bytes,
) -> Key:
    """Create a key file at ``path`` (mode 0600 on POSIX) and return the key.

    Refuses to replace an existing file unless ``force``, and refuses a path inside a monitored
    root. The anchor file next to an old key is left alone: a new key means a new baseline.
    """
    key = generate_key(random_bytes)
    safe_files.write_own_file(
        path,
        encode_key_file(key),
        force=force,
        avoid_roots=avoid_roots,
        label="key file",
    )
    return key


def load_key(path: str, *, avoid_roots: Sequence[str] = ()) -> Key:
    """Read and parse the key file at ``path``.

    On POSIX a key that its group or others can access, or that another user owns, is refused.
    On Windows the ACL is not examined (PLAN.md D7); that is a documented limitation.
    """
    data = safe_files.read_own_file(
        path,
        max_bytes=MAX_KEY_FILE_BYTES,
        avoid_roots=avoid_roots,
        private=True,
        label="key file",
    )
    return decode_key_file(data)


# ---- the rollback anchor's file ------------------------------------------------------------------


def anchor_path(key_path: str) -> str:
    """Where the anchor of the key at ``key_path`` lives: next to it, with the anchor suffix."""
    return key_path + ANCHOR_SUFFIX


def read_anchor_bytes(key_path: str) -> bytes | None:
    """The anchor file's bytes, or None if there is none (a missing anchor is only a warning)."""
    try:
        return safe_files.read_own_file(
            anchor_path(key_path), max_bytes=ANCHOR_MAX_BYTES, label="anchor file"
        )
    except FileMissingError:
        return None


def write_anchor_bytes(key_path: str, data: bytes) -> None:
    """Replace the anchor file next to the key (atomic, no-follow, mode 0600 on POSIX)."""
    safe_files.write_own_file(anchor_path(key_path), data, force=True, label="anchor file")
