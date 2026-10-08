"""Canonical JSON bytes (PLAN.md D3 and D14): the one serialisation of anything that is stored,
signed or hashed.

The output is pure ASCII: ``ensure_ascii`` writes every non-ASCII character, and every lone
surrogate (a POSIX file name byte that does not decode), as a JSON unicode escape. That makes a
record path lossless without the sanitiser, and the bytes identical on every Python version
whatever its Unicode tables say. Keys are sorted and must be text, separators are fixed, and
only null, booleans, integers, text, lists (or tuples) and objects have a canonical form: floats
(NaN, infinity, and the many spellings of one number) are refused, so equal data always gives
equal bytes.
"""

from __future__ import annotations

import json
from typing import Any

from fim.core.errors import ModelError

__all__ = ["canonical_json"]

_MAX_NESTING = 32


def _refuse(kind: str) -> ModelError:
    return ModelError(f"value has no canonical JSON form ({kind})")


def _check(value: Any, depth: int) -> None:
    """Refuse anything json.dumps would silently coerce or that has several spellings."""
    if depth > _MAX_NESTING:
        raise _refuse("nested too deeply")
    if value is None or isinstance(value, bool | int | str):
        return
    if isinstance(value, list | tuple):
        for item in value:
            _check(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise _refuse("object key is not text")
            _check(item, depth + 1)
        return
    raise _refuse(type(value).__name__)


def canonical_json(value: Any) -> bytes:
    """Return the canonical ASCII JSON bytes of ``value``, or raise ModelError."""
    _check(value, 0)
    text = json.dumps(
        value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    )
    return text.encode("ascii")
