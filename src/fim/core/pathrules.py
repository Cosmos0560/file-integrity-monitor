"""String-level rules for user-supplied paths (CLAUDE.md invariant 3), and the path forms the
baseline stores (PLAN.md D10 amendment).

Pure string logic: nothing here touches the filesystem, so the rules for both operating systems
are tested on every host. ``validate_user_path`` refuses UNC paths, ``\\\\?\\`` and ``\\\\.\\``
device paths, NT object paths, Windows reserved device names, drive-relative paths such as
``C:foo``, alternate data streams, anything URL-like (``scheme://``, ``file:``), ``..``
components, control characters and over-long paths. Whether a path really points at a link or a
reparse point is the job of fs/safe_files.py; this module only decides what text is acceptable.

A path is kept as components, never as one string with a guessed separator. Records are stored
root-relative with "/" separators and in their exact original form (PLAN.md D14); escaping is for
display only, applied per component, and the native separator is used only to display, so a
Windows path never shows doubled backslashes.
"""

from __future__ import annotations

import enum
import re
from collections.abc import Sequence
from dataclasses import dataclass

from fim.core.errors import PathRuleError
from fim.core.limits import MAX_DEPTH_CEILING, MAX_PATH_CHARS
from fim.core.sanitize import clip_escaped, escape, first_unsafe

__all__ = [
    "RECORD_SEPARATOR",
    "WINDOWS_RESERVED_NAMES",
    "Flavour",
    "UserPath",
    "display_link_target",
    "display_path",
    "display_user_path",
    "expand_tilde",
    "is_reserved_windows_name",
    "is_within",
    "record_path",
    "split_record_path",
    "validate_user_path",
]

RECORD_SEPARATOR = "/"
_MESSAGE_PATH_CHARS = 120
_URL_SCHEME = re.compile(
    r"[A-Za-z][A-Za-z0-9+.\-]+://"
)  # two or more characters: "C://" is a drive
_WINDOWS_SEPARATORS = "\\/"
_WINDOWS_BAD_NAME_CHARS = frozenset('<>:"|?*')
# Superscript digits count as digits for COM and LPT on current Windows versions.
_SUPERSCRIPT_DIGITS = str.maketrans({"\u00b9": "1", "\u00b2": "2", "\u00b3": "3"})

WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{n}" for n in range(10)}
    | {f"LPT{n}" for n in range(10)}
)


class Flavour(enum.Enum):
    """Which operating system's path rules apply."""

    POSIX = "posix"
    WINDOWS = "windows"


@dataclass(frozen=True, slots=True)
class UserPath:
    """A validated, normalised path kept as components."""

    flavour: Flavour
    drive: str  # "C:" for a Windows drive path, otherwise ""
    absolute: bool
    tilde: bool  # started with "~" (home directory, expanded later by the config loader)
    parts: tuple[str, ...]  # raw components, none empty, "." or ".."

    @property
    def sep(self) -> str:
        return "\\" if self.flavour is Flavour.WINDOWS else "/"

    @property
    def text(self) -> str:
        """The normalised path with native separators, components unescaped."""
        return self._join(self.parts)

    def display(self) -> str:
        """The path for output: components escaped one by one, joined with the native separator."""
        return self._join(tuple(escape(part) for part in self.parts))

    def _join(self, parts: Sequence[str]) -> str:
        body = self.sep.join(parts)
        if self.tilde:
            return "~" + (self.sep + body if body else "")
        if self.drive:
            return self.drive + self.sep + body
        if self.absolute:
            return self.sep + body
        return body


def _refuse(raw: str, reason: str) -> PathRuleError:
    return PathRuleError(f"path '{clip_escaped(raw, _MESSAGE_PATH_CHARS)}' refused: {reason}")


def is_reserved_windows_name(component: str) -> bool:
    """True if Windows would treat ``component`` as a device (``CON``, ``nul.txt``, ``COM1 .x``)."""
    stem = component.translate(_SUPERSCRIPT_DIGITS).split(".", 1)[0].rstrip(" ").upper()
    return stem in WINDOWS_RESERVED_NAMES


def validate_user_path(
    raw: str,
    flavour: Flavour,
    *,
    require_absolute: bool = False,
    allow_tilde: bool = False,
    max_chars: int = MAX_PATH_CHARS,
) -> UserPath:
    """Check ``raw`` against the path rules and return it normalised, or raise PathRuleError.

    ``require_absolute`` demands an absolute path or, with ``allow_tilde``, one that starts
    with ``~`` or ``~/``. ``~user`` is never accepted. Environment variables are not expanded.
    """
    if raw == "":
        raise _refuse(raw, "empty path")
    if len(raw) > max_chars:
        raise _refuse(raw, f"longer than {max_chars} characters")
    unsafe = first_unsafe(raw)
    if unsafe is not None:
        raise _refuse(
            raw, f"contains an unsafe character (U+{ord(raw[unsafe]):04X} at position {unsafe})"
        )
    candidate = raw.lstrip()
    if _URL_SCHEME.match(candidate) or candidate[:5].lower() == "file:":
        raise _refuse(raw, "URL-like path (scheme:// or file:)")

    if flavour is Flavour.WINDOWS:
        path = _parse_windows(raw, allow_tilde)
    else:
        path = _parse_posix(raw, allow_tilde)
    if len(path.parts) > MAX_DEPTH_CEILING:
        raise _refuse(raw, f"more than {MAX_DEPTH_CEILING} path components")
    if require_absolute and not (path.absolute or path.tilde):
        raise _refuse(raw, "must be an absolute path")
    return path


def _split_components(raw: str, rest: str, separators: str, flavour: Flavour) -> tuple[str, ...]:
    pattern = "[" + re.escape(separators) + "]+"
    parts: list[str] = []
    for component in re.split(pattern, rest):
        if component in ("", "."):
            continue
        if component == "..":
            raise _refuse(raw, "contains '..'; give the real path")
        if flavour is Flavour.WINDOWS:
            _check_windows_component(raw, component)
        parts.append(component)
    return tuple(parts)


def _check_windows_component(raw: str, component: str) -> None:
    if ":" in component:
        raise _refuse(raw, "colon in a name (alternate data stream or drive syntax)")
    if any(char in _WINDOWS_BAD_NAME_CHARS for char in component):
        raise _refuse(raw, 'character not allowed in a Windows name (< > " | ? *)')
    if component.endswith((" ", ".")):
        raise _refuse(raw, "name ends with a space or a dot (Windows would silently strip it)")
    if is_reserved_windows_name(component):
        raise _refuse(raw, "Windows reserved device name")


def _tilde_rest(raw: str, separators: str, allow_tilde: bool) -> str | None:
    """The part after a leading ``~``, or None if the path does not start with an allowed one."""
    if not (allow_tilde and raw.startswith("~")):
        return None
    if len(raw) > 1 and raw[1] not in separators:
        raise _refuse(raw, "'~user' is not supported; use ~ or an absolute path")
    return raw[1:]


def _parse_windows(raw: str, allow_tilde: bool) -> UserPath:
    flavour = Flavour.WINDOWS
    seps = _WINDOWS_SEPARATORS
    if len(raw) >= 2 and raw[0] in seps and raw[1] in seps:
        if raw[2:3] in ("?", "."):
            raise _refuse(raw, "device path (\\\\?\\ or \\\\.\\)")
        raise _refuse(raw, "UNC path (\\\\server\\share)")
    if raw[0] in seps:
        if len(raw) >= 4 and raw[1:3] == "??" and raw[3] in seps:
            raise _refuse(raw, "NT object path (\\??\\)")
        raise _refuse(raw, "path relative to the current drive; give the drive letter")
    drive = ""
    rest = raw
    absolute = False
    tilde = False
    if len(raw) >= 2 and raw[1] == ":" and raw[0].isascii() and raw[0].isalpha():
        drive = raw[0].upper() + ":"
        rest = raw[2:]
        if rest == "" or rest[0] not in seps:
            raise _refuse(raw, "drive-relative path (C:foo); give the full path with a backslash")
        absolute = True
    else:
        tilde_rest = _tilde_rest(raw, seps, allow_tilde)
        if tilde_rest is not None:
            tilde = True
            rest = tilde_rest
    parts = _split_components(raw, rest, seps, flavour)
    return UserPath(flavour, drive, absolute, tilde, parts)


def _parse_posix(raw: str, allow_tilde: bool) -> UserPath:
    flavour = Flavour.POSIX
    if raw.startswith("\\\\"):
        raise _refuse(raw, "UNC or device path syntax (\\\\)")
    if len(raw) >= 2 and raw[1] == ":" and raw[0].isascii() and raw[0].isalpha():
        raise _refuse(raw, "looks like a Windows drive path (C:)")
    tilde_rest = _tilde_rest(raw, "/", allow_tilde)
    tilde = tilde_rest is not None
    absolute = raw.startswith("/")
    rest = tilde_rest if tilde_rest is not None else raw
    parts = _split_components(raw, rest, "/", flavour)
    return UserPath(flavour, "", absolute, tilde, parts)


def is_within(path: UserPath, root: UserPath) -> bool:
    """True if ``path`` is ``root`` or lies below it, compared by components (never by prefix).

    Both must be absolute and use the same flavour. Windows compares case-insensitively.
    This is a text comparison only; links are dealt with where the file is opened.
    """
    for candidate in (path, root):
        if not candidate.absolute:
            raise PathRuleError("containment needs absolute paths (expand ~ first)")
    if path.flavour is not root.flavour:
        raise PathRuleError("containment needs paths of the same flavour")
    if path.flavour is Flavour.WINDOWS:
        left = (path.drive.casefold(), *(part.casefold() for part in path.parts))
        right = (root.drive.casefold(), *(part.casefold() for part in root.parts))
    else:
        left, right = path.parts, root.parts
    return left[: len(right)] == right


def record_path(parts: Sequence[str]) -> str:
    """The stored form of a path below its root: exact components joined with "/" (D14).

    Nothing is escaped here: the baseline holds the path as the filesystem reports it, lone
    surrogates included, and canonical JSON is what makes it safe to write.
    """
    for part in parts:
        if part in ("", ".", ".."):
            raise PathRuleError(f"invalid path component '{clip_escaped(part, 20)}'")
        if RECORD_SEPARATOR in part:
            raise PathRuleError("a path component cannot contain '/'")
    return RECORD_SEPARATOR.join(parts)


def split_record_path(text: str) -> tuple[str, ...]:
    """Invert ``record_path``. The empty string is the root itself."""
    if text == "":
        return ()
    pieces = text.split(RECORD_SEPARATOR)
    for piece in pieces:
        if piece in ("", ".", ".."):
            raise PathRuleError(f"invalid record path '{clip_escaped(text, _MESSAGE_PATH_CHARS)}'")
    return tuple(pieces)


def display_path(root: UserPath, record: str) -> str:
    """Root plus a stored record path, for output, with the native separator.

    Both halves are escaped per component and joined once, so a Windows path shows single
    backslashes (``C:\\Users\\lab\\notes.txt``), never doubled ones.
    """
    base = root.display()
    if record == "":
        return base
    tail = root.sep.join(escape(part) for part in split_record_path(record))
    return base + tail if base.endswith(root.sep) else base + root.sep + tail


def display_user_path(raw: str, flavour: Flavour, max_chars: int = _MESSAGE_PATH_CHARS) -> str:
    """A path given by the user, made fit for a message: escaped per component, native separators.

    A path the rules refuse (or one that is too long to show whole) falls back to the plain
    escaped and clipped text, which is also what makes a refused path safe to quote.
    """
    try:
        shown = validate_user_path(raw, flavour, allow_tilde=True).display()
    except PathRuleError:
        return clip_escaped(raw, max_chars)
    return shown if len(shown) <= max_chars else clip_escaped(raw, max_chars)


def expand_tilde(path: UserPath, home: UserPath) -> UserPath:
    """Replace a leading ``~`` with the absolute ``home`` directory (given by the caller)."""
    if not path.tilde:
        raise PathRuleError("the path does not start with '~'")
    if not home.absolute or home.tilde:
        raise PathRuleError("the home directory must be an absolute path")
    if home.flavour is not path.flavour:
        raise PathRuleError("the home directory uses a different path flavour")
    return UserPath(path.flavour, home.drive, True, False, home.parts + path.parts)


# Windows readlink() returns an absolute target in extended-length form. The prefix is how the
# system spells the path, not part of what the link says to a human, so only the display strips it.
_EXTENDED_UNC = re.compile(r"\\\\\?\\UNC\\", re.IGNORECASE)
_EXTENDED_DRIVE = re.compile(r"\\\\\?\\(?=[A-Za-z]:(?:[\\/]|$))")


def display_link_target(raw: str, flavour: Flavour) -> str:
    r"""A symlink target, exactly as ``readlink`` returned it, made fit to show (PLAN.md D6, D14).

    Storage and comparison always use ``raw``; this is for output only. On Windows a leading
    ``\\?\C:\`` is shown as ``C:\`` and ``\\?\UNC\server\share`` as ``\\server\share``; other
    extended forms (``\\?\Volume{...}``) are left as they are, because dropping the prefix there
    would invent a different path. Components are escaped one by one and the original
    separators are kept, so a path never shows doubled backslashes.
    """
    text = raw
    if flavour is Flavour.WINDOWS:
        if _EXTENDED_UNC.match(text):
            text = "\\\\" + text[len("\\\\?\\UNC\\") :]
        else:
            text = _EXTENDED_DRIVE.sub("", text, count=1)
        pieces = re.split(r"([\\/])", text)
    else:
        pieces = re.split(r"(/)", text)
    return "".join(piece if piece in ("\\", "/") else escape(piece) for piece in pieces)
