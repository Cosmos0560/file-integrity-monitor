"""Repository hygiene checks (CLAUDE.md section 6), as plain functions.

The tests in test_hygiene.py run them on the real repository and, with planted bad data, on
temporary directories, so a check that stops working is noticed. Nothing here ever prints a
dangerous character: findings carry the code point and the Unicode category instead.
"""

from __future__ import annotations

import fnmatch
import os
import re
import shutil
import subprocess
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

# Control characters (Cc) other than these, and every format (Cf: bidi controls, zero-width
# characters, BOM), private-use (Co), unassigned (Cn), line/paragraph separator (Zl, Zp) and
# surrogate (Cs) character is refused in tracked files.
DANGEROUS_CATEGORIES = frozenset({"Cc", "Cf", "Co", "Cn", "Zl", "Zp", "Cs"})
ALLOWED_CONTROLS = frozenset({"\n", "\r", "\t"})

# File names that are secrets whatever they contain (matched case-insensitively on the base name).
SECRET_NAME_PATTERNS = ("*.key", "*.pem", "*.p12", "*.pfx", "id_rsa*", ".env*")
KEY_FILE_HEADER = b"FIM-HMAC-KEY"
ANCHOR_FILE_HEADER = b"FIM-ANCHOR"
BASELINE_FORMAT_MARKER = b'"fim-baseline"'
HEADER_SNIFF_BYTES = 1024

EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")


@dataclass(frozen=True, slots=True)
class BadCharacter:
    """One dangerous character: where it is and what it is (never the character itself)."""

    line: int
    column: int
    codepoint: int
    category: str

    def describe(self) -> str:
        return f"line {self.line} col {self.column}: U+{self.codepoint:04X} ({self.category})"


def find_bad_characters(text: str) -> list[BadCharacter]:
    """Every dangerous character in ``text``, in reading order."""
    found: list[BadCharacter] = []
    for line_number, line in enumerate(text.split("\n"), start=1):
        for column, char in enumerate(line, start=1):
            if char in ALLOWED_CONTROLS:
                continue
            category = unicodedata.category(char)
            if category in DANGEROUS_CATEGORIES:
                found.append(BadCharacter(line_number, column, ord(char), category))
    return found


def find_emails(text: str) -> list[str]:
    """Email-address-like strings in ``text``."""
    return EMAIL_PATTERN.findall(text)


def list_repo_files(root: Path) -> list[str]:
    """Tracked files plus untracked files that are not ignored, as paths relative to ``root``."""
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is not available")
    result = subprocess.run(
        [git, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        capture_output=True,
        check=True,
    )
    names = [os.fsdecode(raw) for raw in result.stdout.split(b"\0") if raw]
    return sorted(set(names))


def commit_messages(root: Path) -> str:
    """The full text of every commit message reachable from HEAD (empty if there are none)."""
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is not available")
    result = subprocess.run(
        [git, "log", "--format=%B"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return result.stdout if result.returncode == 0 else ""


def is_secret_name(relative: str) -> bool:
    """True if the base name looks like a key, certificate or environment file."""
    base = relative.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return any(fnmatch.fnmatchcase(base, pattern) for pattern in SECRET_NAME_PATTERNS)


def secret_header_kind(head: bytes) -> str | None:
    """'fim key', 'fim rollback anchor' or 'fim baseline' if the first bytes of a file identify
    one, else None."""
    if head.startswith(KEY_FILE_HEADER):
        return "fim key"
    if head.startswith(ANCHOR_FILE_HEADER):
        return "fim rollback anchor"
    first_line = head.split(b"\n", 1)[0]
    if first_line.lstrip().startswith(b"{") and BASELINE_FORMAT_MARKER in first_line:
        return "fim baseline"
    return None


def find_log_files(files: Iterable[str]) -> list[str]:
    """Log files (``scripts/gate.py --log`` writes them) never belong in the repository."""
    return [f"{name}: log file" for name in files if name.lower().endswith(".log")]


def find_secret_files(root: Path, files: Iterable[str]) -> list[str]:
    """Files that must never be tracked: secret names, fim key files, fim baselines."""
    problems: list[str] = []
    for relative in files:
        if is_secret_name(relative):
            problems.append(f"{relative}: secret file name")
            continue
        path = root / relative
        if not path.is_file():
            continue
        with path.open("rb") as handle:
            kind = secret_header_kind(handle.read(HEADER_SNIFF_BYTES))
        if kind is not None:
            problems.append(f"{relative}: looks like a {kind} file")
    return problems


def scan_text_files(root: Path, files: Iterable[str]) -> list[str]:
    """Problems with the text of ``files``: bad characters, invalid UTF-8, email addresses."""
    problems: list[str] = []
    for relative in files:
        path = root / relative
        if not path.is_file():
            continue
        try:
            text = path.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            problems.append(f"{relative}: not valid UTF-8")
            continue
        problems.extend(f"{relative}: {bad.describe()}" for bad in find_bad_characters(text))
        problems.extend(f"{relative}: email-address pattern found" for _ in find_emails(text))
    return problems
