"""Repository hygiene: no hostile characters, no secrets, no email addresses.

The first group runs the checks on the real repository (CLAUDE.md and PLAN.md included, which is
the proof that the plan files are clean). The rest plants bad data in temporary directories to
prove each check can fail. Test data builds dangerous characters from code points and email
addresses at runtime, so this file itself stays clean.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

import repo_hygiene as hygiene
from conftest import REPO_ROOT


def _emailish(local: str = "someone", domain: str = "example.com") -> str:
    return "@".join((local, domain))


def _git(cwd: Path, *args: str) -> None:
    git = shutil.which("git")
    assert git is not None
    subprocess.run([git, *args], cwd=cwd, check=True, capture_output=True)


# ---- the real repository ---------------------------------------------------------------------


@pytest.fixture(scope="module")
def repo_files() -> list[str]:
    return hygiene.list_repo_files(REPO_ROOT)


@pytest.mark.requires_git
def test_repository_files_have_no_hostile_characters_or_emails(repo_files: list[str]) -> None:
    assert hygiene.scan_text_files(REPO_ROOT, repo_files) == []


@pytest.mark.requires_git
def test_plan_files_are_clean_and_tracked_or_visible(repo_files: list[str]) -> None:
    assert "CLAUDE.md" in repo_files
    assert "PLAN.md" in repo_files
    for name in ("CLAUDE.md", "PLAN.md"):
        text = (REPO_ROOT / name).read_bytes().decode("utf-8")
        assert hygiene.find_bad_characters(text) == []


@pytest.mark.requires_git
def test_claude_md_shows_the_bidi_example_as_escape_text_not_a_raw_character() -> None:
    text = (REPO_ROOT / "CLAUDE.md").read_bytes().decode("utf-8")
    assert "\\u202e" in text  # backslash, u, 2, 0, 2, e: six ordinary characters
    assert chr(0x202E) not in text


@pytest.mark.requires_git
def test_no_key_baseline_or_secret_file_is_tracked_or_visible(repo_files: list[str]) -> None:
    assert hygiene.find_secret_files(REPO_ROOT, repo_files) == []


@pytest.mark.requires_git
def test_no_log_file_is_tracked_or_visible(repo_files: list[str]) -> None:
    assert hygiene.find_log_files(repo_files) == []


def test_log_files_are_found_by_name_in_any_directory() -> None:
    found = hygiene.find_log_files(["gate-full.log", "a/b/Run.LOG", "a/log.txt", "logs/readme.md"])
    assert found == ["gate-full.log: log file", "a/b/Run.LOG: log file"]


@pytest.mark.requires_git
def test_commit_messages_have_no_email_addresses() -> None:
    messages = hygiene.commit_messages(REPO_ROOT)
    assert hygiene.find_emails(messages) == []
    assert "co-authored-by" not in messages.lower()


def test_gitignore_lists_the_secret_and_environment_patterns() -> None:
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    patterns = {line.strip() for line in gitignore.splitlines()}
    for expected in (
        "*.key",
        "*.pem",
        "*.p12",
        "*.pfx",
        "id_rsa*",
        ".env*",
        ".venv/",
        "*.baseline*",
        "*.log",
    ):
        assert expected in patterns, expected


# ---- bad characters: every dangerous one is found ---------------------------------------------

BIDI = [
    0x202A,
    0x202B,
    0x202C,
    0x202D,
    0x202E,
    0x2066,
    0x2067,
    0x2068,
    0x2069,
    0x200E,
    0x200F,
    0x061C,
]
ZERO_WIDTH = [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x180E]
CONTROLS = [0x00, 0x01, 0x07, 0x08, 0x0B, 0x0C, 0x1B, 0x1F, 0x7F, 0x80, 0x85, 0x9F]
OTHER = [0x2028, 0x2029, 0xE000, 0xF8FF, 0x0378, 0xFFFE, 0xE0001, 0xF0000]


@pytest.mark.parametrize("codepoint", BIDI + ZERO_WIDTH + CONTROLS + OTHER)
def test_dangerous_character_is_found_with_its_position(codepoint: int) -> None:
    text = "ab\ncd" + chr(codepoint) + "e\n"
    found = hygiene.find_bad_characters(text)
    assert [(f.line, f.column, f.codepoint) for f in found] == [(2, 3, codepoint)]
    assert chr(codepoint) not in found[0].describe()


def test_lone_surrogate_is_found() -> None:
    found = hygiene.find_bad_characters("a" + chr(0xD800))
    assert [f.category for f in found] == ["Cs"]


@pytest.mark.parametrize("text", ["plain ascii\n", "tab\there\r\n", "café жук 日本\n", ""])
def test_ordinary_text_is_not_flagged(text: str) -> None:
    assert hygiene.find_bad_characters(text) == []


def test_scan_reports_invalid_utf8_and_bad_characters_and_emails(tmp_path: Path) -> None:
    (tmp_path / "bidi.txt").write_bytes(("x" + chr(0x202E) + "y").encode("utf-8"))
    (tmp_path / "bom.txt").write_bytes(b"\xef\xbb\xbfhello")
    (tmp_path / "nul.txt").write_bytes(b"a\x00b")
    (tmp_path / "latin1.txt").write_bytes(b"caf\xe9")
    (tmp_path / "mail.txt").write_text("contact " + _emailish() + "\n", encoding="utf-8")
    (tmp_path / "clean.txt").write_text("nothing to see\n", encoding="utf-8")
    names = ["bidi.txt", "bom.txt", "nul.txt", "latin1.txt", "mail.txt", "clean.txt", "gone.txt"]
    problems = hygiene.scan_text_files(tmp_path, names)
    joined = "\n".join(problems)
    assert "bidi.txt: line 1 col 2: U+202E (Cf)" in joined
    assert "bom.txt: line 1 col 1: U+FEFF (Cf)" in joined
    assert "nul.txt: line 1 col 2: U+0000 (Cc)" in joined
    assert "latin1.txt: not valid UTF-8" in joined
    assert "mail.txt: email-address pattern found" in joined
    assert "clean.txt" not in joined
    assert "gone.txt" not in joined  # a listed but missing file is not an error here


# ---- email patterns --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        _emailish(),
        _emailish("first.last+tag", "sub.domain.org"),
        "see " + _emailish("a_b-c", "host.io") + ".",
        "<" + _emailish("x", "y.example.net") + ">",
    ],
)
def test_email_addresses_are_found(text: str) -> None:
    assert len(hygiene.find_emails(text)) == 1


@pytest.mark.parametrize(
    "text",
    [
        "uses: actions/checkout@v4",
        "uses: actions/setup-python@v5",
        "pip install pkg@1.2.3",
        "@pytest.mark.slow",
        "@dataclass(frozen=True, slots=True)",
        "user@localhost",
        "a@b.c",
        "no at sign here.com",
    ],
)
def test_common_non_email_text_is_not_flagged(text: str) -> None:
    assert hygiene.find_emails(text) == []


# ---- secret files ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "fim.key",
        "dir/server.pem",
        "a/b/c.p12",
        "cert.pfx",
        "id_rsa",
        "id_rsa.pub",
        "id_rsa_backup",
        ".env",
        ".env.local",
        "sub/.env.production",
        "UPPER.KEY",
        "win\\path\\secret.pem",
    ],
)
def test_secret_file_names_are_flagged(name: str) -> None:
    assert hygiene.is_secret_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "keystore.py",
        "turkey.txt",
        "monkey.md",
        "src/fim/services/keystore.py",
        "environment.md",
        "pem.txt",
    ],
)
def test_ordinary_names_are_not_flagged_as_secrets(name: str) -> None:
    assert not hygiene.is_secret_name(name)


def test_fim_key_file_is_detected_by_header_under_an_innocent_name(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_bytes(b"FIM-HMAC-KEY v1\n" + b"ab" * 32 + b"\n")
    problems = hygiene.find_secret_files(tmp_path, ["notes.txt"])
    assert problems == ["notes.txt: looks like a fim key file"]


def test_fim_baseline_is_detected_by_header_under_an_innocent_name(tmp_path: Path) -> None:
    envelope = b'{"format": "fim-baseline", "version": 1, "mac": "00"}\n{"payload": 1}\n'
    (tmp_path / "data.json").write_bytes(envelope)
    problems = hygiene.find_secret_files(tmp_path, ["data.json"])
    assert problems == ["data.json: looks like a fim baseline file"]


def test_files_that_only_mention_the_formats_are_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "doc.md").write_text("# Notes\nThe header is FIM-HMAC-KEY v1.\n", encoding="utf-8")
    (tmp_path / "other.json").write_text('{"format": "something-else"}\n', encoding="utf-8")
    (tmp_path / "later.json").write_text('{"a": 1}\n{"format": "fim-baseline"}\n', encoding="utf-8")
    assert hygiene.find_secret_files(tmp_path, ["doc.md", "other.json", "later.json"]) == []


@pytest.mark.requires_git
def test_git_listing_sees_staged_untracked_and_force_added_files_but_not_ignored(
    tmp_path: Path,
) -> None:
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / ".gitignore").write_text("*.key\n", encoding="utf-8")
    (tmp_path / "ok.txt").write_text("fine\n", encoding="utf-8")
    (tmp_path / "ignored.key").write_text("secret\n", encoding="utf-8")
    (tmp_path / "forced.key").write_text("secret\n", encoding="utf-8")
    (tmp_path / "loose.pem").write_text("secret\n", encoding="utf-8")
    _git(tmp_path, "add", ".gitignore", "ok.txt")
    _git(tmp_path, "add", "-f", "forced.key")

    files = hygiene.list_repo_files(tmp_path)

    assert "ok.txt" in files  # staged
    assert "forced.key" in files  # staged although ignored: still a problem
    assert "loose.pem" in files  # untracked and not ignored
    assert "ignored.key" not in files  # ignored and untracked: not listed
    problems = hygiene.find_secret_files(tmp_path, files)
    assert sorted(p.split(":")[0] for p in problems) == ["forced.key", "loose.pem"]


@pytest.mark.requires_git
def test_commit_messages_helper_returns_empty_for_a_repository_without_commits(
    tmp_path: Path,
) -> None:
    _git(tmp_path, "init", "-q", "-b", "main")
    assert hygiene.commit_messages(tmp_path) == ""
