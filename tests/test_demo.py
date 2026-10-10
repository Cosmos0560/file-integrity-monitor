"""app/demo.py and fs/sandbox.py: the demo leaves nothing behind, also when a step raises, and
never touches a path outside its own temporary directory (CLAUDE.md section 6, PLAN.md Phase 5)."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

import winhelp
from fakes import FakeClock
from fim.app.check import run_check
from fim.app.demo import EXPECTED_KINDS, DemoError, hostile_names, run_demo
from fim.cli import main as cli
from fim.core.errors import ExitCode, FimError
from fim.fs import sandbox as sandbox_module
from fim.fs.sandbox import Sandbox, SandboxError

# ---- the guard: every path the sandbox module touches is inside its own directory ----------------

MUTATORS = (
    "unlink",
    "remove",
    "rmdir",
    "mkdir",
    "makedirs",
    "chmod",
    "rename",
    "replace",
    "utime",
    "symlink",
    "link",
    "truncate",
    "open",
)


class Audit:
    def __init__(self) -> None:
        self.touched: list[str] = []


@pytest.fixture
def audit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Audit:
    """Record every path handed to a mutating ``os`` function by fs/sandbox.py, and fail the
    call if it is not inside ``tmp_path`` (the only base directory the tests ever give it)."""
    record = Audit()
    base = os.path.normcase(os.path.realpath(tmp_path))

    def guard(name: str, real: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(path: Any, *args: Any, **kwargs: Any) -> Any:
            if isinstance(path, str | bytes | os.PathLike):
                text = os.path.normcase(os.path.realpath(os.fsdecode(path)))
                record.touched.append(text)
                inside = text == base or text.startswith(base + os.sep)
                if not inside:
                    raise AssertionError(f"sandbox.{name}() touched {text!r}, outside {base!r}")
            return real(path, *args, **kwargs)

        return wrapper

    for name in MUTATORS:
        real = getattr(os, name, None)
        if real is not None:
            monkeypatch.setattr(f"fim.fs.sandbox.os.{name}", guard(name, real))
    real_mkdtemp = tempfile.mkdtemp

    def mkdtemp(*args: Any, **kwargs: Any) -> str:
        directory = kwargs.get("dir")
        if directory is None or not os.path.normcase(os.path.realpath(directory)).startswith(base):
            raise AssertionError(f"mkdtemp() outside the test base: {directory!r}")
        return str(real_mkdtemp(*args, **kwargs))

    monkeypatch.setattr("fim.fs.sandbox.tempfile.mkdtemp", mkdtemp)
    return record


def listing(directory: Path) -> list[str]:
    return sorted(entry.name for entry in directory.iterdir())


def digest_tree(root: Path) -> dict[str, tuple[str, int]]:
    state = {}
    for current, directories, names in os.walk(root):
        for name in [*directories, *names]:
            path = Path(current) / name
            info = path.lstat()
            data = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""
            state[str(path.relative_to(root))] = (data, info.st_mtime_ns)
    return state


@pytest.fixture
def bystander(tmp_path: Path) -> Path:
    """A directory next to the demo's workspace that the demo must never look at."""
    folder = tmp_path / "bystander"
    folder.mkdir()
    (folder / "precious.txt").write_bytes(b"do not touch\n")
    (folder / "sub").mkdir()
    (folder / "sub" / "deep.txt").write_bytes(b"nor this\n")
    return folder


# ---- the demo ------------------------------------------------------------------------------------


# Slow, by decision of the owner (PLAN.md changelog v0.3.8): every test of this section that is
# marked slow runs the whole demo (a real temporary tree, key, baseline, six steps and the
# removal), 0.1 to 0.35 s each on Windows. The sandbox tests below, the staging failure and the
# hostile-name count stay in the default gate; --full and CI run all of them.
@pytest.fixture(scope="module")
def transcript(tmp_path_factory: pytest.TempPathFactory) -> str:
    """One real run, shared by the tests that only read what the demo printed."""
    base = tmp_path_factory.mktemp("demo-once")
    outcome = run_demo(FakeClock(), base_directory=str(base))
    assert outcome.exit_code is ExitCode.OK
    assert outcome.workspace_removed
    return outcome.text


@pytest.mark.slow
def test_the_demo_shows_every_expected_finding_kind_and_the_refusal(transcript: str) -> None:
    for kind in EXPECTED_KINDS:
        assert kind.value in transcript
    assert "exit code 0" in transcript  # the clean check before the changes
    assert "exit code 1" in transcript  # the check that finds them
    assert "refused, exit code 3" in transcript  # the tampered baseline
    assert "MAC does not verify" in transcript
    assert "the temporary directory was removed" in transcript


@pytest.mark.slow
def test_the_hostile_name_is_shown_escaped_and_never_raw(transcript: str) -> None:
    assert "payroll\\u202e\\u200btxt.bak" in transcript
    assert transcript.isascii()
    assert "\x1b" not in transcript
    assert "\u202e" not in transcript
    assert "\u200b" not in transcript
    assert transcript.count("\n\n\n") == 0


@pytest.mark.posix_only
@pytest.mark.slow
def test_on_posix_a_name_with_an_escape_sequence_and_a_newline_is_also_shown_escaped(
    transcript: str,
) -> None:
    assert "\\x1b[2Jcleared\\x0asecond-line.txt" in transcript


@pytest.mark.slow
def test_the_demo_touches_only_its_own_directory_and_leaves_the_base_as_it_found_it(
    tmp_path: Path, bystander: Path, audit: Audit
) -> None:
    before = digest_tree(tmp_path)
    outcome = run_demo(FakeClock(), base_directory=str(tmp_path))
    assert outcome.workspace_removed
    assert digest_tree(tmp_path) == before
    assert listing(tmp_path) == ["bystander"]
    assert audit.touched  # the guard really was in the way of every mutation


@pytest.mark.slow
def test_the_workspace_exists_while_the_demo_runs_and_each_run_has_its_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Also the default: with no base directory the demo uses the system temp directory."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    seen: list[list[str]] = []
    made: list[str] = []
    real_mkdtemp = tempfile.mkdtemp

    def recording(*args: Any, **kwargs: Any) -> str:
        made.append(real_mkdtemp(*args, **kwargs))
        return made[-1]

    def spying_check(*args: Any, **kwargs: Any) -> Any:
        seen.append(listing(tmp_path))
        return run_check(*args, **kwargs)

    monkeypatch.setattr("fim.fs.sandbox.tempfile.mkdtemp", recording)
    monkeypatch.setattr("fim.app.demo.run_check", spying_check)
    run_demo(FakeClock())
    run_demo(FakeClock())
    assert seen
    assert all(len(names) == 1 and names[0].startswith("fim-demo-") for names in seen)
    assert len(made) == 2
    assert made[0] != made[1]
    assert listing(tmp_path) == []


@pytest.mark.parametrize("failing_call", [1, 2, 3])
@pytest.mark.slow
def test_a_step_that_raises_still_removes_the_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bystander: Path, failing_call: int
) -> None:
    real_check = run_check
    calls = {"n": 0}

    def failing(*args: Any, **kwargs: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == failing_call:
            raise RuntimeError("boom inside a step")
        return real_check(*args, **kwargs)

    monkeypatch.setattr("fim.app.demo.run_check", failing)
    with pytest.raises(RuntimeError, match="boom"):
        run_demo(FakeClock(), base_directory=str(tmp_path))
    assert listing(tmp_path) == ["bystander"]
    assert (bystander / "precious.txt").read_bytes() == b"do not touch\n"


def test_a_failure_while_staging_the_files_still_removes_the_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(self: Sandbox, relative: str, data: bytes) -> None:
        raise SandboxError("the disk is full")

    monkeypatch.setattr(Sandbox, "write_file", fail)
    with pytest.raises(SandboxError, match="disk is full"):
        run_demo(FakeClock(), base_directory=str(tmp_path))
    assert listing(tmp_path) == []


@pytest.mark.slow
def test_a_demo_that_finds_nothing_is_a_failed_demo_not_a_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Sandbox, "remove_file", lambda *_args: None)
    with pytest.raises(DemoError, match="missing deleted"):
        run_demo(FakeClock(), base_directory=str(tmp_path))
    assert listing(tmp_path) == []
    assert isinstance(DemoError("x"), FimError)
    assert DemoError.exit_code is ExitCode.ERROR


@pytest.mark.slow
def test_a_baseline_that_is_accepted_after_tampering_is_a_failed_demo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Sandbox, "flip_byte", lambda *_args: None)
    with pytest.raises(DemoError, match="tampered baseline was accepted"):
        run_demo(FakeClock(), base_directory=str(tmp_path))
    assert listing(tmp_path) == []


@pytest.mark.slow
def test_a_clean_check_that_reports_findings_is_a_failed_demo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_check = run_check
    state = {"calls": 0}

    def meddling(request: Any, clock: Any) -> Any:
        state["calls"] += 1
        if state["calls"] == 1:  # before the first check, change a watched file behind its back
            watched = Path(request.config_path).parent.parent / "watched"
            (watched / "notes.txt").write_bytes(b"changed behind the demo's back")
        return real_check(request, clock)

    monkeypatch.setattr("fim.app.demo.run_check", meddling)
    with pytest.raises(DemoError, match="reported as changed before any change"):
        run_demo(FakeClock(), base_directory=str(tmp_path))
    assert listing(tmp_path) == []


def test_windows_gets_one_hostile_name_and_posix_two(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("fim.app.demo.sys.platform", "win32")
    windows = hostile_names()
    monkeypatch.setattr("fim.app.demo.sys.platform", "linux")
    posix = hostile_names()
    assert len(windows) == 1
    assert posix[0] == windows[0]
    assert len(posix) == 2
    assert not any(ord(char) < 0x20 for char in windows[0])  # a legal Windows file name


@pytest.mark.slow
def test_the_cli_demo_prints_the_transcript_and_exits_0(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    assert cli.main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "fim demo:" in out
    assert "refused, exit code 3" in out
    assert listing(tmp_path) == []


# ---- the sandbox ---------------------------------------------------------------------------------


@pytest.fixture
def box(tmp_path: Path) -> Iterator[Sandbox]:
    sandbox = Sandbox.create(str(tmp_path))
    yield sandbox
    sandbox.destroy()


def test_a_sandbox_is_a_new_empty_directory_with_a_recognisable_name(
    tmp_path: Path, box: Sandbox
) -> None:
    assert Path(box.root).parent == tmp_path
    assert Path(box.root).name.startswith("fim-demo-")
    assert listing(Path(box.root)) == []
    assert box.exists()


@pytest.mark.parametrize(
    "relative",
    ["", "/etc/passwd", "../outside", "a/../../outside", "a//b", "a/./b", ".", "..", "a\\b",
     "C:/x", "a/\x00b", "C:x", "a:stream"],
)  # fmt: skip
def test_paths_that_could_leave_the_sandbox_are_refused(box: Sandbox, relative: str) -> None:
    with pytest.raises(SandboxError, match="not a plain path"):
        box.path(relative)
    with pytest.raises(SandboxError):
        box.write_file(relative, b"x")


def test_files_are_written_changed_and_removed_inside_the_root(box: Sandbox) -> None:
    box.write_file("a/b/c.txt", b"one")
    path = Path(box.path("a/b/c.txt"))
    assert path.read_bytes() == b"one"
    box.write_file("a/b/c.txt", b"two")
    assert path.read_bytes() == b"two"
    box.remove_file("a/b/c.txt")
    assert not path.exists()
    box.make_directory("x/y")
    assert Path(box.path("x/y")).is_dir()


def test_a_failed_operation_is_a_sandbox_error_naming_the_relative_path(box: Sandbox) -> None:
    with pytest.raises(SandboxError, match=r"could not delete missing\.txt"):
        box.remove_file("missing.txt")
    with pytest.raises(SandboxError, match="could not change the permissions of nope"):
        box.set_mode("nope", 0o600)
    with pytest.raises(SandboxError, match="could not modify absent"):
        box.flip_byte("absent", 0)


def test_flip_byte_changes_exactly_one_byte_and_counts_negative_offsets_from_the_end(
    box: Sandbox,
) -> None:
    box.write_file("f", b"\x00\x00\x00\x00")
    box.flip_byte("f", 1)
    box.flip_byte("f", -1)
    assert Path(box.path("f")).read_bytes() == b"\x00\x01\x00\x01"
    with pytest.raises(SandboxError, match="beyond the end"):
        box.flip_byte("f", 10)


def test_destroy_removes_everything_including_read_only_files(box: Sandbox) -> None:
    box.write_file("dir/locked.txt", b"x")
    box.write_file("other.txt", b"y")
    box.set_mode("dir/locked.txt", stat.S_IREAD)
    box.set_mode("other.txt", stat.S_IREAD)
    box.destroy()
    assert not box.exists()
    box.destroy()  # a second call is harmless


@pytest.mark.posix_only
@pytest.mark.requires_non_root
def test_destroy_removes_a_directory_without_write_permission(box: Sandbox) -> None:
    box.write_file("closed/inner/file.txt", b"x")
    os.chmod(box.path("closed/inner"), 0o500)
    os.chmod(box.path("closed"), 0o500)
    box.destroy()
    assert not box.exists()


@pytest.mark.requires_symlinks
def test_destroy_removes_a_link_and_never_what_it_points_at(tmp_path: Path, box: Sandbox) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_bytes(b"keep")
    os.symlink(outside, box.path("link-to-dir"), target_is_directory=True)
    os.symlink(outside / "keep.txt", box.path("link-to-file"))
    box.destroy()
    assert not box.exists()
    assert (outside / "keep.txt").read_bytes() == b"keep"


@pytest.mark.skipif(sys.platform != "win32", reason="junctions exist on Windows only")
@pytest.mark.windows_only
def test_destroy_removes_a_junction_and_never_its_target(tmp_path: Path, box: Sandbox) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_bytes(b"keep")
    winhelp.make_junction(Path(box.path("junction")), outside)
    box.destroy()
    assert not box.exists()
    assert (outside / "keep.txt").read_bytes() == b"keep"


def test_a_directory_that_cannot_be_removed_is_reported_not_ignored(
    box: Sandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    box.write_file("stuck.txt", b"x")

    def refuse(path: str) -> None:
        raise PermissionError(13, "denied")

    monkeypatch.setattr("fim.fs.sandbox.os.unlink", refuse)
    with pytest.raises(SandboxError, match="could not be removed completely"):
        box.destroy()
    monkeypatch.undo()
    box.destroy()  # and a later attempt works once the obstacle is gone


def test_creating_a_sandbox_in_a_missing_directory_is_a_sandbox_error(tmp_path: Path) -> None:
    with pytest.raises(SandboxError, match="could not create a temporary directory"):
        Sandbox.create(str(tmp_path / "no-such-directory"))


def test_the_module_exports_and_is_importable_only_by_the_demo() -> None:
    assert set(sandbox_module.__all__) == {"Sandbox", "SandboxError"}
    from conftest import REPO_ROOT

    checker = (REPO_ROOT / "scripts" / "check_architecture.py").read_text(encoding="utf-8")
    assert '"fim.fs.sandbox": frozenset({"fim.app.demo"})' in checker


def test_a_directory_that_cannot_be_made_or_written_is_a_sandbox_error(box: Sandbox) -> None:
    box.write_file("plain", b"x")
    with pytest.raises(SandboxError, match="could not create the directory"):
        box.make_directory("plain/inside")
    with pytest.raises(SandboxError, match="could not write"):
        box.write_file("plain/inside.txt", b"x")


def test_a_failure_to_examine_list_or_remove_is_counted_and_reported(
    box: Sandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    box.write_file("a/b.txt", b"x")
    real_lstat, real_listdir, real_rmdir = os.lstat, os.listdir, os.rmdir
    inner = box.path("a")

    def lstat(path: Any, *args: Any, **kwargs: Any) -> Any:
        if str(path).endswith("b.txt"):
            raise PermissionError(13, "denied")
        return real_lstat(path, *args, **kwargs)

    def listdir(path: Any = ".") -> Any:
        if str(path) == inner:
            raise PermissionError(13, "denied")
        return real_listdir(path)

    monkeypatch.setattr("fim.fs.sandbox.os.lstat", lstat)
    with pytest.raises(SandboxError, match="could not be removed completely"):
        box.destroy()
    monkeypatch.undo()
    monkeypatch.setattr("fim.fs.sandbox.os.listdir", listdir)
    with pytest.raises(SandboxError, match="could not be removed completely"):
        box.destroy()
    monkeypatch.undo()

    def rmdir(path: Any) -> None:
        if str(path) == inner:
            raise PermissionError(13, "denied")
        real_rmdir(path)

    monkeypatch.setattr("fim.fs.sandbox.os.rmdir", rmdir)
    with pytest.raises(SandboxError, match="could not be removed completely"):
        box.destroy()
    monkeypatch.undo()
    box.destroy()
    assert not box.exists()
