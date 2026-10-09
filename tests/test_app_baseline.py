"""app/baseline.py: init-key, baseline and the verified-baseline reader on real temporary trees."""

from __future__ import annotations

import hashlib
import os
import sys
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import winhelp
from app_helpers import Workspace, make_workspace, tree_state, write_config
from fakes import FakeClock
from fim.app import baseline as app
from fim.app.baseline import BaselineRequest, InitKeyRequest
from fim.core.errors import (
    BaselineIntegrityError,
    ConfigError,
    ExitCode,
    FileAccessError,
    FileMissingError,
    LimitReachedError,
    PathRuleError,
    UsageError,
)
from fim.core.limits import DEFAULT_LIMITS
from fim.core.models import EntryType, HashStatus
from fim.core.pathrules import Flavour, validate_user_path
from fim.fs.safe_files import FileTooLargeError
from fim.services import baseline_codec as codec
from fim.services import keystore


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    return make_workspace(tmp_path)


def make_key(workspace: Workspace) -> keystore.Key:
    return keystore.init_key(str(workspace.key_file), force=False)


def request(workspace: Workspace, **overrides: Any) -> BaselineRequest:
    fields: dict[str, Any] = {
        "config_path": str(workspace.config),
        "baseline_path": str(workspace.baseline),
        "key_file": str(workspace.key_file),
        "force": False,
    }
    fields.update(overrides)
    return BaselineRequest(**fields)


def run(workspace: Workspace, **overrides: Any) -> app.BaselineOutcome:
    return app.run_baseline(request(workspace, **overrides), FakeClock())


def directory_names(path: Path) -> list[str]:
    return sorted(entry.name for entry in path.iterdir())


# ---- init-key ------------------------------------------------------------------------------------


def test_init_key_creates_the_file_and_reports_only_the_key_id(ws: Workspace) -> None:
    outcome = app.run_init_key(InitKeyRequest(str(ws.key_file), None, False))
    key = keystore.load_key(str(ws.key_file))
    assert outcome.key_id == key.key_id
    assert outcome.key_path == str(ws.key_file)
    assert outcome.anchor_path == str(ws.key_file) + ".fim-anchor"
    assert key.secret.hex() not in repr(outcome)


def test_init_key_refuses_to_replace_without_force(ws: Workspace) -> None:
    app.run_init_key(InitKeyRequest(str(ws.key_file), None, False))
    before = ws.key_file.read_bytes()
    with pytest.raises(FileAccessError, match="already exists"):
        app.run_init_key(InitKeyRequest(str(ws.key_file), None, False))
    assert ws.key_file.read_bytes() == before
    app.run_init_key(InitKeyRequest(str(ws.key_file), None, True))
    assert ws.key_file.read_bytes() != before


def test_init_key_with_a_config_refuses_a_path_inside_its_monitored_paths(ws: Workspace) -> None:
    with pytest.raises(PathRuleError, match="must not be inside a monitored path"):
        app.run_init_key(InitKeyRequest(str(ws.watched / "fim.key"), str(ws.config), False))
    assert not (ws.watched / "fim.key").exists()


def test_init_key_without_a_config_cannot_know_the_roots(ws: Workspace) -> None:
    app.run_init_key(InitKeyRequest(str(ws.watched / "fim.key"), None, False))
    assert (ws.watched / "fim.key").exists()  # only --config makes the check possible


# ---- baseline: the happy path --------------------------------------------------------------------


def test_baseline_writes_a_verifiable_baseline_and_an_anchor(ws: Workspace) -> None:
    key = make_key(ws)
    outcome = run(ws)
    assert outcome.sequence == 1
    assert outcome.complete
    assert outcome.exit_code == ExitCode.OK
    assert outcome.key_id == key.key_id
    assert outcome.anchor_existed is False
    assert outcome.issues == ()
    data = ws.baseline.read_bytes()
    assert outcome.size_bytes == len(data)

    verified = app.read_verified_baseline(str(ws.baseline), key, str(ws.key_file))
    assert verified.warnings == ()
    decoded = verified.decoded
    assert decoded.baseline.header.sequence == 1
    assert decoded.baseline.header.host == "lab-01"
    assert decoded.baseline.header.complete
    assert outcome.records == len(decoded.baseline.records)

    by_path = {record.path: record for record in decoded.baseline.records}
    assert set(by_path) == {"", "file0.txt", "file1.txt", "file2.txt", "sub", "sub/nested.txt"}
    assert by_path[""].type is EntryType.DIR
    assert by_path["file1.txt"].sha256 == hashlib.sha256(b"content 1\n").hexdigest()
    assert by_path["file1.txt"].hash_status is HashStatus.OK
    assert by_path["sub/nested.txt"].size == len(b"nested\n")


def test_the_anchor_matches_the_baseline_just_written(ws: Workspace) -> None:
    key = make_key(ws)
    outcome = run(ws)
    raw = keystore.read_anchor_bytes(str(ws.key_file))
    assert raw is not None
    anchor = codec.decode_anchor(raw, key)
    assert anchor.sequence == outcome.sequence
    assert (
        anchor.payload_sha256
        == hashlib.sha256(ws.baseline.read_bytes().split(b"\n", 1)[1]).hexdigest()
    )


def test_the_sequence_is_the_anchors_plus_one(ws: Workspace) -> None:
    make_key(ws)
    assert [run(ws, force=index > 0).sequence for index in range(4)] == [1, 2, 3, 4]
    assert run(ws, force=True).anchor_existed is True


def test_the_scan_never_changes_a_monitored_file(ws: Workspace) -> None:
    make_key(ws)
    before = tree_state(ws.watched)
    listing = directory_names(ws.watched)
    run(ws)
    run(ws, force=True)
    assert tree_state(ws.watched) == before
    assert directory_names(ws.watched) == listing


def test_baseline_writes_only_its_own_files(ws: Workspace) -> None:
    make_key(ws)
    run(ws)
    assert directory_names(ws.keys) == ["fim.key", "fim.key.fim-anchor"]
    assert directory_names(ws.baseline.parent) == ["fim.baseline"]
    assert directory_names(ws.base) == ["fim.yaml", "keys", "out", "watched"]


def test_the_key_can_come_from_the_configuration(ws: Workspace) -> None:
    make_key(ws)
    write_config(ws.config, [ws.watched], key_file=ws.key_file)
    outcome = run(ws, key_file=None)
    assert outcome.sequence == 1


def test_the_command_line_key_overrides_the_configuration(ws: Workspace) -> None:
    other = ws.keys / "other.key"
    other_key = keystore.init_key(str(other), force=False)
    make_key(ws)
    write_config(ws.config, [ws.watched], key_file=ws.key_file)
    outcome = run(ws, key_file=str(other))
    assert outcome.key_id == other_key.key_id
    assert (ws.keys / "other.key.fim-anchor").exists()


def test_a_missing_key_setting_is_a_usage_error(ws: Workspace) -> None:
    with pytest.raises(UsageError, match="no key file"):
        run(ws, key_file=None)
    assert not ws.baseline.exists()


# ---- baseline: refusals --------------------------------------------------------------------------


def test_an_existing_baseline_is_not_replaced_without_force_and_the_scan_does_not_run(
    ws: Workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_key(ws)
    run(ws)
    before = ws.baseline.read_bytes()
    anchor_before = (ws.keys / "fim.key.fim-anchor").read_bytes()
    monkeypatch.setattr(
        app, "scan", lambda *_a, **_k: pytest.fail("the scan ran although the write was refused")
    )
    with pytest.raises(FileAccessError, match="already exists; use --force"):
        run(ws)
    assert ws.baseline.read_bytes() == before
    assert (ws.keys / "fim.key.fim-anchor").read_bytes() == anchor_before


def test_a_baseline_path_inside_a_monitored_root_is_refused(ws: Workspace) -> None:
    make_key(ws)
    with pytest.raises(PathRuleError, match="must not be inside a monitored path"):
        run(ws, baseline_path=str(ws.watched / "fim.baseline"))
    assert directory_names(ws.watched) == sorted(["file0.txt", "file1.txt", "file2.txt", "sub"])


def test_a_key_file_inside_a_monitored_root_is_refused_on_the_command_line(ws: Workspace) -> None:
    inside = ws.watched / "fim.key"
    keystore.init_key(str(inside), force=False)
    with pytest.raises(PathRuleError, match="must not be inside a monitored path"):
        run(ws, key_file=str(inside))
    assert not ws.baseline.exists()


def test_a_key_file_inside_a_monitored_root_is_refused_in_the_configuration(ws: Workspace) -> None:
    inside = ws.watched / "fim.key"
    write_config(ws.config, [ws.watched], key_file=inside)
    with pytest.raises(ConfigError, match="key_file must not be inside a monitored path"):
        run(ws, key_file=None)


def test_a_missing_baseline_directory_is_an_error(ws: Workspace) -> None:
    make_key(ws)
    with pytest.raises(FileAccessError):
        run(ws, baseline_path=str(ws.base / "nodir" / "fim.baseline"))
    assert not (ws.keys / "fim.key.fim-anchor").exists()


def test_a_missing_monitored_path_is_refused_and_nothing_is_written(ws: Workspace) -> None:
    make_key(ws)
    write_config(ws.config, [ws.watched, ws.base / "gone"])
    with pytest.raises(ConfigError, match="a monitored path is unavailable") as raised:
        run(ws)
    assert raised.value.exit_code == ExitCode.ERROR
    assert "not found" in raised.value.message
    assert not ws.baseline.exists()
    assert not (ws.keys / "fim.key.fim-anchor").exists()


@pytest.mark.requires_symlinks
def test_a_monitored_root_that_is_a_symlink_is_refused_with_exit_2(ws: Workspace) -> None:
    make_key(ws)
    link = ws.base / "link-to-watched"
    os.symlink(ws.watched, link, target_is_directory=True)
    write_config(ws.config, [link])
    with pytest.raises(
        ConfigError, match="link or reparse point; configure the real path"
    ) as raised:
        run(ws)
    assert raised.value.exit_code == ExitCode.ERROR
    assert not ws.baseline.exists()
    assert not (ws.keys / "fim.key.fim-anchor").exists()


@pytest.mark.windows_only
def test_a_monitored_root_that_is_a_junction_is_refused_with_exit_2(ws: Workspace) -> None:
    make_key(ws)
    junction = ws.base / "junction-to-watched"
    winhelp.make_junction(junction, ws.watched)
    write_config(ws.config, [junction])
    with pytest.raises(
        ConfigError, match="link or reparse point; configure the real path"
    ) as raised:
        run(ws)
    assert raised.value.exit_code == ExitCode.ERROR
    assert not ws.baseline.exists()


def test_a_monitored_root_that_is_a_file_is_accepted(ws: Workspace) -> None:
    make_key(ws)
    single = ws.base / "single.txt"
    single.write_bytes(b"one file")
    write_config(ws.config, [single])
    outcome = run(ws)
    assert outcome.records == 1


# ---- baseline: limits ----------------------------------------------------------------------------


def test_a_scan_that_hits_a_limit_still_writes_a_baseline_marked_incomplete_with_exit_4(
    ws: Workspace,
) -> None:
    key = make_key(ws)
    write_config(ws.config, [ws.watched], limits={"max_files": 3})
    outcome = run(ws)
    assert outcome.complete is False
    assert outcome.exit_code == ExitCode.INCOMPLETE
    assert any(issue.kind.value == "limit_reached" for issue in outcome.issues)
    verified = app.read_verified_baseline(str(ws.baseline), key, str(ws.key_file))
    assert verified.decoded.baseline.header.complete is False
    assert keystore.read_anchor_bytes(str(ws.key_file)) is not None


def test_a_baseline_over_the_size_limit_is_not_written(ws: Workspace) -> None:
    make_key(ws)
    write_config(ws.config, [ws.watched], limits={"max_baseline_bytes": 500})
    with pytest.raises(LimitReachedError, match="nothing was written") as raised:
        run(ws)
    assert raised.value.exit_code == ExitCode.INCOMPLETE
    assert not ws.baseline.exists()
    assert not (ws.keys / "fim.key.fim-anchor").exists()


# ---- baseline: the anchor ------------------------------------------------------------------------


def test_a_tampered_anchor_stops_a_new_baseline_with_exit_3(ws: Workspace) -> None:
    make_key(ws)
    run(ws)
    anchor = ws.keys / "fim.key.fim-anchor"
    anchor.write_bytes(anchor.read_bytes().replace(b"sequence 1", b"sequence 9"))
    before = ws.baseline.read_bytes()
    with pytest.raises(BaselineIntegrityError) as raised:
        run(ws, force=True)
    assert raised.value.exit_code == ExitCode.INTEGRITY
    assert ws.baseline.read_bytes() == before


def test_an_anchor_made_with_another_key_stops_a_new_baseline_with_exit_3(ws: Workspace) -> None:
    make_key(ws)
    run(ws)
    keystore.init_key(str(ws.key_file), force=True)  # a new key, the old anchor stays
    with pytest.raises(BaselineIntegrityError, match="different key"):
        run(ws, force=True)


def test_a_missing_anchor_restarts_the_sequence_at_one(ws: Workspace) -> None:
    make_key(ws)
    run(ws)
    run(ws, force=True)
    (ws.keys / "fim.key.fim-anchor").unlink()
    outcome = run(ws, force=True)
    assert outcome.sequence == 1
    assert outcome.anchor_existed is False


def test_if_the_anchor_cannot_be_written_the_error_is_reported_and_force_repairs_it(
    ws: Workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = make_key(ws)

    def fail(*_a: object) -> None:
        raise FileAccessError("anchor file could not be written (EIO)")

    with monkeypatch.context() as patch:
        patch.setattr(keystore, "write_anchor_bytes", fail)
        with pytest.raises(FileAccessError, match="anchor file"):
            run(ws)
    assert ws.baseline.exists()  # written first, as documented
    assert not (ws.keys / "fim.key.fim-anchor").exists()
    assert read(ws, key).warnings  # without an anchor the baseline still verifies, with a warning
    repaired = run(ws, force=True)
    assert repaired.sequence == 1
    app.read_verified_baseline(str(ws.baseline), key, str(ws.key_file))


# ---- the configuration file ----------------------------------------------------------------------


def test_a_missing_configuration_is_exit_2(ws: Workspace) -> None:
    make_key(ws)
    with pytest.raises(FileMissingError, match="configuration file"):
        run(ws, config_path=str(ws.base / "nope.yaml"))


def test_an_oversize_configuration_is_refused_unread(ws: Workspace) -> None:
    make_key(ws)
    ws.config.write_bytes(b"#" * (256 * 1024 + 1))
    with pytest.raises(FileTooLargeError, match="configuration file"):
        run(ws)


@pytest.mark.requires_symlinks
def test_a_configuration_that_is_a_symlink_is_not_followed(ws: Workspace) -> None:
    make_key(ws)
    link = ws.base / "link.yaml"
    os.symlink(ws.config, link)
    with pytest.raises(FileAccessError, match="symbolic link or reparse point"):
        run(ws, config_path=str(link))


def test_an_invalid_configuration_is_exit_2(ws: Workspace) -> None:
    make_key(ws)
    ws.config.write_text("version: 2\npaths: []\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        run(ws)


@pytest.mark.parametrize(
    "raw",
    ["http://example.com/x", "file:///etc/passwd", "a/../b", "~user/x", ""]
    + (
        ["\\\\server\\share\\x", "\\\\?\\C:\\x", "C:x", "C:\\dir\\CON"]
        if sys.platform == "win32"
        else []
    ),
)
def test_hostile_command_line_paths_are_refused_before_any_io(raw: str) -> None:
    with pytest.raises(PathRuleError):
        app.resolve_path_argument(raw, None)


def test_a_tilde_path_is_expanded_with_the_home_directory() -> None:
    flavour = Flavour.WINDOWS if sys.platform == "win32" else Flavour.POSIX
    home_text = "C:\\Users\\lab" if sys.platform == "win32" else "/home/lab"
    home = validate_user_path(home_text, flavour, require_absolute=True)
    sep = "\\" if sys.platform == "win32" else "/"
    assert (
        app.resolve_path_argument("~/keys/fim.key", home)
        == home_text + sep + "keys" + sep + "fim.key"
    )
    assert app.resolve_path_argument("plain/relative", home) == "plain/relative"
    with pytest.raises(UsageError, match="home directory is unknown"):
        app.resolve_path_argument("~/x", None)


# ---- reading a baseline back ---------------------------------------------------------------------


def make_baseline(ws: Workspace) -> keystore.Key:
    key = make_key(ws)
    run(ws)
    return key


def read(ws: Workspace, key: keystore.Key) -> app.VerifiedBaseline:
    return app.read_verified_baseline(str(ws.baseline), key, str(ws.key_file))


def test_a_missing_baseline_is_an_error_never_no_changes(ws: Workspace) -> None:
    key = make_key(ws)
    with pytest.raises(FileMissingError) as raised:
        read(ws, key)
    assert raised.value.exit_code == ExitCode.ERROR


def test_a_missing_anchor_is_only_a_warning(ws: Workspace) -> None:
    key = make_baseline(ws)
    (ws.keys / "fim.key.fim-anchor").unlink()
    verified = read(ws, key)
    assert len(verified.warnings) == 1
    assert "no rollback anchor found" in verified.warnings[0]
    assert "fim.key.fim-anchor" in verified.warnings[0]


def flip_mac(data: bytes) -> bytes:
    marker = b'"mac":"'
    start = data.index(marker) + len(marker)
    flipped = b"0" if data[start : start + 1] != b"0" else b"1"
    return data[:start] + flipped + data[start + 1 :]


@pytest.mark.parametrize(
    "tamper",
    [
        pytest.param(lambda d: d[:-1], id="truncated"),
        pytest.param(lambda d: d + b"\n", id="trailing-newline"),
        pytest.param(lambda d: d + b"junk", id="trailing-bytes"),
        pytest.param(lambda d: d[:40], id="cut-in-the-envelope"),
        pytest.param(lambda _d: b"", id="empty"),
        pytest.param(lambda d: d.replace(b'"version":1', b'"version":2'), id="version"),
        pytest.param(lambda d: d.replace(b"fim-baseline", b"fim-basel1ne"), id="format"),
        pytest.param(lambda d: d.replace(b"lab-01", b"lab-02"), id="payload"),
        pytest.param(flip_mac, id="mac"),
    ],
)
def test_every_tampered_baseline_is_exit_3_with_a_clear_message(ws: Workspace, tamper: Any) -> None:
    key = make_baseline(ws)
    ws.baseline.write_bytes(tamper(ws.baseline.read_bytes()))
    with pytest.raises(BaselineIntegrityError) as raised:
        read(ws, key)
    assert raised.value.exit_code == ExitCode.INTEGRITY
    assert raised.value.message.startswith("the baseline is not trustworthy: ")


def test_a_changed_key_id_is_reported_as_the_wrong_key(ws: Workspace) -> None:
    key = make_baseline(ws)
    data = ws.baseline.read_bytes()
    ws.baseline.write_bytes(data.replace(key.key_id.encode(), b"0" * 16, 1))
    with pytest.raises(BaselineIntegrityError, match="wrong key file"):
        read(ws, key)


def test_the_wrong_key_is_reported_as_the_wrong_key(ws: Workspace) -> None:
    make_baseline(ws)
    other = keystore.generate_key()
    with pytest.raises(BaselineIntegrityError, match="wrong key file") as raised:
        read(ws, other)
    assert raised.value.exit_code == ExitCode.INTEGRITY


def test_an_oversize_baseline_is_exit_3_and_never_read(
    ws: Workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = make_baseline(ws)
    ws.baseline.write_bytes(b"x" * 2000)
    monkeypatch.setattr(
        os, "read", lambda *_a: pytest.fail("an oversize baseline must not be read")
    )
    with pytest.raises(BaselineIntegrityError, match="larger than the 1000 byte limit") as raised:
        app.read_verified_baseline(
            str(ws.baseline),
            key,
            str(ws.key_file),
            limits=replace(DEFAULT_LIMITS, max_baseline_bytes=1000),
        )
    assert raised.value.exit_code == ExitCode.INTEGRITY


def test_an_older_validly_signed_baseline_put_back_is_refused_as_a_rollback(ws: Workspace) -> None:
    key = make_key(ws)
    run(ws)
    old = ws.baseline.read_bytes()
    run(ws, force=True)
    run(ws, force=True)
    ws.baseline.write_bytes(old)  # a genuine, correctly signed, but old baseline
    codec.decode_baseline(old, key, max_bytes=10**9)  # it does verify on its own
    with pytest.raises(BaselineIntegrityError, match="rollback anchor") as raised:
        read(ws, key)
    assert raised.value.exit_code == ExitCode.INTEGRITY
    assert "sequence 1" in raised.value.message
    assert "sequence 3" in raised.value.message


def test_a_tampered_anchor_is_exit_3_when_reading(ws: Workspace) -> None:
    key = make_baseline(ws)
    anchor = ws.keys / "fim.key.fim-anchor"
    anchor.write_bytes(anchor.read_bytes().replace(b"sequence 1", b"sequence 2"))
    with pytest.raises(BaselineIntegrityError, match="rollback anchor") as raised:
        read(ws, key)
    assert raised.value.exit_code == ExitCode.INTEGRITY


def test_a_substituted_baseline_with_the_right_sequence_is_refused(ws: Workspace) -> None:
    key = make_baseline(ws)
    decoded = codec.decode_baseline(ws.baseline.read_bytes(), key, max_bytes=10**9)
    header = replace(decoded.baseline.header, host="elsewhere")  # same sequence, other content
    forged = codec.encode_baseline(replace(decoded.baseline, header=header), key)
    ws.baseline.write_bytes(forged.data)
    codec.decode_baseline(forged.data, key, max_bytes=10**9)  # it verifies on its own
    with pytest.raises(BaselineIntegrityError, match="different content"):
        read(ws, key)


# ---- the key never leaks -------------------------------------------------------------------------


def test_the_key_appears_in_no_output_exception_baseline_anchor_or_log(
    ws: Workspace, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    key = make_key(ws)
    secret_hex = key.secret.hex()
    collected: list[str] = []

    outcome = run(ws)
    collected.append(repr(outcome))
    failing_calls: list[Callable[[], object]] = [
        lambda: run(ws),  # exists
        lambda: run(ws, key_file=str(ws.keys / "missing.key")),
        lambda: run(ws, baseline_path=str(ws.watched / "x"), force=True),
    ]
    for failing in failing_calls:
        with pytest.raises(Exception) as raised:  # noqa: PT011  # any failure; none may leak
            failing()
        collected.extend([str(raised.value), repr(raised.value)])
    ws.baseline.write_bytes(ws.baseline.read_bytes()[:-1])
    with pytest.raises(BaselineIntegrityError) as tampered:
        read(ws, key)
    collected.extend([tampered.value.message, repr(tampered.value)])

    captured = capsys.readouterr()
    collected.extend([captured.out, captured.err, caplog.text])
    collected.append(ws.baseline.read_bytes().decode("ascii"))
    collected.append((ws.keys / "fim.key.fim-anchor").read_text(encoding="ascii"))
    collected.append(repr(os.environ.values()))
    collected.append(repr(sys.argv))
    for text in collected:
        assert secret_hex not in text
        assert secret_hex.upper() not in text
    assert caplog.records == []
