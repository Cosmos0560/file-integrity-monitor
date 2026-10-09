"""services/keystore.py: the key file, key ids, and the anchor file's bytes (PLAN.md D2, D3)."""

from __future__ import annotations

import hashlib
import hmac
import os
import stat
from collections.abc import Callable
from pathlib import Path

import pytest

from fim.core.errors import ConfigError, ExitCode, FileAccessError, FileMissingError, PathRuleError
from fim.fs.safe_files import FileTooLargeError
from fim.services import keystore
from fim.services.keystore import Key

SECRET = bytes(range(32))
HEX = SECRET.hex()
HEADER = "FIM-HMAC-KEY v1"


def write_private(path: Path, data: bytes) -> None:
    """Write a key-like file that only its owner can read (load_key refuses anything else)."""
    path.write_bytes(data)
    path.chmod(0o600)


def fixed(value: bytes = SECRET) -> Callable[[int], bytes]:
    return lambda size: value[:size]


# ---- the Key object ------------------------------------------------------------------------------


def test_a_key_must_be_exactly_32_bytes() -> None:
    for bad in (b"", b"x" * 31, b"x" * 33):
        with pytest.raises(ConfigError):
            Key(bad)
    with pytest.raises(ConfigError):
        Key("x" * 32)  # type: ignore[arg-type]  # the wrong type is the test


def test_key_id_follows_the_documented_formula() -> None:
    expected = hmac.new(SECRET, b"fim key id v1", hashlib.sha256).hexdigest()[:16]
    assert Key(SECRET).key_id == expected
    assert len(expected) == 16
    assert Key(SECRET).key_id != Key(bytes(reversed(SECRET))).key_id


def test_key_id_reveals_nothing_usable() -> None:
    assert HEX[:16] != Key(SECRET).key_id
    assert HEX not in Key(SECRET).key_id


def test_mac_is_hmac_sha256() -> None:
    assert Key(SECRET).mac(b"m") == hmac.new(SECRET, b"m", hashlib.sha256).digest()


def test_no_text_form_of_a_key_shows_the_secret() -> None:
    key = Key(SECRET)
    forms = [
        repr(key),
        str(key),
        f"{key}",
        f"{key!r}",
        "%s %r" % (key, key),  # noqa: UP031  # the printf style is one of the forms to check
        format(key),
        repr([key]),
        repr({"k": key}),
    ]
    for text in forms:
        assert HEX not in text
        assert repr(SECRET) not in text
        assert str(list(SECRET)) not in text
        assert key.key_id in text


def test_a_key_is_frozen_and_compares_by_value() -> None:
    key = Key(SECRET)
    with pytest.raises(AttributeError):
        key.secret = b"x" * 32  # type: ignore[misc]  # frozen on purpose
    assert key == Key(SECRET)
    assert hash(key) == hash(Key(SECRET))


def test_generate_key_uses_the_given_random_source_for_32_bytes() -> None:
    sizes: list[int] = []

    def source(size: int) -> bytes:
        sizes.append(size)
        return SECRET

    assert keystore.generate_key(source).secret == SECRET
    assert sizes == [32]


def test_generate_key_default_is_random_and_32_bytes() -> None:
    first, second = keystore.generate_key(), keystore.generate_key()
    assert len(first.secret) == 32
    assert first != second


# ---- the key file format -------------------------------------------------------------------------


def test_key_file_format_is_two_lines() -> None:
    assert keystore.encode_key_file(Key(SECRET)) == f"{HEADER}\n{HEX}\n".encode("ascii")
    assert keystore.KEY_HEADER == HEADER


def test_key_file_round_trip_and_final_newline_is_optional() -> None:
    assert keystore.decode_key_file(keystore.encode_key_file(Key(SECRET))) == Key(SECRET)
    assert keystore.decode_key_file(f"{HEADER}\n{HEX}".encode("ascii")) == Key(SECRET)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"", "does not start with"),
        (b"\n", "does not start with"),
        (HEX.encode() + b"\n", "does not start with"),
        (f"FIM-HMAC-KEY v2\n{HEX}\n".encode(), "does not start with"),
        (f"fim-hmac-key v1\n{HEX}\n".encode(), "does not start with"),
        (f" {HEADER}\n{HEX}\n".encode(), "does not start with"),
        (f"{HEADER}\r\n{HEX}\r\n".encode(), "does not start with"),
        (f"{HEADER}\n".encode(), "exactly two lines"),
        (f"{HEADER}\n{HEX}\nextra\n".encode(), "exactly two lines"),
        (f"{HEADER}\n{HEX}\n\n".encode(), "exactly two lines"),
        (f"{HEADER}\n\n{HEX}\n".encode(), "exactly two lines"),
        (f"{HEADER}\n{HEX[:-1]}\n".encode(), "lower-case hex"),
        (f"{HEADER}\n{HEX}0\n".encode(), "lower-case hex"),
        (f"{HEADER}\n{HEX.upper()}\n".encode(), "lower-case hex"),
        (f"{HEADER}\n{'g' * 64}\n".encode(), "lower-case hex"),
        (f"{HEADER}\n{HEX}\r\n".encode(), "lower-case hex"),
        (f"{HEADER}\n {HEX}\n".encode(), "lower-case hex"),
        (f"{HEADER}\n{HEX} \n".encode(), "lower-case hex"),
        (f"{HEADER}\n\u00e9{HEX[1:]}\n".encode(), "plain ASCII"),
        (b"\xff\xfe" + HEADER.encode(), "plain ASCII"),
        (b"x" * 5000, "larger than 4096"),
    ],
)
def test_malformed_key_files_are_refused_with_a_clear_message(content: bytes, message: str) -> None:
    with pytest.raises(ConfigError, match=message) as raised:
        keystore.decode_key_file(content)
    assert raised.value.exit_code == ExitCode.ERROR


def test_a_refusal_never_repeats_the_file_content() -> None:
    wrong_header_but_a_real_key = f"NOT-A-KEY\n{HEX}\n".encode()
    for content in (
        wrong_header_but_a_real_key,
        f"{HEADER}\n{HEX}0\n".encode(),
        f"{HEADER}\n{HEX[:-1]}\n".encode(),
        f"{HEADER}\n{HEX.upper()}\n".encode(),
        f"{HEADER}\n{HEX}\nextra\n".encode(),
    ):
        with pytest.raises(ConfigError) as raised:
            keystore.decode_key_file(content)
        assert HEX not in raised.value.message
        assert HEX.upper() not in raised.value.message
        assert HEX[:20] not in raised.value.message


# ---- creating and loading key files --------------------------------------------------------------


def test_init_key_creates_a_loadable_file_and_returns_the_key(tmp_path: Path) -> None:
    path = tmp_path / "fim.key"
    key = keystore.init_key(str(path), force=False, random_bytes=fixed())
    assert key == Key(SECRET)
    assert path.read_bytes() == f"{HEADER}\n{HEX}\n".encode("ascii")
    assert keystore.load_key(str(path)) == key
    assert [entry.name for entry in tmp_path.iterdir()] == ["fim.key"]


def test_init_key_default_randomness_gives_a_different_key_each_time(tmp_path: Path) -> None:
    first = keystore.init_key(str(tmp_path / "a.key"), force=False)
    second = keystore.init_key(str(tmp_path / "b.key"), force=False)
    assert first != second


def test_init_key_refuses_to_replace_a_key_without_force(tmp_path: Path) -> None:
    path = tmp_path / "fim.key"
    keystore.init_key(str(path), force=False, random_bytes=fixed())
    before = path.read_bytes()
    with pytest.raises(FileAccessError, match=r"key file .* already exists; use --force"):
        keystore.init_key(str(path), force=False)
    assert path.read_bytes() == before


def test_init_key_force_replaces_the_key(tmp_path: Path) -> None:
    path = tmp_path / "fim.key"
    keystore.init_key(str(path), force=False, random_bytes=fixed())
    other = bytes(reversed(SECRET))
    keystore.init_key(str(path), force=True, random_bytes=fixed(other))
    assert keystore.load_key(str(path)).secret == other


def test_init_key_force_leaves_an_old_anchor_alone(tmp_path: Path) -> None:
    path = tmp_path / "fim.key"
    keystore.init_key(str(path), force=False)
    keystore.write_anchor_bytes(str(path), b"anchor")
    keystore.init_key(str(path), force=True)
    assert keystore.read_anchor_bytes(str(path)) == b"anchor"


def test_init_key_refuses_a_path_inside_a_monitored_root(tmp_path: Path) -> None:
    root = tmp_path / "watched"
    root.mkdir()
    with pytest.raises(PathRuleError, match="must not be inside a monitored path"):
        keystore.init_key(str(root / "fim.key"), force=False, avoid_roots=[str(root)])
    assert list(root.iterdir()) == []


def test_load_key_refuses_a_key_inside_a_monitored_root(tmp_path: Path) -> None:
    root = tmp_path / "watched"
    root.mkdir()
    (root / "fim.key").write_bytes(keystore.encode_key_file(Key(SECRET)))
    with pytest.raises(PathRuleError, match="must not be inside a monitored path"):
        keystore.load_key(str(root / "fim.key"), avoid_roots=[str(root)])


def test_load_key_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileMissingError, match=r"key file .* does not exist"):
        keystore.load_key(str(tmp_path / "nope.key"))


def test_load_key_wrong_header_never_echoes_the_content(tmp_path: Path) -> None:
    path = tmp_path / "fim.key"
    write_private(path, f"NOT-A-KEY\n{HEX}\n".encode())
    with pytest.raises(ConfigError) as raised:
        keystore.load_key(str(path))
    assert HEX not in raised.value.message


def test_load_key_oversize_file_is_refused_unread(tmp_path: Path) -> None:
    path = tmp_path / "fim.key"
    write_private(path, b"x" * 5000)
    with pytest.raises(FileTooLargeError, match="larger than 4096"):
        keystore.load_key(str(path))


@pytest.mark.requires_symlinks
def test_load_key_will_not_follow_a_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real.key"
    real.write_bytes(keystore.encode_key_file(Key(SECRET)))
    link = tmp_path / "link.key"
    os.symlink(real, link)
    with pytest.raises(FileAccessError, match="symbolic link or reparse point"):
        keystore.load_key(str(link))


@pytest.mark.requires_symlinks
def test_init_key_will_not_write_through_a_symlink(tmp_path: Path) -> None:
    target = tmp_path / "victim"
    target.write_bytes(b"precious")
    link = tmp_path / "fim.key"
    os.symlink(target, link)
    for force in (False, True):
        with pytest.raises(FileAccessError):
            keystore.init_key(str(link), force=force)
    assert target.read_bytes() == b"precious"


@pytest.mark.posix_only
def test_a_new_key_file_is_mode_0600_and_a_group_readable_one_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "fim.key"
    keystore.init_key(str(path), force=False)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    path.chmod(0o640)
    with pytest.raises(FileAccessError, match="not private"):
        keystore.load_key(str(path))


# ---- the anchor file -----------------------------------------------------------------------------


def test_the_anchor_sits_next_to_the_key_with_a_fixed_suffix() -> None:
    assert keystore.ANCHOR_SUFFIX == ".fim-anchor"
    assert keystore.anchor_path("/keys/fim.key") == "/keys/fim.key.fim-anchor"


def test_a_missing_anchor_is_none_not_an_error(tmp_path: Path) -> None:
    assert keystore.read_anchor_bytes(str(tmp_path / "fim.key")) is None


def test_anchor_bytes_round_trip_and_replace(tmp_path: Path) -> None:
    key_path = str(tmp_path / "fim.key")
    keystore.write_anchor_bytes(key_path, b"one")
    assert keystore.read_anchor_bytes(key_path) == b"one"
    keystore.write_anchor_bytes(key_path, b"two")
    assert keystore.read_anchor_bytes(key_path) == b"two"
    assert [entry.name for entry in tmp_path.iterdir()] == ["fim.key.fim-anchor"]


def test_an_oversize_anchor_is_refused(tmp_path: Path) -> None:
    (tmp_path / "fim.key.fim-anchor").write_bytes(b"x" * 2000)
    with pytest.raises(FileTooLargeError):
        keystore.read_anchor_bytes(str(tmp_path / "fim.key"))


@pytest.mark.requires_symlinks
def test_the_anchor_is_neither_read_nor_written_through_a_symlink(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_bytes(b"precious")
    os.symlink(victim, tmp_path / "fim.key.fim-anchor")
    with pytest.raises(FileAccessError, match="symbolic link or reparse point"):
        keystore.read_anchor_bytes(str(tmp_path / "fim.key"))
    with pytest.raises(FileAccessError, match="symbolic link or reparse point"):
        keystore.write_anchor_bytes(str(tmp_path / "fim.key"), b"evil")
    assert victim.read_bytes() == b"precious"
