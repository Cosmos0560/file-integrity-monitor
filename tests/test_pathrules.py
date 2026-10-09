"""core/pathrules.py: what a user-supplied path may look like, for both operating systems.

The rules are pure string logic, so every case runs on every host. Hostile characters are written
as escapes, never raw.
"""

from __future__ import annotations

import random

import pytest

from fim.core import pathrules
from fim.core.errors import PathRuleError
from fim.core.limits import MAX_DEPTH_CEILING, MAX_PATH_CHARS
from fim.core.pathrules import (
    Flavour,
    UserPath,
    display_path,
    display_user_path,
    is_reserved_windows_name,
    is_within,
    record_path,
    split_record_path,
    validate_user_path,
)

WIN = Flavour.WINDOWS
POSIX = Flavour.POSIX


def refused(raw: str, flavour: Flavour, **kwargs: bool) -> str:
    """Validate ``raw``, expect a refusal, and return the error message."""
    with pytest.raises(PathRuleError) as raised:
        validate_user_path(raw, flavour, **kwargs)
    return str(raised.value)


# ---- Windows: accepted --------------------------------------------------------------------------

WINDOWS_ACCEPTED = [
    pytest.param(r"C:\Users\lab", "C:", True, ("Users", "lab"), r"C:\Users\lab", id="drive-path"),
    pytest.param(
        "c:/Users/lab/", "C:", True, ("Users", "lab"), r"C:\Users\lab", id="lowercase-drive"
    ),
    pytest.param(r"C:\\Users\\\\lab", "C:", True, ("Users", "lab"), r"C:\Users\lab", id="repeated"),
    pytest.param(r"C:\a\.\b", "C:", True, ("a", "b"), r"C:\a\b", id="dot-component-dropped"),
    pytest.param("C:\\", "C:", True, (), "C:\\", id="drive-root"),
    pytest.param("C:/", "C:", True, (), "C:\\", id="drive-root-forward-slash"),
    pytest.param(r"relative\dir", "", False, ("relative", "dir"), r"relative\dir", id="relative"),
    pytest.param(
        r"C:\Program Files\App",
        "C:",
        True,
        ("Program Files", "App"),
        r"C:\Program Files\App",
        id="space",
    ),
    pytest.param(
        "C:\\caf\u00e9\\\u65e5\u672c",
        "C:",
        True,
        ("caf\u00e9", "\u65e5\u672c"),
        "C:\\caf\u00e9\\\u65e5\u672c",
        id="unicode",
    ),
    pytest.param(
        r"C:\CONSOLE\COM10\NULL\aux_file\dir.CON.txt",
        "C:",
        True,
        ("CONSOLE", "COM10", "NULL", "aux_file", "dir.CON.txt"),
        r"C:\CONSOLE\COM10\NULL\aux_file\dir.CON.txt",
        id="near-miss-device-names",
    ),
    pytest.param("C://x", "C:", True, ("x",), r"C:\x", id="drive-with-double-slash-is-not-a-url"),
]


@pytest.mark.parametrize(("raw", "drive", "absolute", "parts", "text"), WINDOWS_ACCEPTED)
def test_windows_paths_that_are_accepted(
    raw: str, drive: str, absolute: bool, parts: tuple[str, ...], text: str
) -> None:
    path = validate_user_path(raw, WIN)
    assert (path.drive, path.absolute, path.parts, path.text) == (drive, absolute, parts, text)
    assert path.tilde is False


def test_windows_tilde_is_a_home_directory_only_when_allowed() -> None:
    home = validate_user_path("~", WIN, allow_tilde=True)
    assert (home.tilde, home.parts, home.text) == (True, (), "~")
    bin_dir = validate_user_path(r"~\bin\tools", WIN, allow_tilde=True)
    assert (bin_dir.tilde, bin_dir.parts, bin_dir.text) == (True, ("bin", "tools"), r"~\bin\tools")
    assert validate_user_path("~/bin", WIN, allow_tilde=True).parts == ("bin",)
    plain = validate_user_path("~", WIN)  # without allow_tilde it is an ordinary name
    assert (plain.tilde, plain.parts) == (False, ("~",))


# ---- Windows: refused ---------------------------------------------------------------------------

WINDOWS_REFUSED = [
    pytest.param(r"\\server\share\file", "UNC", id="unc"),
    pytest.param("//server/share/file", "UNC", id="unc-forward-slashes"),
    pytest.param(r"\\?\C:\Windows", "device path", id="device-question-mark"),
    pytest.param(r"\\.\COM1", "device path", id="device-dot"),
    pytest.param(r"\\?\UNC\server\share", "device path", id="device-unc"),
    pytest.param("//?/C:/x", "device path", id="device-forward-slashes"),
    pytest.param("//./pipe/x", "device path", id="device-dot-forward-slashes"),
    pytest.param(r"\??\C:\x", "NT object path", id="nt-object"),
    pytest.param(r"\Windows\System32", "current drive", id="rooted-without-drive"),
    pytest.param("/Windows", "current drive", id="forward-rooted-without-drive"),
    pytest.param("\\", "current drive", id="single-backslash"),
    pytest.param("\\??", "current drive", id="short-nt-prefix-is-just-rooted"),
    pytest.param("C:", "drive-relative", id="drive-only"),
    pytest.param("C:foo", "drive-relative", id="drive-relative-file"),
    pytest.param(r"C:foo\bar", "drive-relative", id="drive-relative-dir"),
    pytest.param("z:rel", "drive-relative", id="other-drive-relative"),
    pytest.param("a:b", "drive-relative", id="looks-like-drive-relative"),
    pytest.param(r"C:\dir\file.txt:stream", "colon", id="alternate-data-stream"),
    pytest.param(r"C:\dir\file.txt::$DATA", "colon", id="ads-default-stream"),
    pytest.param("name:stream", "colon", id="relative-ads"),
    pytest.param(r"C:\CON", "reserved", id="con"),
    pytest.param(r"C:\dir\NUL.txt", "reserved", id="nul-with-extension"),
    pytest.param(r"C:\dir\com1", "reserved", id="com1-lowercase"),
    pytest.param(r"C:\dir\LPT9.log", "reserved", id="lpt9"),
    pytest.param(r"C:\dir\AUX", "reserved", id="aux"),
    pytest.param(r"C:\dir\PRN.tar.gz", "reserved", id="prn-double-extension"),
    pytest.param("C:\\dir\\COM\u00b9", "reserved", id="com-superscript-one"),
    pytest.param("C:\\dir\\LPT\u00b3.txt", "reserved", id="lpt-superscript-three"),
    pytest.param(r"C:\dir\CONIN$", "reserved", id="conin"),
    pytest.param(r"C:\dir\CONOUT$", "reserved", id="conout"),
    pytest.param(r"C:\dir\con .txt", "reserved", id="space-before-extension"),
    pytest.param(r"C:\aux ", "space or a dot", id="trailing-space"),
    pytest.param("C:\\nul.", "space or a dot", id="trailing-dot"),
    pytest.param("C:\\a\\b.", "space or a dot", id="trailing-dot-file"),
    pytest.param(r"C:\a<b", "not allowed in a Windows name", id="less-than"),
    pytest.param(r"C:\a>b", "not allowed in a Windows name", id="greater-than"),
    pytest.param('C:\\a"b', "not allowed in a Windows name", id="double-quote"),
    pytest.param(r"C:\a|b", "not allowed in a Windows name", id="pipe"),
    pytest.param(r"C:\a?b", "not allowed in a Windows name", id="question-mark"),
    pytest.param(r"C:\a*b", "not allowed in a Windows name", id="asterisk"),
    pytest.param(r"C:\a\..\b", "'..'", id="parent-component"),
    pytest.param("..", "'..'", id="bare-parent"),
    pytest.param(r"..\x", "'..'", id="leading-parent"),
    pytest.param(r"~user\x", "~user", id="tilde-user"),
]


@pytest.mark.parametrize(("raw", "reason"), WINDOWS_REFUSED)
def test_windows_paths_that_are_refused(raw: str, reason: str) -> None:
    message = refused(raw, WIN, allow_tilde=True)
    assert reason in message
    assert message.startswith("path '")


# ---- POSIX: accepted ----------------------------------------------------------------------------

POSIX_ACCEPTED = [
    pytest.param("/etc", True, ("etc",), "/etc", id="absolute"),
    pytest.param(
        "/home/lab/bin/", True, ("home", "lab", "bin"), "/home/lab/bin", id="trailing-slash"
    ),
    pytest.param("//etc//passwd", True, ("etc", "passwd"), "/etc/passwd", id="repeated-slashes"),
    pytest.param("/a/./b", True, ("a", "b"), "/a/b", id="dot-component"),
    pytest.param("/", True, (), "/", id="root"),
    pytest.param("relative/dir", False, ("relative", "dir"), "relative/dir", id="relative"),
    pytest.param("/srv/a:b", True, ("srv", "a:b"), "/srv/a:b", id="colon-in-name"),
    pytest.param(
        "/srv/2024-01-01T10:00:00.log",
        True,
        ("srv", "2024-01-01T10:00:00.log"),
        "/srv/2024-01-01T10:00:00.log",
        id="timestamp-name",
    ),
    pytest.param("/srv/with space", True, ("srv", "with space"), "/srv/with space", id="space"),
    pytest.param("/srv/CON", True, ("srv", "CON"), "/srv/CON", id="windows-device-name-is-fine"),
    pytest.param(
        "/srv/back\\slash", True, ("srv", "back\\slash"), "/srv/back\\slash", id="backslash-in-name"
    ),
    pytest.param("/srv/caf\u00e9", True, ("srv", "caf\u00e9"), "/srv/caf\u00e9", id="unicode"),
    pytest.param(
        "/srv/http:/x", True, ("srv", "http:", "x"), "/srv/http:/x", id="scheme-like-in-the-middle"
    ),
    pytest.param(
        "/srv/trailing.", True, ("srv", "trailing."), "/srv/trailing.", id="trailing-dot-is-fine"
    ),
]


@pytest.mark.parametrize(("raw", "absolute", "parts", "text"), POSIX_ACCEPTED)
def test_posix_paths_that_are_accepted(
    raw: str, absolute: bool, parts: tuple[str, ...], text: str
) -> None:
    path = validate_user_path(raw, POSIX)
    assert (path.absolute, path.parts, path.text, path.drive) == (absolute, parts, text, "")


def test_posix_tilde() -> None:
    assert validate_user_path("~/bin", POSIX, allow_tilde=True).text == "~/bin"
    assert validate_user_path("~", POSIX, allow_tilde=True).parts == ()
    assert validate_user_path("~", POSIX).parts == ("~",)


# ---- POSIX: refused -----------------------------------------------------------------------------

POSIX_REFUSED = [
    pytest.param("\\\\server\\share", "UNC or device", id="unc-syntax"),
    pytest.param("\\\\?\\C:\\x", "UNC or device", id="device-syntax"),
    pytest.param("\\\\.\\COM1", "UNC or device", id="device-dot-syntax"),
    pytest.param("C:foo", "Windows drive", id="drive-relative"),
    pytest.param("C:/x", "Windows drive", id="drive-absolute"),
    pytest.param("c:", "Windows drive", id="drive-only"),
    pytest.param("/a/../b", "'..'", id="parent-component"),
    pytest.param("..", "'..'", id="bare-parent"),
    pytest.param("../x", "'..'", id="leading-parent"),
    pytest.param("~user/x", "~user", id="tilde-user"),
]


@pytest.mark.parametrize(("raw", "reason"), POSIX_REFUSED)
def test_posix_paths_that_are_refused(raw: str, reason: str) -> None:
    assert reason in refused(raw, POSIX, allow_tilde=True)


# ---- both flavours ------------------------------------------------------------------------------

URL_LIKE = [
    "http://example.com/x",
    "HTTPS://example.com",
    "ftp://host/dir",
    "s3://bucket/key",
    "a1+b.c-d://x",
    "file:///etc/passwd",
    "file:/etc/passwd",
    "FILE:x",
    "file:C:/x",
    "  http://spaces-first",
]


@pytest.mark.parametrize("flavour", [WIN, POSIX])
@pytest.mark.parametrize("raw", URL_LIKE)
def test_url_like_paths_are_refused_on_both_systems(raw: str, flavour: Flavour) -> None:
    assert "URL-like" in refused(raw, flavour)


@pytest.mark.parametrize("flavour", [WIN, POSIX])
def test_empty_path_is_refused(flavour: Flavour) -> None:
    assert "empty" in refused("", flavour)


@pytest.mark.parametrize("flavour", [WIN, POSIX])
@pytest.mark.parametrize(
    "bad",
    [
        0x00,
        0x07,
        0x0A,
        0x0D,
        0x09,
        0x1B,
        0x7F,
        0x85,
        0x202E,
        0x200B,
        0xFEFF,
        0x2028,
        0xE000,
        0x0378,
        0xDC80,
    ],
)
def test_unsafe_characters_are_refused_on_both_systems(bad: int, flavour: Flavour) -> None:
    prefix = "C:\\dir\\" if flavour is WIN else "/dir/"
    message = refused(prefix + "a" + chr(bad) + "b", flavour)
    assert "unsafe character" in message
    assert f"U+{bad:04X}" in message


@pytest.mark.parametrize("flavour", [WIN, POSIX])
def test_over_long_paths_are_refused(flavour: Flavour) -> None:
    prefix = "C:\\" if flavour is WIN else "/"
    ok = prefix + "a" * (MAX_PATH_CHARS - len(prefix))
    assert len(ok) == MAX_PATH_CHARS
    assert validate_user_path(ok, flavour).parts == ("a" * (MAX_PATH_CHARS - len(prefix)),)
    assert "longer than" in refused(ok + "a", flavour)


def test_the_character_limit_can_be_lowered() -> None:
    with pytest.raises(PathRuleError, match="longer than 10"):
        validate_user_path("/aaaa/bbbbbbb", POSIX, max_chars=10)


@pytest.mark.parametrize("flavour", [WIN, POSIX])
def test_too_many_components_are_refused(flavour: Flavour) -> None:
    prefix = "C:\\" if flavour is WIN else "/"
    sep = "\\" if flavour is WIN else "/"
    allowed = prefix + sep.join("d" for _ in range(MAX_DEPTH_CEILING))
    assert len(validate_user_path(allowed, flavour).parts) == MAX_DEPTH_CEILING
    assert "components" in refused(allowed + sep + "d", flavour)


def test_require_absolute() -> None:
    with pytest.raises(PathRuleError, match="absolute"):
        validate_user_path("rel/dir", POSIX, require_absolute=True)
    with pytest.raises(PathRuleError, match="absolute"):
        validate_user_path(r"rel\dir", WIN, require_absolute=True)
    assert validate_user_path("/abs", POSIX, require_absolute=True).absolute
    assert validate_user_path("~/x", POSIX, require_absolute=True, allow_tilde=True).tilde
    # without allow_tilde, "~/x" is just a relative path named "~"
    with pytest.raises(PathRuleError, match="absolute"):
        validate_user_path("~/x", POSIX, require_absolute=True)


def test_refusal_messages_never_contain_hostile_characters() -> None:
    hostile = "/dir/\x1b[31mred" + chr(0x202E) + "\nnext"
    message = refused(hostile, POSIX)
    for char in ("\x1b", chr(0x202E), "\n"):
        assert char not in message


def test_refusal_message_is_bounded() -> None:
    message = refused("http://" + "x" * 5000, POSIX)
    assert len(message) < 300


def test_validated_text_is_a_fixed_point() -> None:
    cases = [(r"C:\\a\.\b\\", WIN), ("c:/x/y/", WIN), ("//a//b/./c/", POSIX), ("rel/./x", POSIX)]
    for raw, flavour in cases:
        once = validate_user_path(raw, flavour)
        again = validate_user_path(once.text, flavour)
        assert again == once


# ---- reserved names -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "CON",
        "con",
        "Prn",
        "AUX",
        "NUL",
        "COM1",
        "com9",
        "COM0",
        "LPT1",
        "lpt9",
        "NUL.txt",
        "con.tar.gz",
        "COM1 .x",
        "CONIN$",
        "CONOUT$",
        "COM\u00b2",
        "LPT\u00b9.log",
    ],
)
def test_reserved_windows_names(name: str) -> None:
    assert is_reserved_windows_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "CONSOLE",
        "COM10",
        "LPT10",
        "COM",
        "LPT",
        "NULL",
        "aux_file",
        "file.CON",
        "xCON",
        "CON_",
        "",
        "COM1x",
    ],
)
def test_names_that_are_not_reserved(name: str) -> None:
    assert not is_reserved_windows_name(name)


# ---- containment --------------------------------------------------------------------------------


def _win(raw: str) -> UserPath:
    return validate_user_path(raw, WIN)


def _posix(raw: str) -> UserPath:
    return validate_user_path(raw, POSIX)


@pytest.mark.parametrize(
    ("path", "root", "expected"),
    [
        ("/data/fim/fim.key", "/data/fim", True),
        ("/data/fim", "/data/fim", True),
        ("/data/fimx/key", "/data/fim", False),
        ("/data", "/data/fim", False),
        ("/anything", "/", True),
        ("/Data/fim/key", "/data/fim", False),
    ],
)
def test_posix_containment_is_by_component_and_case_sensitive(
    path: str, root: str, expected: bool
) -> None:
    assert is_within(_posix(path), _posix(root)) is expected


@pytest.mark.parametrize(
    ("path", "root", "expected"),
    [
        (r"C:\Data\fim\fim.key", r"C:\Data\fim", True),
        (r"c:\DATA\FIM\Key", r"C:\data\fim", True),
        (r"C:\Data\fimx\key", r"C:\Data\fim", False),
        (r"D:\Data\fim\key", r"C:\Data\fim", False),
        (r"C:\Data", r"C:\Data\fim", False),
        (r"C:\anything", "C:\\", True),
    ],
)
def test_windows_containment_is_by_component_and_case_insensitive(
    path: str, root: str, expected: bool
) -> None:
    assert is_within(_win(path), _win(root)) is expected


def test_containment_needs_absolute_paths_of_one_flavour() -> None:
    with pytest.raises(PathRuleError, match="absolute"):
        is_within(_posix("rel"), _posix("/root"))
    with pytest.raises(PathRuleError, match="absolute"):
        is_within(_posix("/abs"), validate_user_path("~", POSIX, allow_tilde=True))
    with pytest.raises(PathRuleError, match="flavour"):
        is_within(_win(r"C:\a"), _posix("/a"))


# ---- record paths (PLAN.md D14) and display (D10 amendment) -------------------------------------


def test_record_path_keeps_each_component_exactly_and_joins_with_slash() -> None:
    parts = ("docs", "a b", "x\ny", "back\\slash", "e" + chr(0x202E))
    assert record_path(parts) == "docs/a b/x\ny/back\\slash/e" + chr(0x202E)
    assert record_path(()) == ""


def test_record_path_does_not_escape_or_touch_lone_surrogates() -> None:
    assert record_path(("a" + chr(0xDC80),)) == "a" + chr(0xDC80)
    assert record_path(("\x1b[31m",)) == "\x1b[31m"


@pytest.mark.parametrize("parts", [("",), (".",), ("..",), ("a", ""), ("a/b",)])
def test_record_path_refuses_bad_components(parts: tuple[str, ...]) -> None:
    with pytest.raises(PathRuleError):
        record_path(parts)


def test_record_path_round_trips() -> None:
    rng = random.Random(42)
    alphabet = [
        "a",
        "b",
        " ",
        "\\",
        "\x1b",
        chr(0x202E),
        chr(0xE9),
        chr(0x65E5),
        chr(0xDC80),
        "x1b",
    ]
    for _ in range(1000):
        parts = tuple(
            "n" + "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 6)))
            for _ in range(rng.randrange(0, 5))
        )
        assert split_record_path(record_path(parts)) == parts


@pytest.mark.parametrize("text", ["a//b", "/a", "a/", ".", "a/./b", "a/../b"])
def test_split_record_path_refuses_malformed_text(text: str) -> None:
    with pytest.raises(PathRuleError):
        split_record_path(text)


def test_split_record_path_takes_raw_characters_because_storage_is_exact() -> None:
    assert split_record_path("a\x1bb/c\\x41") == ("a\x1bb", "c\\x41")


def test_windows_display_never_shows_doubled_backslashes() -> None:
    root = _win(r"C:\Users\lab")
    shown = display_path(root, record_path(("docs", "notes.txt")))
    assert shown == r"C:\Users\lab\docs\notes.txt"
    assert "\\\\" not in shown
    assert root.display() == r"C:\Users\lab"
    assert "\\\\" not in display_path(_win("C:\\"), record_path(("a", "b")))
    assert display_path(_win("C:\\"), record_path(("a",))) == "C:\\a"
    assert display_path(root, "") == r"C:\Users\lab"


def test_windows_display_escapes_hostile_components_and_still_has_single_separators() -> None:
    root = _win(r"C:\dir")
    shown = display_path(root, record_path(("a\u202eb", "x\x1by")))
    assert shown == "C:\\dir\\a\\u202eb\\x\\x1by"
    assert "\x1b" not in shown
    assert chr(0x202E) not in shown


def test_posix_display_keeps_a_literal_backslash_visible_as_two() -> None:
    root = _posix("/data")
    assert display_path(root, record_path(("a\\b",))) == "/data/a\\\\b"
    assert display_path(_posix("/"), record_path(("etc",))) == "/etc"
    assert display_path(_posix("/"), "") == "/"


def test_tilde_root_display() -> None:
    home = validate_user_path("~", POSIX, allow_tilde=True)
    assert display_path(home, record_path(("bin",))) == "~/bin"


def test_display_refuses_a_non_canonical_record_path() -> None:
    with pytest.raises(PathRuleError):
        display_path(_posix("/data"), "a//b")


def test_module_exports() -> None:
    assert set(pathrules.__all__) >= {"validate_user_path", "Flavour", "UserPath", "display_path"}


# ---- display_user_path ---------------------------------------------------------------------------


def test_a_windows_path_is_shown_with_single_backslashes() -> None:
    shown = display_user_path(r"C:\Users\lab\fim.key", WIN)
    assert shown == r"C:\Users\lab\fim.key"
    assert "\\\\" not in shown


def test_a_posix_path_is_shown_with_slashes() -> None:
    assert display_user_path("/home/lab/fim.key", POSIX) == "/home/lab/fim.key"
    assert display_user_path("rel/dir/k", POSIX) == "rel/dir/k"


def test_a_tilde_path_is_shown_as_given() -> None:
    assert display_user_path("~/keys/k", POSIX) == "~/keys/k"


def test_dangerous_characters_in_a_shown_path_are_escaped() -> None:
    shown = display_user_path("/dir/a\u202eb", POSIX)
    assert "\u202e" not in shown
    assert shown == "/dir/a\\u202eb"


def test_a_refused_path_is_shown_escaped_and_clipped() -> None:
    shown = display_user_path("a/../b\x1b[31m", POSIX)
    assert "\x1b" not in shown
    assert "\\x1b" in shown
    assert len(display_user_path("http://" + "a" * 500, POSIX, 50)) <= 50


def test_a_valid_but_too_long_path_is_clipped() -> None:
    path = "/" + "/".join(["component"] * 30)
    assert len(display_user_path(path, POSIX, 40)) <= 40
