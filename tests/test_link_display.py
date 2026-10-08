"""core/pathrules.py display_link_target: storage keeps readlink's text, only display changes.

Synthetic strings, so the rule is tested on every OS (the real Windows behaviour is asserted in
test_observe.py and test_scanner_real.py).
"""

from __future__ import annotations

import pytest

from fim.core.pathrules import Flavour, display_link_target

WINDOWS = Flavour.WINDOWS
POSIX = Flavour.POSIX


@pytest.mark.parametrize(
    ("raw", "shown"),
    [
        (r"\\?\C:\Users\lab\target.txt", r"C:\Users\lab\target.txt"),
        (r"\\?\c:\x", r"c:\x"),
        (r"\\?\C:", "C:"),
        (r"\\?\C:/mixed/seps", "C:/mixed/seps"),
        (r"\\?\UNC\server\share\dir\f", r"\\server\share\dir\f"),
        (r"\\?\unc\server\share", r"\\server\share"),
        (r"\\?\UNC\server", r"\\server"),
        # nothing to strip: shown as is
        (r"C:\Users\lab\target.txt", r"C:\Users\lab\target.txt"),
        (r"..\sibling\f.txt", r"..\sibling\f.txt"),
        ("relative.txt", "relative.txt"),
        ("", ""),
        # other extended forms are not a drive or UNC path: dropping the prefix would lie
        (r"\\?\Volume{01234567-89ab}\dir\f", r"\\?\Volume{01234567-89ab}\dir\f"),
        (r"\\?\GLOBALROOT\Device\X", r"\\?\GLOBALROOT\Device\X"),
        (r"\\?\C", r"\\?\C"),
        (r"\\?\CC:\x", r"\\?\CC:\x"),
        # only a leading prefix is special
        (r"C:\a\\?\b", r"C:\a\\?\b"),
    ],
)
def test_windows_display_strips_the_extended_prefix_only_for_drive_and_unc_paths(
    raw: str, shown: str
) -> None:
    assert display_link_target(raw, WINDOWS) == shown


def test_the_display_never_shows_doubled_backslashes_for_a_windows_path() -> None:
    assert "\\\\" not in display_link_target(r"\\?\C:\a\b\c", WINDOWS)


def test_hostile_components_are_escaped_one_by_one_and_separators_are_kept() -> None:
    raw = "\\\\?\\C:\\dir\\" + "bidi" + chr(0x202E) + "x\\esc\x1b[31m/forward\n"
    shown = display_link_target(raw, WINDOWS)
    assert shown == "C:\\dir\\bidi" + "\\u202e" + "x\\esc\\x1b[31m/forward\\x0a"
    assert chr(0x202E) not in shown
    assert "\x1b" not in shown
    assert "\n" not in shown


def test_undecodable_posix_bytes_are_shown_as_y_escapes() -> None:
    assert display_link_target("bad" + chr(0xDC80) + "/name", POSIX) == "bad\\y80/name"


def test_a_posix_target_is_never_rewritten() -> None:
    # A backslash is an ordinary name character on POSIX, so the Windows prefix means nothing.
    raw = r"\\?\C:\x"
    assert display_link_target(raw, POSIX) == "\\\\\\\\?\\\\C:\\\\x"  # escaped, prefix kept
    assert display_link_target("../up/target", POSIX) == "../up/target"
    assert display_link_target("/abs/target", POSIX) == "/abs/target"


def test_display_is_stable_when_applied_to_its_own_output() -> None:
    once = display_link_target(r"\\?\C:\a\b", WINDOWS)
    assert display_link_target(once, WINDOWS) == once
