"""platform/hostinfo.py: path flavour, home directory and host label."""

from __future__ import annotations

import sys

import pytest

from fim.core.pathrules import Flavour
from fim.platform import hostinfo

HOME_VARIABLE = "USERPROFILE" if sys.platform == "win32" else "HOME"
GOOD_HOME = "C:\\Users\\lab" if sys.platform == "win32" else "/home/lab"
HOSTILE_HOMES = (
    ["relative\\home", "\\\\server\\share", "\\\\?\\C:\\x", "C:home", "C:\\a\\..\\b", "http://x/y"]
    if sys.platform == "win32"
    else ["relative/home", "http://example.com/x", "/home/../etc", "/home/\x1b[31mx", "~"]
)


def test_flavour_follows_sys_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    assert hostinfo.path_flavour() is Flavour.WINDOWS
    monkeypatch.setattr(sys, "platform", "linux")
    assert hostinfo.path_flavour() is Flavour.POSIX
    monkeypatch.setattr(sys, "platform", "darwin")
    assert hostinfo.path_flavour() is Flavour.POSIX


def test_platform_name_is_sys_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    assert hostinfo.platform_name() == "linux"


def test_home_comes_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(HOME_VARIABLE, GOOD_HOME)
    home = hostinfo.home_directory()
    assert home is not None
    assert home.absolute
    assert home.text == GOOD_HOME


def test_unset_or_empty_home_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(HOME_VARIABLE, raising=False)
    assert hostinfo.home_directory() is None
    monkeypatch.setenv(HOME_VARIABLE, "")
    assert hostinfo.home_directory() is None


@pytest.mark.parametrize("hostile", HOSTILE_HOMES)
def test_a_hostile_home_value_is_not_used(monkeypatch: pytest.MonkeyPatch, hostile: str) -> None:
    monkeypatch.setenv(HOME_VARIABLE, hostile)
    assert hostinfo.home_directory() is None


def test_host_label_is_the_machine_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("fim.platform.hostinfo.platform.node", lambda: "lab-01")
    assert hostinfo.default_host_label() == "lab-01"


@pytest.mark.parametrize("name", ["", "x" * 129, "bad\x1bname", "bad\u202ename"])
def test_an_unusable_machine_name_gives_the_placeholder(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    monkeypatch.setattr("fim.platform.hostinfo.platform.node", lambda: name)
    assert hostinfo.default_host_label() == hostinfo.UNKNOWN_HOST


def test_the_real_host_label_is_always_usable() -> None:
    label = hostinfo.default_host_label()
    assert 1 <= len(label) <= 128
