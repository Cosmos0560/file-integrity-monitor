"""Facts about the machine the tool runs on: path flavour, home directory, host label.

Platform code collects the raw facts (environment variables, the platform name); the rules for
what is acceptable are in core/pathrules.py. Nothing here touches the filesystem.
"""

from __future__ import annotations

import os
import platform
import sys

from fim.core.errors import PathRuleError
from fim.core.pathrules import Flavour, UserPath, validate_user_path
from fim.core.sanitize import first_unsafe

__all__ = ["default_host_label", "home_directory", "path_flavour", "platform_name"]

UNKNOWN_HOST = "unknown-host"
_MAX_HOST_CHARS = 128


def path_flavour() -> Flavour:
    """Which operating system's path rules apply here."""
    return Flavour.WINDOWS if sys.platform == "win32" else Flavour.POSIX


def platform_name() -> str:
    """The platform label stored in a baseline (``sys.platform``, for example ``win32``)."""
    return sys.platform


def home_directory() -> UserPath | None:
    """The user's home directory from the environment, or None if it is unset or not usable.

    ``HOME`` on POSIX, ``USERPROFILE`` on Windows. The value is checked with the same rules as
    any other path, so a hostile environment cannot smuggle in a device or UNC path.
    """
    flavour = path_flavour()
    raw = os.environ.get("USERPROFILE" if flavour is Flavour.WINDOWS else "HOME")
    if not raw:
        return None
    try:
        return validate_user_path(raw, flavour, require_absolute=True)
    except PathRuleError:
        return None


def default_host_label() -> str:
    """The machine's name, or ``unknown-host`` if it is empty, too long or has odd characters."""
    name = platform.node()
    if not name or len(name) > _MAX_HOST_CHARS or first_unsafe(name) is not None:
        return UNKNOWN_HOST
    return name
