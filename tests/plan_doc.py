"""Read sections of PLAN.md so drift tests can compare documented values with the code."""

from __future__ import annotations

import re

from conftest import REPO_ROOT

PLAN_PATH = REPO_ROOT / "PLAN.md"

_UNITS = {"KiB": 1024, "MiB": 1024**2, "GiB": 1024**3}
_QUANTITY = re.compile(r"(\d[\d ]*)\s*(KiB|MiB|GiB|s)?")


def plan_text() -> str:
    return PLAN_PATH.read_text(encoding="utf-8")


def section(heading_prefix: str) -> str:
    """The text of the PLAN.md section whose heading starts with ``heading_prefix``.

    The section ends at the next heading of the same or a higher level.
    """
    lines = plan_text().splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith(heading_prefix)), None)
    if start is None:
        raise LookupError(f"no PLAN.md heading starts with {heading_prefix!r}")
    level = len(lines[start]) - len(lines[start].lstrip("#"))
    body: list[str] = []
    for line in lines[start + 1 :]:
        stripped = line.lstrip("#")
        hashes = len(line) - len(stripped)
        if 0 < hashes <= level and stripped.startswith(" "):
            break
        body.append(line)
    return "\n".join(body)


def parse_quantity(text: str) -> int:
    """'200 000' -> 200000, '256 MiB' -> 268435456, '86 400 s' -> 86400."""
    match = _QUANTITY.fullmatch(text.strip())
    if match is None:
        raise ValueError(f"not a quantity: {text!r}")
    number = int(match.group(1).replace(" ", ""))
    return number * _UNITS.get(match.group(2) or "", 1)
