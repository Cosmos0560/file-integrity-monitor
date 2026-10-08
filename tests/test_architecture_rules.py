"""Architecture checker usage rules: each rule trips on a planted violation.

Every table row writes one module into a throwaway tree and says which rule must fire (or that
the tree must be clean). The "allowed" tables matter as much: a rule that fires on legitimate
code gets switched off by whoever has to ship.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from arch_helpers import check, rules

SERVICE = "services/scanner.py"
CORE = "core/models.py"
OBSERVE = "fs/observe.py"
SAFE_FILES = "fs/safe_files.py"
SANDBOX = "fs/sandbox.py"
CLOCK = "platform/clock.py"
CONFIG = "services/config.py"
CLI = "cli/main.py"


def fired(tmp_path: Path, module: str, source: str) -> list[str]:
    return rules(check(tmp_path, {module: source}))


def assert_trips(tmp_path: Path, module: str, source: str, rule: str) -> None:
    found = fired(tmp_path, module, source)
    assert rule in found, f"{rule} did not fire for {module}: {source!r} (got {found})"


# ---- A006: filesystem default-deny ----------------------------------------------------------

A006_CASES = [
    pytest.param("import pathlib\n", id="import-pathlib"),
    pytest.param("from pathlib import Path\n", id="from-pathlib"),
    pytest.param("import shutil\n", id="shutil"),
    pytest.param("import tempfile\n", id="tempfile"),
    pytest.param("import glob\n", id="glob"),
    pytest.param("import zipfile\n", id="zipfile"),
    pytest.param("import gzip\n", id="gzip"),
    pytest.param("import sqlite3\n", id="sqlite3"),
    pytest.param("def f():\n    return open('x')\n", id="builtin-open"),
    pytest.param("def f(p):\n    return p.open()\n", id="method-open"),
    pytest.param("import os\nos.listdir('.')\n", id="os-listdir"),
    pytest.param("import os\nos.scandir('.')\n", id="os-scandir"),
    pytest.param("import os\nos.stat('x')\n", id="os-stat"),
    pytest.param("import os\nos.walk('.')\n", id="os-walk"),
    pytest.param("import os\nos.open('x', 0)\n", id="os-open"),
    pytest.param("import os\ndef f():\n    os.unlink('x')\n", id="os-unlink-in-function"),
    pytest.param("from os import scandir\n", id="from-os-scandir"),
    pytest.param("from os import remove as rm\nrm('x')\n", id="from-os-aliased"),
    pytest.param("import os as o\no.remove('x')\n", id="os-aliased"),
    pytest.param("import os\nos.path.exists('x')\n", id="os-path-exists"),
    pytest.param("import os\nos.path.isfile('x')\n", id="os-path-isfile"),
    pytest.param("from os.path import isdir\n", id="from-os-path-isdir"),
    pytest.param("from os import path\npath.getsize('x')\n", id="os-path-via-from"),
    pytest.param("import io\nio.open('x')\n", id="io-open"),
    pytest.param("import io\nio.FileIO('x')\n", id="io-fileio"),
    pytest.param("from io import open\n", id="from-io-open"),
    pytest.param("import os\ngetattr(os, 'remove')('x')\n", id="getattr-os-const"),
    pytest.param("import os\ndef f(n):\n    return getattr(os, n)\n", id="getattr-os-dynamic"),
]


@pytest.mark.parametrize("source", A006_CASES)
def test_a006_filesystem_api_outside_fs(tmp_path: Path, source: str) -> None:
    assert_trips(tmp_path, SERVICE, source, "A006")


A006_ALLOWED = [
    pytest.param(
        "import os\n"
        "a = os.environ.get('A')\n"
        "b = os.fspath('x')\n"
        "c = os.path.join('a', 'b')\n"
        "d = os.sep\n"
        "e = os.path.basename('a/b')\n"
        "f = os.path.expanduser('~')\n"
        "g = os.strerror(2)\n",
        id="os-pure-parts",
    ),
    pytest.param("import io\nio.StringIO()\n", id="io-stringio"),
    pytest.param("from os.path import join, basename, normpath\n", id="os-path-pure-import"),
    pytest.param("import os\nx = getattr(os, 'environ')\n", id="getattr-safe-name"),
    pytest.param(
        "# open('x') and os.remove(y) in a comment\ntext = 'import os; os.remove(x); open(y)'\n",
        id="comments-and-strings",
    ),
]


@pytest.mark.parametrize("source", A006_ALLOWED)
def test_a006_pure_os_and_io_use_is_allowed(tmp_path: Path, source: str) -> None:
    assert fired(tmp_path, SERVICE, source) == []


@pytest.mark.parametrize("module", [SAFE_FILES, SANDBOX])
def test_fs_modules_may_use_the_filesystem(tmp_path: Path, module: str) -> None:
    source = (
        "import os\nimport pathlib\nimport shutil\nimport tempfile\n"
        "open('x')\nos.remove('x')\nos.path.exists('x')\nos.replace('a', 'b')\n"
        "pathlib.Path('x').write_text('y')\n"
    )
    assert fired(tmp_path, module, source) == []


# ---- A007: observe.py is read-only ----------------------------------------------------------

A007_CASES = [
    pytest.param("import os\nos.remove('x')\n", id="os-remove"),
    pytest.param("import os\nos.unlink('x')\n", id="os-unlink"),
    pytest.param("import os\nos.rename('a', 'b')\n", id="os-rename"),
    pytest.param("import os\nos.replace('a', 'b')\n", id="os-replace"),
    pytest.param("import os\nos.mkdir('x')\n", id="os-mkdir"),
    pytest.param("import os\nos.makedirs('x')\n", id="os-makedirs"),
    pytest.param("import os\nos.rmdir('x')\n", id="os-rmdir"),
    pytest.param("import os\nos.chmod('x', 0o600)\n", id="os-chmod"),
    pytest.param("import os\nos.utime('x')\n", id="os-utime"),
    pytest.param("import os\nos.truncate('x', 0)\n", id="os-truncate"),
    pytest.param("import os\nos.symlink('a', 'b')\n", id="os-symlink"),
    pytest.param("import os\nos.write(1, b'x')\n", id="os-write"),
    pytest.param("import os\nos.fsync(1)\n", id="os-fsync"),
    pytest.param("import os\nflags = os.O_WRONLY\n", id="flag-wronly"),
    pytest.param("import os\nflags = os.O_RDONLY | os.O_RDWR\n", id="flag-rdwr"),
    pytest.param("import os\nflags = os.O_RDONLY | os.O_CREAT\n", id="flag-creat"),
    pytest.param("import os\nflags = os.O_APPEND\n", id="flag-append"),
    pytest.param("import os\nflags = os.O_TRUNC\n", id="flag-trunc"),
    pytest.param("import os\nflags = os.O_EXCL\n", id="flag-excl"),
    pytest.param("import os\nflags = os.O_TMPFILE\n", id="flag-tmpfile-not-on-read-list"),
    pytest.param("from os import O_WRONLY\n", id="from-os-flag"),
    pytest.param("from os import remove\n", id="from-os-remove"),
    pytest.param("import os as o\no.remove('x')\n", id="aliased-remove"),
    pytest.param("import os\nos.open('x', 1)\n", id="literal-open-flags"),
    pytest.param("import os\nos.open('x', flags=577)\n", id="literal-open-flags-keyword"),
    pytest.param("import os\nos.open('x', os.O_RDONLY | 0o1)\n", id="literal-mixed-into-flags"),
    pytest.param("import os\nos.open('x')\n", id="open-without-flags"),
    pytest.param("def f():\n    return open('x')\n", id="builtin-open"),
    pytest.param("import shutil\n", id="shutil"),
    pytest.param("import tempfile\n", id="tempfile"),
    pytest.param("import os\ngetattr(os, 'remove')('x')\n", id="getattr-write-api"),
    pytest.param("import os\ndef f(n):\n    return getattr(os, n)\n", id="getattr-dynamic"),
    pytest.param("import os\ngetattr(os, 'O_CREAT', 0)\n", id="getattr-write-flag"),
    pytest.param("import pathlib\npathlib.Path('x').write_text('y')\n", id="pathlib-write-text"),
    pytest.param("def f(p):\n    p.write_bytes(b'')\n", id="method-write-bytes"),
    pytest.param("def f(p):\n    p.touch()\n", id="method-touch"),
    pytest.param("def f(p):\n    p.unlink()\n", id="method-unlink"),
    pytest.param("def f(h):\n    h.write(b'x')\n", id="method-write"),
]


@pytest.mark.parametrize("source", A007_CASES)
def test_a007_write_or_mutate_api_in_observe(tmp_path: Path, source: str) -> None:
    assert_trips(tmp_path, OBSERVE, source, "A007")


def test_observe_may_read_with_read_only_flags(tmp_path: Path) -> None:
    source = (
        "import os\n"
        "import stat\n"
        "flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC\n"
        "flags |= getattr(os, 'O_NOATIME', 0)\n"
        "flags |= getattr(os, 'O_BINARY', 0)\n"
        "fd = os.open('x', flags)\n"
        "info = os.fstat(fd)\n"
        "os.lstat('x')\n"
        "os.scandir('.')\n"
        "os.read(fd, 1)\n"
        "os.close(fd)\n"
        "os.path.join('a', 'b')\n"
        "stat.S_ISREG(info.st_mode)\n"
    )
    assert fired(tmp_path, OBSERVE, source) == []


def test_the_same_write_apis_are_fine_in_safe_files(tmp_path: Path) -> None:
    source = "import os\nos.rename('a', 'b')\nflags = os.O_WRONLY | os.O_CREAT | os.O_EXCL\n"
    assert fired(tmp_path, SAFE_FILES, source) == []


# ---- A008: clocks ---------------------------------------------------------------------------

A008_CASES = [
    pytest.param("import time\n", id="import-time"),
    pytest.param("from time import sleep\n", id="from-time-sleep"),
    pytest.param("import time as t\nt.sleep(1)\n", id="time-aliased"),
    pytest.param("import datetime\ndatetime.datetime.now()\n", id="datetime-now"),
    pytest.param("import datetime\ndatetime.datetime.utcnow()\n", id="datetime-utcnow"),
    pytest.param("import datetime\ndatetime.datetime.today()\n", id="datetime-today"),
    pytest.param("import datetime\ndatetime.date.today()\n", id="date-today"),
    pytest.param("from datetime import datetime\ndatetime.now()\n", id="from-datetime-now"),
    pytest.param("from datetime import datetime as dt\ndt.now()\n", id="aliased-now"),
    pytest.param("from datetime import date\ndate.today()\n", id="from-date-today"),
]


@pytest.mark.parametrize("source", A008_CASES)
def test_a008_clock_access_outside_platform_clock(tmp_path: Path, source: str) -> None:
    assert_trips(tmp_path, SERVICE, source, "A008")


def test_a008_applies_to_core_too(tmp_path: Path) -> None:
    assert_trips(tmp_path, "core/clock.py", "import time\n", "A008")


def test_a008_platform_clock_may_read_the_clock(tmp_path: Path) -> None:
    source = (
        "import datetime\nimport time\n"
        "time.sleep(1)\ntime.monotonic()\ndatetime.datetime.now(datetime.UTC)\n"
    )
    assert fired(tmp_path, CLOCK, source) == []


def test_a008_injected_clock_and_pure_conversions_are_allowed(tmp_path: Path) -> None:
    source = (
        "from datetime import datetime, UTC\n"
        "def f(clock):\n"
        "    return clock.now()\n"
        "def g(seconds):\n"
        "    return datetime.fromtimestamp(seconds, UTC)\n"
    )
    assert fired(tmp_path, SERVICE, source) == []


# ---- A009: third-party imports --------------------------------------------------------------

A009_CASES = [
    pytest.param(SERVICE, "import requests\n", id="requests"),
    pytest.param(SERVICE, "import numpy as np\n", id="numpy"),
    pytest.param(SERVICE, "import yaml\n", id="yaml-outside-config"),
    pytest.param(SERVICE, "from yaml import safe_load\n", id="from-yaml-outside-config"),
    pytest.param("app/check.py", "import yaml\n", id="yaml-in-app"),
    pytest.param(CORE, "import yaml\n", id="yaml-in-core"),
    pytest.param(CLI, "import click\n", id="click-in-cli"),
]


@pytest.mark.parametrize(("module", "source"), A009_CASES)
def test_a009_third_party_import_not_allowed(tmp_path: Path, module: str, source: str) -> None:
    assert_trips(tmp_path, module, source, "A009")


def test_a009_yaml_is_allowed_in_the_config_loader_only(tmp_path: Path) -> None:
    source = "import yaml\nyaml.SafeLoader\nyaml.compose('')\n"
    assert fired(tmp_path, CONFIG, source) == []


def test_a009_stdlib_and_future_imports_are_allowed(tmp_path: Path) -> None:
    source = "from __future__ import annotations\nimport json\nimport hashlib\nimport hmac\n"
    assert fired(tmp_path, SERVICE, source) == []


# ---- A010: banned modules, builtins and APIs -------------------------------------------------

A010_CASES = [
    pytest.param(SERVICE, "import subprocess\n", id="subprocess"),
    pytest.param(SERVICE, "import socket\n", id="socket"),
    pytest.param(SERVICE, "import urllib.request\n", id="urllib-request"),
    pytest.param(SERVICE, "from urllib import parse\n", id="from-urllib"),
    pytest.param(SERVICE, "import http.client\n", id="http-client"),
    pytest.param(SERVICE, "import pickle\n", id="pickle"),
    pytest.param(SERVICE, "import marshal\n", id="marshal"),
    pytest.param(SERVICE, "import shelve\n", id="shelve"),
    pytest.param(SERVICE, "import random\n", id="random"),
    pytest.param(SERVICE, "import importlib\n", id="importlib"),
    pytest.param(SERVICE, "from importlib import import_module\n", id="from-importlib"),
    pytest.param(SERVICE, "import ctypes\n", id="ctypes"),
    pytest.param(SERVICE, "import builtins\n", id="builtins"),
    pytest.param(SERVICE, "eval('1')\n", id="eval"),
    pytest.param(SERVICE, "exec('x = 1')\n", id="exec"),
    pytest.param(SERVICE, "__import__('os')\n", id="dunder-import"),
    pytest.param(SERVICE, "from os import *\n", id="star-import"),
    pytest.param(SERVICE, "import sys\nsys.modules['x']\n", id="sys-modules"),
    pytest.param(SERVICE, "import os\nos.system('x')\n", id="os-system"),
    pytest.param(SAFE_FILES, "import os\nos.system('x')\n", id="os-system-even-in-fs"),
    pytest.param(SAFE_FILES, "import os\nos.kill(1, 9)\n", id="os-kill-even-in-fs"),
    pytest.param(SAFE_FILES, "import os\nos.popen('x')\n", id="os-popen-even-in-fs"),
    pytest.param(SAFE_FILES, "import os\nos.execv('x', [])\n", id="os-exec-even-in-fs"),
    pytest.param(SAFE_FILES, "import os\nos.fork()\n", id="os-fork-even-in-fs"),
    pytest.param(CONFIG, "import yaml\nyaml.load('', Loader=yaml.SafeLoader)\n", id="yaml-load"),
    pytest.param(CONFIG, "import yaml\nyaml.load_all('')\n", id="yaml-load-all"),
    pytest.param(CONFIG, "import yaml\nyaml.unsafe_load('')\n", id="yaml-unsafe-load"),
    pytest.param(CONFIG, "import yaml\nyaml.full_load('')\n", id="yaml-full-load"),
    pytest.param(CONFIG, "import yaml\nx = yaml.Loader\n", id="yaml-loader"),
    pytest.param(CONFIG, "import yaml\nx = yaml.UnsafeLoader\n", id="yaml-unsafe-loader"),
    pytest.param(CONFIG, "from yaml import load\n", id="from-yaml-load"),
    pytest.param(CONFIG, "import yaml as y\ny.load('', Loader=y.SafeLoader)\n", id="yaml-aliased"),
]


@pytest.mark.parametrize(("module", "source"), A010_CASES)
def test_a010_banned_module_builtin_or_api(tmp_path: Path, module: str, source: str) -> None:
    assert_trips(tmp_path, module, source, "A010")


def test_a010_safe_loader_subclass_is_allowed(tmp_path: Path) -> None:
    source = (
        "import yaml\n"
        "class Strict(yaml.SafeLoader):\n"
        "    pass\n"
        "def parse(text):\n"
        "    loader = Strict(text)\n"
        "    return loader.get_single_data()\n"
    )
    assert fired(tmp_path, CONFIG, source) == []


# ---- A011: assert ----------------------------------------------------------------------------


def test_a011_assert_statement(tmp_path: Path) -> None:
    assert_trips(tmp_path, SERVICE, "assert 1 == 1\n", "A011")


def test_a011_assert_inside_a_function(tmp_path: Path) -> None:
    assert_trips(tmp_path, CORE, "def f(x):\n    assert x, 'never'\n", "A011")


def test_explicit_raise_instead_of_assert_is_fine(tmp_path: Path) -> None:
    source = "def f(x):\n    if not x:\n        raise ValueError('bad')\n"
    assert fired(tmp_path, SERVICE, source) == []


# ---- A012: printing --------------------------------------------------------------------------

A012_CASES = [
    pytest.param("print('x')\n", id="print"),
    pytest.param("import sys\nsys.stdout.write('x')\n", id="stdout-write"),
    pytest.param("import sys\nsys.stderr.write('x')\n", id="stderr-write"),
    pytest.param("import sys\nprint('x', file=sys.stderr)\n", id="print-to-stderr"),
    pytest.param("from sys import stdout\nstdout.write('x')\n", id="from-sys-stdout"),
]


@pytest.mark.parametrize("source", A012_CASES)
def test_a012_printing_outside_cli(tmp_path: Path, source: str) -> None:
    assert_trips(tmp_path, "app/check.py", source, "A012")


def test_a012_cli_may_print(tmp_path: Path) -> None:
    source = "import sys\nprint('x')\nsys.stdout.write('y')\nsys.stderr.write('z')\n"
    assert fired(tmp_path, CLI, source) == []


# ---- A015: core purity -----------------------------------------------------------------------

A015_CASES = [
    pytest.param("import os\n", id="os"),
    pytest.param("import sys\n", id="sys"),
    pytest.param("from os import path\n", id="from-os"),
    pytest.param("import pathlib\n", id="pathlib"),
    pytest.param("from pathlib import Path\n", id="from-pathlib"),
    pytest.param("import shutil\n", id="shutil"),
    pytest.param("import tempfile\n", id="tempfile"),
    pytest.param("import glob\n", id="glob"),
    pytest.param("import os.path\n", id="os-path"),
]


@pytest.mark.parametrize("source", A015_CASES)
def test_a015_core_stays_pure(tmp_path: Path, source: str) -> None:
    assert_trips(tmp_path, CORE, source, "A015")


def test_core_may_use_pure_stdlib(tmp_path: Path) -> None:
    source = (
        "import enum\nimport io\nimport unicodedata\nimport re\n"
        "from dataclasses import dataclass\nfrom datetime import datetime\n"
    )
    assert fired(tmp_path, CORE, source) == []


# ---- reporting -------------------------------------------------------------------------------


def test_violations_carry_the_file_and_line(tmp_path: Path) -> None:
    violations = check(tmp_path, {SERVICE: "x = 1\n\nimport subprocess\n"})
    assert len(violations) == 1
    assert violations[0].rule == "A010"
    assert violations[0].line == 3
    assert violations[0].path.endswith("fim/services/scanner.py")


def test_two_violations_on_different_lines_are_both_reported(tmp_path: Path) -> None:
    violations = check(tmp_path, {SERVICE: "import subprocess\nimport socket\n"})
    assert [v.line for v in violations] == [1, 2]
