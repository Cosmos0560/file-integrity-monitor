"""services/config.py: a strict loader. Every invalid shape is refused with a clear message."""

from __future__ import annotations

import sys
import textwrap
from typing import Any

import pytest

from fim.core.errors import ConfigError
from fim.core.limits import DEFAULT_LIMITS, KIB, MAX_CONFIG_BYTES_CEILING
from fim.core.models import Severity, SymlinkPolicy
from fim.core.pathrules import Flavour, validate_user_path
from fim.core.policy import digest_is_valid
from fim.services import config as config_module
from fim.services.config import Config, load_config

POSIX = Flavour.POSIX
WINDOWS = Flavour.WINDOWS
HOME = validate_user_path("/home/lab", POSIX)
WIN_HOME = validate_user_path("C:\\Users\\lab", WINDOWS)


def load(text: str, *, flavour: Flavour = POSIX, home: Any = HOME) -> Config:
    return load_config(textwrap.dedent(text).encode("utf-8"), flavour=flavour, home=home)


def refuse(text: str, message: str, **kwargs: Any) -> ConfigError:
    with pytest.raises(ConfigError, match=message) as raised:
        load(text, **kwargs)
    return raised.value


MINIMAL = 'version: 1\npaths:\n  - path: "/srv/data"\n'

# ---- valid configurations ------------------------------------------------------------------------


def test_a_minimal_configuration_gets_the_documented_defaults() -> None:
    config = load(MINIMAL)
    policy = config.policy
    assert len(policy.roots) == 1
    root = policy.roots[0]
    assert root.path.text == "/srv/data"
    assert root.severity is Severity.MEDIUM
    assert root.one_file_system is True
    assert (root.include, root.exclude) == ((), ())
    assert policy.exclude == ()
    assert policy.symlinks is SymlinkPolicy.NEVER
    assert policy.limits == DEFAULT_LIMITS
    assert config.host_label is None
    assert config.key_file is None
    assert digest_is_valid(policy)


def test_the_example_from_the_plan_loads() -> None:
    config = load(
        """\
        version: 1
        host_label: "lab-01"
        key_file: "~/.config/fim/fim.key"
        symlinks: never
        one_file_system: true
        exclude: ["*.tmp", "**/__pycache__/**"]
        paths:
          - path: "/etc"
            severity: high
            exclude: ["mtab"]
          - path: "/home/lab/bin"
            severity: critical
            include: ["*"]
        limits:
          max_files: 100000
        """
    )
    policy = config.policy
    assert config.host_label == "lab-01"
    assert config.key_file is not None
    assert config.key_file.text == "/home/lab/.config/fim/fim.key"
    assert policy.exclude == ("*.tmp", "**/__pycache__/**")
    assert [root.path.text for root in policy.roots] == ["/etc", "/home/lab/bin"]
    assert [root.severity for root in policy.roots] == [Severity.HIGH, Severity.CRITICAL]
    assert policy.roots[0].exclude == ("mtab",)
    assert policy.roots[1].include == ("*",)
    assert policy.limits.max_files == 100_000
    assert policy.limits.max_depth == DEFAULT_LIMITS.max_depth


def test_a_tilde_root_is_expanded_with_the_given_home() -> None:
    config = load('version: 1\npaths:\n  - path: "~/notes"\n')
    assert config.policy.roots[0].path.text == "/home/lab/notes"


def test_a_windows_configuration() -> None:
    config = load(
        """\
        version: 1
        key_file: 'D:\\keys\\fim.key'
        symlinks: files
        paths:
          - path: 'C:\\Users\\lab\\Documents'
          - path: "~"
            severity: low
        """,
        flavour=WINDOWS,
        home=WIN_HOME,
    )
    roots = config.policy.roots
    assert roots[0].path.display() == "C:\\Users\\lab\\Documents"
    assert roots[1].path.text == "C:\\Users\\lab"
    assert config.policy.symlinks is SymlinkPolicy.FILES
    assert config.key_file is not None
    assert config.key_file.drive == "D:"


def test_global_one_file_system_is_the_default_for_roots_and_a_root_can_override() -> None:
    config = load(
        """\
        version: 1
        one_file_system: false
        paths:
          - path: "/a"
          - path: "/b"
            one_file_system: true
        """
    )
    assert [root.one_file_system for root in config.policy.roots] == [False, True]


def test_only_the_lower_case_severity_names_are_accepted() -> None:
    for label in ("info", "low", "medium", "high", "critical"):
        config = load(f'version: 1\npaths:\n  - path: "/a"\n    severity: {label}\n')
        assert config.policy.roots[0].severity.label == label


def test_limits_can_be_lowered_and_raised_up_to_the_ceiling() -> None:
    config = load(MINIMAL + "limits:\n  max_files: 10\n  max_depth: 128\n")
    assert config.policy.limits.max_files == 10
    assert config.policy.limits.max_depth == 128


def test_an_empty_limits_section_means_the_defaults() -> None:
    assert load(MINIMAL + "limits:\n").policy.limits == DEFAULT_LIMITS


def test_comments_key_order_and_quoting_do_not_change_the_policy_digest() -> None:
    first = load(
        """\
        # a comment
        version: 1
        exclude: ["*.tmp"]
        paths:
          - path: "/srv/data"
            severity: high
        """
    )
    second = load(
        """\
        paths:
          - severity: 'high'
            path: '/srv/data'   # trailing comment
        exclude:
          - '*.tmp'
        version: 1
        """
    )
    assert first.policy.digest == second.policy.digest


def test_a_changed_exclude_changes_the_policy_digest() -> None:
    first = load(MINIMAL)
    second = load(MINIMAL + 'exclude: ["*.log"]\n')
    assert first.policy.digest != second.policy.digest


def test_the_host_label_may_contain_ordinary_non_ascii_text() -> None:
    label = "lab-" + chr(0xE9)
    config = load(f'version: 1\nhost_label: "{label}"\npaths:\n  - path: "/a"\n')
    assert config.host_label == label


# ---- size, encoding and invisible characters -----------------------------------------------------


def test_the_input_must_be_bytes() -> None:
    with pytest.raises(ConfigError, match="bytes"):
        load_config(MINIMAL, flavour=POSIX)  # type: ignore[arg-type]  # str is the mistake under test


def test_an_oversize_configuration_is_refused_before_it_is_parsed() -> None:
    big = b"version: 1\n#" + b"x" * (MAX_CONFIG_BYTES_CEILING)
    with pytest.raises(ConfigError, match="larger than 262144 bytes"):
        load_config(big, flavour=POSIX)


# Slow: parsing a 256 KiB comment character by character in pure Python takes about 0.6 s.
@pytest.mark.slow
def test_a_configuration_exactly_at_the_size_limit_is_accepted() -> None:
    just_fits = b"version: 1\npaths:\n  - path: '/a'\n#" + b"x" * (MAX_CONFIG_BYTES_CEILING - 60)
    assert load_config(just_fits, flavour=POSIX).policy.roots


def test_the_configuration_may_lower_its_own_size_limit() -> None:
    text = MINIMAL + "limits:\n  max_config_bytes: 64\n" + "# padding to pass the limit\n" * 4
    refuse(text, "larger than 64 bytes")


def test_invalid_utf8_is_refused() -> None:
    with pytest.raises(ConfigError, match="UTF-8"):
        load_config(b"version: 1\n\xff\xfe\n", flavour=POSIX)


@pytest.mark.parametrize(
    ("char", "code"),
    [
        ("\x1b", "001B"),
        ("\x00", "0000"),
        (chr(0x202E), "202E"),
        (chr(0x200B), "200B"),
        (chr(0xFEFF), "FEFF"),
        (chr(0x00A0), "00A0"),
        (chr(0x2028), "2028"),
    ],
)
def test_invisible_and_control_characters_are_refused_with_their_line(char: str, code: str) -> None:
    text = f'version: 1\npaths:\n  - path: "/a"\n# note {char} here\n'
    with pytest.raises(ConfigError, match=f"line 4 .*U\\+{code}") as raised:
        load_config(text.encode("utf-8"), flavour=POSIX)
    assert char not in str(raised.value)


def test_ordinary_whitespace_controls_are_fine() -> None:
    text = "version: 1\r\npaths:\r\n  - path: '/a'\r\n# a tab\there\r\n"
    assert load_config(text.encode("utf-8"), flavour=POSIX).policy.roots


# ---- document shape ------------------------------------------------------------------------------


@pytest.mark.parametrize("text", ["", "   \n", "# only a comment\n", "---\n", "~\n", "null\n"])
def test_an_empty_document_is_refused(text: str) -> None:
    refuse(text, "empty")


@pytest.mark.parametrize("text", ["- a\n- b\n", "just text\n", "42\n", "true\n"])
def test_the_top_level_must_be_a_mapping(text: str) -> None:
    refuse(text, "must be a mapping")


def test_more_than_one_document_is_refused() -> None:
    refuse("version: 1\n---\nversion: 2\n", "invalid YAML")


@pytest.mark.parametrize(
    "text",
    [
        "version: 1\npaths: [\n",
        "version: 1\npaths:\n\t- path: '/a'\n",
        "version: 1: 2\n",
        "{unclosed: \n",
        "a: 'unterminated\n",
    ],
)
def test_yaml_syntax_errors_are_config_errors(text: str) -> None:
    refuse(text, r"invalid YAML \(line \d+\)")


def test_unknown_top_level_keys_are_refused() -> None:
    refuse(MINIMAL + "colour: red\n", "unknown key 'colour' in the configuration")


def test_unknown_path_keys_are_refused() -> None:
    refuse(
        'version: 1\npaths:\n  - path: "/a"\n    sevrity: high\n',
        r"unknown key 'sevrity' in paths\[0\]",
    )


@pytest.mark.parametrize("version", ["", "version: 2\n", "version: '1'\n", "version: true\n"])
def test_version_must_be_exactly_the_number_one(version: str) -> None:
    refuse(version + 'paths:\n  - path: "/a"\n', "version must be the number 1")


def test_a_float_one_is_not_version_one() -> None:
    refuse('version: 1.0\npaths:\n  - path: "/a"\n', "version must be the number 1")


@pytest.mark.parametrize(
    "paths",
    ["", "paths:\n", "paths: []\n", "paths: /a\n", "paths:\n  key: value\n"],
)
def test_paths_must_be_a_non_empty_list(paths: str) -> None:
    refuse("version: 1\n" + paths, "paths must list at least one")


@pytest.mark.parametrize("entry", ["- /a", "- 5", "- [a]", "- ~"])
def test_a_path_entry_must_be_a_mapping(entry: str) -> None:
    refuse(f"version: 1\npaths:\n  {entry}\n", r"paths\[0\] must be a mapping")


def test_a_path_entry_needs_a_path() -> None:
    refuse("version: 1\npaths:\n  - severity: high\n", r"paths\[0\] needs a 'path'")


# ---- YAML 1.1 surprises: text expected, something else read --------------------------------------


@pytest.mark.parametrize(
    ("value", "found"),
    [
        ("yes", "bool"),
        ("0755", "int"),
        ("1.5", "float"),
        ("2024-01-01", "date"),
        ("null", "nothing"),
    ],
)
def test_a_value_yaml_turned_into_something_else_is_refused_with_a_quote_hint(
    value: str, found: str
) -> None:
    error = refuse(f"version: 1\npaths:\n  - path: {value}\n", r"paths\[0\]\.path must be text")
    assert found in str(error)
    assert "quotes" in str(error)


def test_host_label_that_is_a_number_is_refused() -> None:
    refuse(MINIMAL + "host_label: 12\n", "host_label must be text, found a int")


# ---- paths ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("relative/dir", "absolute"),
        ("../up", r"\.\."),
        ("/a/../b", r"\.\."),
        ("file:///etc", "URL"),
        ("http://x/y", "URL"),
        ("C:\\Users", "Windows drive"),
        ("~other/x", "~user"),
        ("", "empty"),
    ],
)
def test_bad_root_paths_are_refused(raw: str, message: str) -> None:
    refuse(f"version: 1\npaths:\n  - path: '{raw}'\n", message)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("\\\\server\\share", "UNC"),
        ("\\\\?\\C:\\x", "device"),
        ("\\\\.\\COM1", "device"),
        ("C:foo", "drive-relative"),
        ("\\rooted", "current drive"),
        ("C:\\dir\\CON", "reserved"),
        ("C:\\a:stream", "alternate"),
        ("relative", "absolute"),
    ],
)
def test_bad_windows_root_paths_are_refused(raw: str, message: str) -> None:
    refuse(
        f"version: 1\npaths:\n  - path: '{raw}'\n",
        message,
        flavour=WINDOWS,
        home=WIN_HOME,
    )


def test_a_tilde_without_a_known_home_is_refused() -> None:
    refuse('version: 1\npaths:\n  - path: "~/x"\n', "home directory is unknown", home=None)


def test_a_root_longer_than_the_path_limit_is_refused() -> None:
    refuse(
        'version: 1\npaths:\n  - path: "/' + "a" * 50 + '"\nlimits:\n  max_path_chars: 20\n',
        "longer than 20",
    )


def test_the_same_root_twice_is_refused() -> None:
    refuse('version: 1\npaths:\n  - path: "/a"\n  - path: "/a/"\n', "listed twice")


def test_nested_roots_are_allowed() -> None:
    config = load('version: 1\npaths:\n  - path: "/a"\n  - path: "/a/b"\n')
    assert len(config.policy.roots) == 2


def test_more_roots_than_the_limit_are_refused() -> None:
    refuse(
        'version: 1\npaths:\n  - path: "/a"\n  - path: "/b"\nlimits:\n  max_roots: 1\n',
        "more than 1 monitored",
    )


# ---- severity, patterns, symlinks, flags ---------------------------------------------------------


@pytest.mark.parametrize("severity", ["HIGH", "High", "urgent", "''", "' high'", "5", "true"])
def test_bad_severities_are_refused(severity: str) -> None:
    refuse(
        f'version: 1\npaths:\n  - path: "/a"\n    severity: {severity}\n',
        r"severity must be (one of|text)",
    )


@pytest.mark.parametrize(
    ("section", "message"),
    [
        ("exclude: '*.tmp'", "exclude must be a list"),
        ("exclude: [1]", r"exclude\[0\] must be text"),
        ("exclude: [[a]]", r"exclude\[0\] must be text"),
        ("exclude: ['[abc']", "unterminated"),
        ("exclude: ['/abs']", "leading"),
        ("exclude: ['a\\b']", "not an escape"),
        ("exclude: ['']", "empty"),
    ],
)
def test_bad_global_excludes_are_refused(section: str, message: str) -> None:
    refuse(MINIMAL + section + "\n", message)


@pytest.mark.parametrize("key", ["include", "exclude"])
def test_bad_root_patterns_are_refused(key: str) -> None:
    refuse(
        f'version: 1\npaths:\n  - path: "/a"\n    {key}: "x"\n',
        rf"paths\[0\]\.{key} must be a list",
    )
    refuse(
        f'version: 1\npaths:\n  - path: "/a"\n    {key}: ["x/"]\n',
        "trailing",
    )


def test_too_many_patterns_in_total_are_refused() -> None:
    refuse(MINIMAL + "exclude: [a, b, c]\nlimits:\n  max_patterns: 2\n", "more than 2")


def test_patterns_longer_than_the_limit_are_refused() -> None:
    refuse(MINIMAL + "exclude: ['abcdef']\nlimits:\n  max_pattern_chars: 5\n", "longer than 5")


@pytest.mark.parametrize("value", ["all", "follow", "''", "yes", "1"])
def test_symlink_policy_is_never_or_files(value: str) -> None:
    refuse(MINIMAL + f"symlinks: {value}\n", r"symlinks must be|symlinks must be text")


@pytest.mark.parametrize("value", ["'true'", "1", "maybe", "null"])
def test_flags_must_be_real_booleans(value: str) -> None:
    refuse(MINIMAL + f"one_file_system: {value}\n", "one_file_system must be true or false")
    refuse(
        f'version: 1\npaths:\n  - path: "/a"\n    one_file_system: {value}\n',
        r"paths\[0\]\.one_file_system must be true or false",
    )


# ---- limits --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("section", "message"),
    [
        ("max_files: 1000001", "above its hard ceiling"),
        ("max_depth: 129", "above its hard ceiling"),
        ("max_hash_file_bytes: 4294967297", "above its hard ceiling"),
        ("max_run_seconds: 3601", "above its hard ceiling"),
        ("max_files: 0", "at least 1"),
        ("max_files: -5", "at least 1"),
        ("max_files: true", "must be an integer"),
        ("max_files: '10'", "must be an integer"),
        ("max_files: 1.5", "must be an integer"),
        ("max_colour: 3", "unknown limit"),
    ],
)
def test_limits_outside_what_is_allowed_are_refused(section: str, message: str) -> None:
    refuse(MINIMAL + f"limits:\n  {section}\n", message)


def test_limits_must_be_a_mapping() -> None:
    refuse(MINIMAL + "limits: 5\n", "limits must be a mapping")


# ---- key file ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key_file",
    ["/srv/data/fim.key", "/srv/data/deeper/fim.key", "/srv/data"],
)
def test_a_key_file_inside_a_monitored_root_is_refused(key_file: str) -> None:
    refuse(MINIMAL + f'key_file: "{key_file}"\n', "key_file must not be inside a monitored path")


def test_a_key_file_inside_a_nested_root_is_refused() -> None:
    refuse(
        'version: 1\nkey_file: "/a/b/k"\npaths:\n  - path: "/x"\n  - path: "/a/b"\n',
        "key_file must not be inside",
    )


def test_a_key_file_next_to_a_root_is_fine() -> None:
    config = load(MINIMAL + 'key_file: "/srv/data2/fim.key"\n')
    assert config.key_file is not None
    assert config.key_file.text == "/srv/data2/fim.key"


def test_a_key_file_in_a_windows_root_is_refused_regardless_of_case() -> None:
    refuse(
        "version: 1\nkey_file: 'c:\\DATA\\k.key'\npaths:\n  - path: 'C:\\data'\n",
        "key_file must not be inside",
        flavour=WINDOWS,
        home=WIN_HOME,
    )


def test_a_relative_key_file_is_refused() -> None:
    refuse(MINIMAL + 'key_file: "fim.key"\n', "key_file: .*absolute")


def test_a_key_file_that_is_not_text_is_refused() -> None:
    refuse(MINIMAL + "key_file: 5\n", "key_file must be text")


def test_a_key_file_with_a_tilde_needs_a_home() -> None:
    refuse(MINIMAL + 'key_file: "~/fim.key"\n', "home directory is unknown", home=None)


# ---- host label ----------------------------------------------------------------------------------


def test_a_host_label_must_be_short_and_visible() -> None:
    refuse(MINIMAL + 'host_label: ""\n', "host_label must be 1 to 128")
    refuse(MINIMAL + f'host_label: "{"x" * 129}"\n', "host_label must be 1 to 128")
    refuse(MINIMAL + 'host_label: "a\\x1bb"\n', "host_label contains a control")
    refuse(MINIMAL + 'host_label: "a\\u202eb"\n', "host_label contains a control")
    assert load(MINIMAL + f'host_label: "{"x" * 128}"\n').host_label == "x" * 128


# ---- constructs the loader refuses ---------------------------------------------------------------


def test_aliases_are_refused_with_a_hint_about_quoting_stars() -> None:
    error = refuse("version: 1\npaths:\n  - *b\n", r"aliases .*not allowed \(line 3\)")
    assert "quote" in str(error)


def test_an_unquoted_glob_is_refused_with_a_hint_to_quote_it() -> None:
    error = refuse(MINIMAL + "exclude: [*.tmp]\n", r"invalid YAML \(line 4\)")
    assert "must be quoted" in str(error)
    error = refuse(MINIMAL + "exclude:\n  - *.tmp\n", r"invalid YAML \(line 5\)")
    assert "must be quoted" in str(error)


def test_anchors_are_refused() -> None:
    refuse("version: 1\npaths: &p\n  - path: '/a'\n", "anchors")


def test_expansion_bombs_never_get_far_enough_to_expand() -> None:
    bomb = (
        "a: &a [x, x, x, x, x, x, x, x, x]\n"
        "b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\n"
        "c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]\n"
    )
    refuse("version: 1\n" + bomb, "anchors")


@pytest.mark.parametrize(
    "text",
    [
        "version: !!int 1\n",
        "version: 1\npaths: !!python/list []\n",
        "version: 1\nx: !!python/object/apply:os.system ['echo hi']\n",
        "version: 1\nx: !custom {a: 1}\n",
        "version: 1\nx: !!str 12\n",
    ],
)
def test_explicit_tags_are_refused(text: str) -> None:
    refuse(text, "tags")


def test_merge_keys_are_refused() -> None:
    refuse("version: 1\nx:\n  <<: {a: 1}\n", "merge keys")


@pytest.mark.parametrize(
    "text",
    [
        "version: 1\nversion: 1\n",
        'version: 1\npaths:\n  - path: "/a"\n    path: "/b"\n',
        "version: 1\nlimits:\n  max_files: 1\n  max_files: 2\n",
    ],
)
def test_duplicate_keys_are_refused(text: str) -> None:
    refuse(text, "duplicate key")


@pytest.mark.parametrize(
    "text",
    ["1: a\n", "true: a\n", "null: a\n", "2024-01-01: a\n"],
)
def test_keys_that_are_not_text_are_refused(text: str) -> None:
    refuse(text, "must be text, YAML read")


def test_complex_keys_are_refused() -> None:
    refuse("? [a, b]\n: value\n", "plain text")
    refuse("? {a: 1}\n: value\n", "plain text")


# 2500 levels is already past twice Python's recursion limit, which is what a crash needs; the
# 20000-level document costs seconds in the pure-Python YAML scanner, so it runs only in --full.
@pytest.mark.parametrize(
    "depth",
    [pytest.param(2500, id="default"), pytest.param(20000, id="full", marks=pytest.mark.slow)],
)
def test_absurd_nesting_is_a_config_error_not_a_crash(depth: int) -> None:
    assert depth > 2 * sys.getrecursionlimit()
    text = "a: " + "[" * depth + "]" * depth + "\n"
    refuse(text, "nested too deeply|invalid YAML")


def test_hostile_key_names_never_reach_the_message_raw() -> None:
    error = refuse('"bad\\x1b[31m": 1\n', "unknown key")
    assert "\x1b" not in str(error)
    error = refuse('version: 1\n"bad\\u202ekey": 1\n', "unknown key")
    assert chr(0x202E) not in str(error)


def test_the_module_exports() -> None:
    assert set(config_module.__all__) == {"Config", "load_config"}


def test_the_size_limit_is_the_documented_one() -> None:
    assert DEFAULT_LIMITS.max_config_bytes == 256 * KIB
