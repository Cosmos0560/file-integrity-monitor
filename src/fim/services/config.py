"""Configuration loading (PLAN.md section 1.6): YAML text in, a validated Config out.

This module takes the config *bytes*; reading the file is the job of fs/safe_files.py, so
nothing here touches the filesystem. It is the only importer of ``yaml``, and it never calls
``yaml.load``: a SafeLoader subclass that refuses what a configuration has no use for (aliases
and anchors, which allow expansion bombs; explicit tags; merge keys; duplicate keys; non-text
keys) is driven directly.

The schema is strict: unknown keys, wrong types and YAML 1.1 surprises (an unquoted ``yes`` or
``0755`` or ``2024-01-01`` where text is expected) are errors that say what was found and
where. Every message is scrubbed, so hostile text in the file cannot reach the terminal.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode

from fim.core.errors import ConfigError, PathRuleError
from fim.core.limits import DEFAULT_LIMITS, Limits
from fim.core.models import Policy, RootPolicy, Severity, SymlinkPolicy
from fim.core.pathrules import Flavour, UserPath, expand_tilde, is_within, validate_user_path
from fim.core.policy import build_policy
from fim.core.sanitize import clip_escaped, first_unsafe

__all__ = ["Config", "load_config"]

CONFIG_VERSION = 1
MAX_HOST_LABEL_CHARS = 128
_MERGE_TAG = "tag:yaml.org,2002:merge"
_MESSAGE_VALUE_CHARS = 60

_TOP_LEVEL_KEYS = frozenset(
    {
        "version",
        "host_label",
        "key_file",
        "symlinks",
        "one_file_system",
        "exclude",
        "paths",
        "limits",
    }
)
_PATH_KEYS = frozenset({"path", "severity", "include", "exclude", "one_file_system"})
_SEVERITY_BY_LABEL = {severity.label: severity for severity in Severity}
_SEVERITY_LABELS = ", ".join(_SEVERITY_BY_LABEL)


@dataclass(frozen=True, slots=True)
class Config:
    """A validated configuration. ``policy`` carries the roots, patterns, limits and digest."""

    policy: Policy
    host_label: str | None
    key_file: UserPath | None


# ---- the strict YAML loader ----------------------------------------------------------------------


def _line(mark: Any) -> str:
    return f" (line {mark.line + 1})" if mark is not None else ""


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that also refuses aliases, anchors, tags, merge keys and unusual keys."""

    def compose_node(self, parent: Node | None, index: int) -> Node | None:
        event = self.peek_event()  # type: ignore[no-untyped-call]  # types-PyYAML leaves it untyped
        mark = getattr(event, "start_mark", None)
        if isinstance(event, yaml.AliasEvent):
            raise ConfigError(
                f"YAML aliases ('*name') are not allowed{_line(mark)}; "
                "quote patterns that start with '*'"
            )
        if getattr(event, "anchor", None) is not None:
            raise ConfigError(f"YAML anchors ('&name') are not allowed{_line(mark)}")
        if getattr(event, "tag", None) is not None:
            raise ConfigError(f"YAML tags ('!tag') are not allowed{_line(mark)}")
        return super().compose_node(parent, index)

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[str] = set()
        for key_node, _value_node in node.value:
            if key_node.tag == _MERGE_TAG:
                raise ConfigError(
                    f"YAML merge keys ('<<') are not allowed{_line(key_node.start_mark)}"
                )
            if not isinstance(key_node, ScalarNode):
                raise ConfigError(f"a mapping key must be plain text{_line(key_node.start_mark)}")
            key = self.construct_object(key_node, deep=True)
            if not isinstance(key, str):
                raise ConfigError(
                    f"a mapping key must be text, YAML read a {type(key).__name__}"
                    f"{_line(key_node.start_mark)}; quote it"
                )
            if key in seen:
                raise ConfigError(
                    f"duplicate key '{clip_escaped(key, _MESSAGE_VALUE_CHARS)}'"
                    f"{_line(key_node.start_mark)}"
                )
            seen.add(key)
        return super().construct_mapping(node, deep)


def _parse_yaml(text: str) -> Any:
    loader = _StrictLoader(text)
    try:
        return loader.get_single_data()
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        problem = getattr(exc, "problem", None) or "syntax error"
        hint = ""
        if "alphabetic or numeric character" in problem:
            hint = " (a pattern that starts with '*' must be quoted)"
        raise ConfigError(f"invalid YAML{_line(mark)}: {problem}{hint}") from None
    except RecursionError:
        raise ConfigError("the configuration is nested too deeply") from None
    finally:
        loader.dispose()


# ---- schema checks -------------------------------------------------------------------------------


def _describe(value: object) -> str:
    return "nothing" if value is None else f"a {type(value).__name__}"


def _wrong_type(where: str, expected: str, value: object) -> ConfigError:
    hint = ""
    if not isinstance(value, str | list | dict):
        hint = "; YAML guessed a type, put the value in quotes if it is text"
    return ConfigError(f"{where} must be {expected}, found {_describe(value)}{hint}")


def _mapping(where: str, value: object, allowed: frozenset[str]) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise _wrong_type(where, "a mapping", value)
    for key in value:
        if key not in allowed:
            raise ConfigError(f"unknown key '{clip_escaped(key, _MESSAGE_VALUE_CHARS)}' in {where}")
    return value


def _text(where: str, value: object) -> str:
    if not isinstance(value, str):
        raise _wrong_type(where, "text", value)
    return value


def _flag(where: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise _wrong_type(where, "true or false", value)
    return value


def _text_list(where: str, value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise _wrong_type(where, "a list of text", value)
    return tuple(_text(f"{where}[{index}]", item) for index, item in enumerate(value))


def _user_path(
    where: str, raw: str, flavour: Flavour, home: UserPath | None, max_chars: int
) -> UserPath:
    try:
        path = validate_user_path(
            raw, flavour, require_absolute=True, allow_tilde=True, max_chars=max_chars
        )
        if path.tilde:
            if home is None:
                raise ConfigError(f"{where} starts with '~' but the home directory is unknown")
            path = expand_tilde(path, home)
    except PathRuleError as exc:
        raise ConfigError(f"{where}: {exc.message}") from None
    return path


def _limits(value: object) -> Limits:
    if value is None:
        return DEFAULT_LIMITS
    if not isinstance(value, dict):
        raise _wrong_type("limits", "a mapping", value)
    return DEFAULT_LIMITS.with_overrides(value)


def _severity(where: str, value: object) -> Severity:
    label = _text(where, value)
    if label not in _SEVERITY_BY_LABEL:  # exact, lower case: no 'HIGH', no ' high'
        raise ConfigError(f"{where} must be one of: {_SEVERITY_LABELS}")
    return _SEVERITY_BY_LABEL[label]


def _root(
    index: int,
    entry: object,
    flavour: Flavour,
    home: UserPath | None,
    default_one_file_system: bool,
    max_chars: int,
) -> RootPolicy:
    where = f"paths[{index}]"
    fields = _mapping(where, entry, _PATH_KEYS)
    if "path" not in fields:
        raise ConfigError(f"{where} needs a 'path'")
    path = _user_path(
        f"{where}.path", _text(f"{where}.path", fields["path"]), flavour, home, max_chars
    )
    return RootPolicy(
        path=path,
        severity=_severity(f"{where}.severity", fields["severity"])
        if "severity" in fields
        else Severity.MEDIUM,
        include=_text_list(f"{where}.include", fields["include"]) if "include" in fields else (),
        exclude=_text_list(f"{where}.exclude", fields["exclude"]) if "exclude" in fields else (),
        one_file_system=_flag(f"{where}.one_file_system", fields["one_file_system"])
        if "one_file_system" in fields
        else default_one_file_system,
    )


def _host_label(value: object) -> str:
    label = _text("host_label", value)
    if label == "" or len(label) > MAX_HOST_LABEL_CHARS:
        raise ConfigError(f"host_label must be 1 to {MAX_HOST_LABEL_CHARS} characters")
    if first_unsafe(label) is not None:
        raise ConfigError("host_label contains a control or invisible character")
    return label


def _decode(data: bytes) -> str:
    if not isinstance(data, bytes | bytearray):
        raise ConfigError("the configuration must be given as bytes")
    if len(data) > DEFAULT_LIMITS.max_config_bytes:
        raise ConfigError(
            f"the configuration is larger than {DEFAULT_LIMITS.max_config_bytes} bytes"
        )
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError("the configuration is not valid UTF-8") from None
    # Whitespace controls are normal in YAML; anything else invisible could hide content.
    plain = text.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    position = first_unsafe(plain)
    if position is not None:
        line = text.count("\n", 0, position) + 1
        raise ConfigError(
            f"the configuration has a control or invisible character at line {line} "
            f"(U+{ord(text[position]):04X})"
        )
    return text


def load_config(data: bytes, *, flavour: Flavour, home: UserPath | None = None) -> Config:
    """Parse and validate configuration ``data``; raise ConfigError for anything wrong.

    ``flavour`` says which operating system's path rules apply, and ``home`` is the absolute
    home directory that ``~`` expands to (None means a ``~`` is an error). Nothing is read from
    the environment and the filesystem is not touched.
    """
    document = _parse_yaml(_decode(data))
    if document is None:
        raise ConfigError("the configuration is empty")
    top = _mapping("the configuration", document, _TOP_LEVEL_KEYS)

    version = top.get("version")
    if type(version) is not int or version != CONFIG_VERSION:  # not True, not 1.0
        raise ConfigError(f"version must be the number {CONFIG_VERSION}")
    limits = _limits(top.get("limits"))
    if len(data) > limits.max_config_bytes:
        raise ConfigError(f"the configuration is larger than {limits.max_config_bytes} bytes")

    symlinks = SymlinkPolicy.NEVER
    if "symlinks" in top:
        label = _text("symlinks", top["symlinks"])
        try:
            symlinks = SymlinkPolicy(label)
        except ValueError:
            raise ConfigError("symlinks must be 'never' or 'files'") from None
    one_file_system = (
        _flag("one_file_system", top["one_file_system"]) if "one_file_system" in top else True
    )
    exclude = _text_list("exclude", top["exclude"]) if "exclude" in top else ()

    entries = top.get("paths")
    if not isinstance(entries, list) or not entries:
        raise ConfigError("paths must list at least one monitored path")
    roots = [
        _root(index, entry, flavour, home, one_file_system, limits.max_path_chars)
        for index, entry in enumerate(entries)
    ]
    policy = build_policy(roots, exclude, symlinks, limits)

    key_file = None
    if "key_file" in top:
        key_file = _user_path(
            "key_file",
            _text("key_file", top["key_file"]),
            flavour,
            home,
            limits.max_path_chars,
        )
        # CLAUDE.md invariant 5. The anchor file sits next to the key, so it is covered too.
        if any(is_within(key_file, root.path) for root in policy.roots):
            raise ConfigError("key_file must not be inside a monitored path")
    host_label = _host_label(top["host_label"]) if "host_label" in top else None
    return Config(policy=policy, host_label=host_label, key_file=key_file)
