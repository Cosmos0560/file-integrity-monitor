"""core/policy.py: building, digesting and applying the policy (PLAN.md D4)."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

import factories as make
from fim.core import policy as policy_module
from fim.core.errors import ConfigError, PathRuleError
from fim.core.limits import DEFAULT_LIMITS, Limits
from fim.core.models import Policy, RootPolicy, Severity, SymlinkPolicy
from fim.core.pathrules import Flavour, expand_tilde, validate_user_path
from fim.core.policy import (
    POLICY_DIGEST_VERSION,
    build_policy,
    compile_rules,
    component_key,
    compute_digest,
    digest_is_valid,
    owning_root,
    policy_document,
)

POSIX = Flavour.POSIX
WINDOWS = Flavour.WINDOWS


def posix_root(raw: str, **overrides: Any) -> RootPolicy:
    return RootPolicy(path=validate_user_path(raw, POSIX), **overrides)


def windows_root(raw: str, **overrides: Any) -> RootPolicy:
    return RootPolicy(path=validate_user_path(raw, WINDOWS), **overrides)


def build(roots: list[RootPolicy] | None = None, **overrides: Any) -> Policy:
    fields: dict[str, Any] = {
        "roots": roots if roots is not None else [posix_root("/data")],
        "exclude": ["*.tmp"],
        "symlinks": SymlinkPolicy.NEVER,
        "limits": DEFAULT_LIMITS,
    }
    fields.update(overrides)
    return build_policy(**fields)


# ---- digest --------------------------------------------------------------------------------------


def test_the_document_names_its_version_and_every_input() -> None:
    document = policy_document(
        [posix_root("/etc", severity=Severity.HIGH, include=("*.conf",), exclude=("mtab",))],
        ["*.tmp"],
        SymlinkPolicy.FILES,
        DEFAULT_LIMITS,
    )
    assert document["version"] == POLICY_DIGEST_VERSION
    assert document["symlinks"] == "files"
    assert document["exclude"] == ["*.tmp"]
    assert document["limits"]["max_files"] == DEFAULT_LIMITS.max_files
    assert document["roots"] == [
        {
            "flavour": "posix",
            "drive": "",
            "parts": ["etc"],
            "severity": "high",
            "include": ["*.conf"],
            "exclude": ["mtab"],
            "one_file_system": True,
        }
    ]


def test_the_digest_is_pinned_so_a_change_of_the_canonical_form_is_noticed() -> None:
    digest = compute_digest(
        [posix_root("/etc", severity=Severity.HIGH)], ["*.tmp"], SymlinkPolicy.NEVER, DEFAULT_LIMITS
    )
    assert digest == "484d74a4e7a4ef9e2d4083e287f7bad02324b9d70417ca9f4b735d9544fb405d"


def test_a_built_policy_carries_a_valid_digest() -> None:
    policy = build()
    assert len(policy.digest) == 64
    assert digest_is_valid(policy)


def test_equal_input_gives_equal_digest() -> None:
    assert build().digest == build().digest


@pytest.mark.parametrize(
    "change",
    [
        {"roots": [posix_root("/other")]},
        {"roots": [posix_root("/data", severity=Severity.HIGH)]},
        {"roots": [posix_root("/data", include=("*.py",))]},
        {"roots": [posix_root("/data", exclude=("x",))]},
        {"roots": [posix_root("/data", one_file_system=False)]},
        {"roots": [posix_root("/data"), posix_root("/more")]},
        {"exclude": []},
        {"exclude": ["*.tmp", "*.bak"]},
        {"exclude": ["*.bak"]},
        {"symlinks": SymlinkPolicy.FILES},
        {"limits": Limits(max_files=1000)},
        {"limits": Limits(max_hash_file_bytes=1024)},
    ],
    ids=lambda change: next(iter(change)),
)
def test_every_input_changes_the_digest(change: dict[str, Any]) -> None:
    assert build(**change).digest != build().digest


def test_the_order_of_roots_matters_because_root_index_refers_to_it() -> None:
    first = build([posix_root("/a"), posix_root("/b")])
    second = build([posix_root("/b"), posix_root("/a")])
    assert first.digest != second.digest


def test_a_tampered_policy_fails_the_digest_check() -> None:
    policy = build()
    tampered = replace(policy, exclude=("*.tmp", "secret/**"))
    assert not digest_is_valid(tampered)
    assert digest_is_valid(replace(policy))


def test_windows_and_posix_roots_with_the_same_parts_digest_differently() -> None:
    posix = build([posix_root("/a/b")])
    windows = build([windows_root("C:\\a\\b")])
    assert posix.digest != windows.digest


# ---- validation ----------------------------------------------------------------------------------


def test_no_roots_is_refused() -> None:
    with pytest.raises(ConfigError, match="at least one"):
        build([])


def test_more_roots_than_the_limit_is_refused() -> None:
    roots = [posix_root(f"/r{n}") for n in range(3)]
    with pytest.raises(ConfigError, match="more than 2 monitored"):
        build(roots, limits=Limits(max_roots=2))


def test_the_same_root_twice_is_refused() -> None:
    with pytest.raises(ConfigError, match="twice"):
        build([posix_root("/data"), posix_root("/data/")])


def test_windows_roots_that_differ_only_in_case_are_the_same_root() -> None:
    with pytest.raises(ConfigError, match="twice"):
        build([windows_root("C:\\Data"), windows_root("c:\\DATA")])


def test_posix_roots_that_differ_only_in_case_are_different_roots() -> None:
    assert len(build([posix_root("/Data"), posix_root("/data")]).roots) == 2


def test_mixing_windows_and_posix_roots_is_refused() -> None:
    with pytest.raises(ConfigError, match="mix"):
        build([posix_root("/data"), windows_root("C:\\data")])


def test_too_many_patterns_in_total_is_refused() -> None:
    limits = Limits(max_patterns=3)
    with pytest.raises(ConfigError, match="more than 3"):
        build(
            [posix_root("/a", include=("a", "b")), posix_root("/b", exclude=("c",))],
            exclude=["d"],
            limits=limits,
        )
    build([posix_root("/a", include=("a", "b"))], exclude=["d"], limits=limits)  # exactly 3


@pytest.mark.parametrize("bad", ["[abc", "a//b", "", "/abs"])
def test_a_bad_pattern_anywhere_is_refused_before_any_scan(bad: str) -> None:
    with pytest.raises(ConfigError):
        build(exclude=[bad])
    with pytest.raises(ConfigError):
        build([posix_root("/data", include=(bad,))])
    with pytest.raises(ConfigError):
        build([posix_root("/data", exclude=(bad,))])


def test_the_pattern_length_limit_comes_from_the_policy_limits() -> None:
    with pytest.raises(ConfigError, match="longer than 5"):
        build(exclude=["abcdefg"], limits=Limits(max_pattern_chars=5))


# ---- applying the policy -------------------------------------------------------------------------


def test_rules_put_global_excludes_before_the_roots_own() -> None:
    policy = build([posix_root("/data", exclude=("mine",), include=("*.py",))], exclude=["glob"])
    (rules,) = compile_rules(policy)
    assert [p.source for p in rules.exclude] == ["glob", "mine"]
    assert [p.source for p in rules.include] == ["*.py"]
    assert rules.index == 0
    assert rules.nested == frozenset()


def test_posix_rules_are_case_sensitive_and_windows_rules_are_not() -> None:
    (posix_rules,) = compile_rules(build([posix_root("/d")], exclude=["*.TMP"]))
    (windows_rules,) = compile_rules(build([windows_root("C:\\d")], exclude=["*.TMP"]))
    assert posix_rules.exclude[0].case_sensitive is True
    assert windows_rules.exclude[0].case_sensitive is False


def test_nested_roots_are_listed_for_the_enclosing_root_only() -> None:
    policy = build([posix_root("/srv"), posix_root("/srv/app"), posix_root("/other")])
    outer, inner, other = compile_rules(policy)
    assert outer.nested == frozenset({component_key(POSIX, "", ("srv", "app"))})
    assert inner.nested == frozenset()
    assert other.nested == frozenset()


def test_deeply_nested_roots_are_all_listed() -> None:
    policy = build([posix_root("/a"), posix_root("/a/b"), posix_root("/a/b/c")])
    outer, middle, inner = compile_rules(policy)
    assert len(outer.nested) == 2
    assert len(middle.nested) == 1
    assert inner.nested == frozenset()


def test_a_sibling_with_a_common_prefix_is_not_nested() -> None:
    policy = build([posix_root("/srv/app"), posix_root("/srv/app2")])
    assert all(rules.nested == frozenset() for rules in compile_rules(policy))


def test_windows_nesting_ignores_case() -> None:
    policy = build([windows_root("C:\\Srv"), windows_root("c:\\srv\\APP")])
    outer, _inner = compile_rules(policy)
    assert outer.nested == frozenset({component_key(WINDOWS, "C:", ("srv", "app"))})


def test_the_filesystem_root_contains_everything() -> None:
    policy = build([posix_root("/"), posix_root("/etc")])
    outer, _ = compile_rules(policy)
    assert len(outer.nested) == 1


def test_component_key_folds_case_only_on_windows() -> None:
    assert component_key(POSIX, "", ("A", "b")) == ("", "A", "b")
    assert component_key(WINDOWS, "C:", ("A", "b")) == ("c:", "a", "b")


def test_the_most_specific_root_owns_a_path() -> None:
    policy = build([posix_root("/srv"), posix_root("/srv/app"), posix_root("/other")])
    assert owning_root(policy, validate_user_path("/srv/file", POSIX)) == 0
    assert owning_root(policy, validate_user_path("/srv/app/file", POSIX)) == 1
    assert owning_root(policy, validate_user_path("/srv/app", POSIX)) == 1
    assert owning_root(policy, validate_user_path("/srv", POSIX)) == 0
    assert owning_root(policy, validate_user_path("/other/x/y", POSIX)) == 2
    assert owning_root(policy, validate_user_path("/elsewhere", POSIX)) is None
    assert owning_root(policy, validate_user_path("/srvx/file", POSIX)) is None


def test_ownership_is_independent_of_the_order_of_the_roots() -> None:
    policy = build([posix_root("/srv/app"), posix_root("/srv")])
    assert owning_root(policy, validate_user_path("/srv/app/file", POSIX)) == 0
    assert owning_root(policy, validate_user_path("/srv/file", POSIX)) == 1


def test_the_factory_policy_is_consistent_with_a_built_one() -> None:
    # The hand-made factory digest is arbitrary; only build_policy produces a verifiable one.
    assert not digest_is_valid(make.policy())


def test_module_exports() -> None:
    assert set(policy_module.__all__) >= {"build_policy", "compile_rules", "owning_root"}


# ---- expand_tilde (pathrules) --------------------------------------------------------------------


def test_expand_tilde_joins_the_home_directory() -> None:
    home = validate_user_path("/home/lab", POSIX)
    path = validate_user_path("~/bin/tools", POSIX, allow_tilde=True)
    expanded = expand_tilde(path, home)
    assert expanded.text == "/home/lab/bin/tools"
    assert expanded.absolute
    assert not expanded.tilde


def test_expand_tilde_alone_is_the_home_directory() -> None:
    home = validate_user_path("C:\\Users\\lab", WINDOWS)
    expanded = expand_tilde(validate_user_path("~", WINDOWS, allow_tilde=True), home)
    assert expanded.text == "C:\\Users\\lab"
    assert expanded.drive == "C:"


def test_expand_tilde_refuses_wrong_inputs() -> None:
    home = validate_user_path("/home/lab", POSIX)
    with pytest.raises(PathRuleError, match="start with"):
        expand_tilde(validate_user_path("/etc", POSIX), home)
    tilde = validate_user_path("~/x", POSIX, allow_tilde=True)
    with pytest.raises(PathRuleError, match="absolute"):
        expand_tilde(tilde, tilde)
    with pytest.raises(PathRuleError, match="absolute"):
        expand_tilde(tilde, validate_user_path("rel/dir", POSIX))
    with pytest.raises(PathRuleError, match="flavour"):
        expand_tilde(tilde, validate_user_path("C:\\Users", WINDOWS))
