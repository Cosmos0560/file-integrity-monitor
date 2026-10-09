"""services/baseline_codec.py: the file format, verify-before-parse, tamper cases, the golden file
and the rollback anchor (PLAN.md D3 and its rollback-anchor amendment)."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import baseline_helpers as helpers
from fim.core.canonical import canonical_json
from fim.core.errors import BaselineIntegrityError, ExitCode, ModelError
from fim.core.limits import DEFAULT_LIMITS, MAX_BASELINE_BYTES
from fim.core.models import EntryType
from fim.services import baseline_codec as codec
from fim.services.keystore import Key

KEY = helpers.TEST_KEY
OTHER_KEY = Key(bytes(range(1, 33)))
MAX = DEFAULT_LIMITS.max_baseline_bytes
DATA_DIR = Path(__file__).parent / "data"


def encoded(sequence: int = 1) -> codec.EncodedBaseline:
    return codec.encode_baseline(helpers.sample_baseline(sequence), KEY)


def refused(data: bytes, key: Key = KEY, max_bytes: int = MAX) -> BaselineIntegrityError:
    with pytest.raises(BaselineIntegrityError) as raised:
        codec.decode_baseline(data, key, max_bytes=max_bytes)
    assert raised.value.exit_code == ExitCode.INTEGRITY
    return raised.value


def split(data: bytes) -> tuple[dict[str, Any], bytes]:
    line, _, payload = data.partition(b"\n")
    return json.loads(line), payload


def dumps(value: Any) -> bytes:
    """JSON as an attacker may write it: not bound by our canonical encoder (floats allowed)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def join(envelope: dict[str, Any], payload: bytes) -> bytes:
    return dumps(envelope) + b"\n" + payload


def sign(payload: bytes, key: Key = KEY) -> dict[str, Any]:
    """A valid envelope for ``payload``, built from the documented formula, not from the codec."""
    key_id = hmac.new(key.secret, b"fim key id v1", hashlib.sha256).hexdigest()[:16]
    message = b"fim-baseline\x00v1\x00" + key_id.encode() + b"\x00" + payload
    return {
        "format": "fim-baseline",
        "version": 1,
        "mac_alg": "HMAC-SHA256",
        "key_id": key_id,
        "mac": hmac.new(key.secret, message, hashlib.sha256).hexdigest(),
    }


# ---- round trip and format -----------------------------------------------------------------------


def test_round_trip_gives_back_the_same_baseline() -> None:
    original = helpers.sample_baseline(5)
    result = encoded(5)
    decoded = codec.decode_baseline(result.data, KEY, max_bytes=MAX)
    assert decoded.baseline == original
    assert decoded.key_id == KEY.key_id == result.key_id
    assert decoded.payload_sha256 == result.payload_sha256
    assert result.sequence == 5


def test_round_trip_keeps_the_exact_path_and_link_target() -> None:
    decoded = codec.decode_baseline(encoded().data, KEY, max_bytes=MAX)
    paths = [record.path for record in decoded.baseline.records]
    assert "d\udc80ir/\u00e9\u202e.txt" in paths
    link = next(r for r in decoded.baseline.records if r.type is EntryType.SYMLINK)
    assert link.link_target == "../target\\x"


def test_the_file_is_an_envelope_line_then_the_payload() -> None:
    envelope, payload = split(encoded().data)
    assert set(envelope) == {"format", "version", "mac_alg", "key_id", "mac"}
    assert envelope["format"] == "fim-baseline"
    assert envelope["version"] == 1
    assert envelope["mac_alg"] == "HMAC-SHA256"
    assert len(encoded().data.split(b"\n", 1)[0]) < codec.ENVELOPE_MAX_BYTES
    assert payload.startswith(b'{"header":')
    assert b"\n" not in payload  # canonical JSON has no newline, so "the rest" is unambiguous


def test_the_whole_file_is_ascii_whatever_the_paths_contain() -> None:
    data = encoded().data
    data.decode("ascii")
    assert b"\xc3" not in data
    assert b"\\udc80" in data  # the lone surrogate is an escape, not raw


def test_the_mac_follows_the_documented_formula() -> None:
    data = encoded().data
    envelope, payload = split(data)
    assert envelope == sign(payload)


def test_encoding_is_deterministic() -> None:
    assert encoded(2).data == encoded(2).data


def test_a_different_sequence_changes_the_mac_and_the_digest() -> None:
    first, second = encoded(1), encoded(2)
    assert first.payload_sha256 != second.payload_sha256
    assert split(first.data)[0]["mac"] != split(second.data)[0]["mac"]


# ---- the golden file -----------------------------------------------------------------------------

GOLDEN_FULL_FILE_SHA256 = "c362130787c5d610cffba54efa2d6eb49e38bdf008353cec84d7fd5f62ac1907"
GOLDEN_KEY_ID = "a2698a054f3aac06"


def test_canonical_bytes_equal_the_golden_file_on_every_python() -> None:
    """The same bytes on Python 3.11, 3.12 and 3.13 (CI runs this file on all three).

    The golden payload is committed; if a Python version writes other bytes, or a Unicode
    table change leaks into storage, this fails.
    """
    golden = (DATA_DIR / "golden_payload.json").read_bytes()
    result = codec.encode_baseline(helpers.sample_baseline(3), KEY)
    assert split(result.data)[1] == golden
    assert result.payload_sha256 == hashlib.sha256(golden).hexdigest()
    assert hashlib.sha256(result.data).hexdigest() == GOLDEN_FULL_FILE_SHA256
    assert result.key_id == GOLDEN_KEY_ID


def test_the_golden_payload_decodes_with_a_signature_made_independently() -> None:
    golden = (DATA_DIR / "golden_payload.json").read_bytes()
    decoded = codec.decode_baseline(join(sign(golden), golden), KEY, max_bytes=MAX)
    assert decoded.baseline == helpers.sample_baseline(3)


# ---- every tamper case exits 3 -------------------------------------------------------------------


def test_one_flipped_byte_anywhere_in_the_envelope_is_refused() -> None:
    data = encoded().data
    envelope_end = data.index(b"\n")
    for position in range(envelope_end + 1):  # the newline too: then there is no envelope
        for flip in (0x01, 0x80):
            damaged = bytearray(data)
            damaged[position] ^= flip
            refused(bytes(damaged))


def test_one_flipped_byte_anywhere_in_the_payload_is_refused() -> None:
    data = encoded().data
    start = data.index(b"\n") + 1
    for position in range(start, len(data)):
        damaged = bytearray(data)
        damaged[position] ^= 0x01
        error = refused(bytes(damaged))
        assert "MAC does not verify" in error.message


def test_a_changed_mac_is_refused_with_the_mac_message() -> None:
    envelope, payload = split(encoded().data)
    envelope["mac"] = ("0" if envelope["mac"][0] != "0" else "1") + envelope["mac"][1:]
    assert "MAC does not verify" in refused(join(envelope, payload)).message


def test_a_changed_version_is_refused_as_unsupported() -> None:
    envelope, payload = split(encoded().data)
    for version in (2, 0, "1", True, 1.0, None):
        envelope["version"] = version
        error = refused(join(envelope, payload))
        assert "unsupported version" in error.message


def test_an_unknown_format_is_refused() -> None:
    envelope, payload = split(encoded().data)
    envelope["format"] = "fim-baseline-x"
    assert "unknown format" in refused(join(envelope, payload)).message


def test_an_unknown_mac_algorithm_is_refused() -> None:
    envelope, payload = split(encoded().data)
    envelope["mac_alg"] = "HMAC-SHA1"
    assert "MAC algorithm" in refused(join(envelope, payload)).message


def test_a_changed_key_id_is_refused_as_a_wrong_key() -> None:
    envelope, payload = split(encoded().data)
    envelope["key_id"] = "0" * 16
    assert "wrong key file" in refused(join(envelope, payload)).message


def test_a_key_id_edited_together_with_a_correct_looking_mac_still_fails() -> None:
    """Re-signing with the wrong key gives a consistent envelope that this key must reject."""
    payload = split(encoded().data)[1]
    forged = join(sign(payload, OTHER_KEY), payload)
    assert "wrong key file" in refused(forged).message


def test_the_wrong_key_says_wrong_key_not_just_mac_mismatch() -> None:
    error = refused(encoded().data, key=OTHER_KEY)
    assert "wrong key file" in error.message
    assert KEY.key_id in error.message
    assert OTHER_KEY.key_id in error.message


@pytest.mark.parametrize("keep", [0, 1, 10, 100, 150, 400, 2000])
def test_a_truncated_file_is_refused(keep: int) -> None:
    data = encoded().data
    assert keep < len(data)
    refused(data[:keep])


def test_a_file_missing_only_its_last_byte_is_refused() -> None:
    assert "MAC does not verify" in refused(encoded().data[:-1]).message


@pytest.mark.parametrize("extra", [b"\n", b" ", b"x", b"\x00", b"\r\n", b"}", b"{}"])
def test_trailing_bytes_are_refused(extra: bytes) -> None:
    assert "MAC does not verify" in refused(encoded().data + extra).message


def test_an_envelope_only_file_is_refused() -> None:
    envelope = split(encoded().data)[0]
    refused(canonical_json(envelope) + b"\n")
    refused(canonical_json(envelope))


def test_an_oversize_file_is_refused_before_anything_else() -> None:
    data = encoded().data
    error = refused(data, max_bytes=len(data) - 1)
    assert "larger than" in error.message
    assert codec.decode_baseline(data, KEY, max_bytes=len(data)).baseline is not None


def record_json(calls: list[int]) -> Any:
    def loads(*_args: Any, **_kwargs: Any) -> None:
        calls.append(1)

    return loads


def test_an_oversize_file_is_never_looked_at(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    monkeypatch.setattr("fim.services.baseline_codec.json.loads", record_json(calls))
    refused(b"x" * 100, max_bytes=10)
    assert calls == []


def test_the_default_size_limit_is_the_documented_ceiling() -> None:
    assert MAX == MAX_BASELINE_BYTES


def test_envelope_must_be_exactly_the_five_fields() -> None:
    envelope, payload = split(encoded().data)
    refused(join({**envelope, "extra": 1}, payload))
    short = dict(envelope)
    del short["mac_alg"]
    refused(join(short, payload))


def test_envelope_that_is_not_an_object_is_refused() -> None:
    payload = split(encoded().data)[1]
    for line in (b"[]", b"null", b"3", b'"x"', b"{", b"", b"\xff\xfe"):
        refused(line + b"\n" + payload)


def test_envelope_with_duplicate_keys_is_refused() -> None:
    envelope, payload = split(encoded().data)
    text = canonical_json(envelope).decode()
    doubled = text[:-1] + ',"version":1}'
    refused(doubled.encode() + b"\n" + payload)


def test_envelope_with_malformed_key_id_or_mac_is_refused() -> None:
    envelope, payload = split(encoded().data)
    for name, bad in (
        ("key_id", "XYZ"),
        ("key_id", 5),
        ("mac", "ab"),
        ("mac", "G" * 64),
        ("mac", None),
        ("key_id", "A" * 16),
    ):
        refused(join({**envelope, name: bad}, payload))


def test_a_long_first_line_is_not_an_envelope() -> None:
    refused(b"a" * 2000 + b"\n" + split(encoded().data)[1])


# ---- verify before parse (spy) -------------------------------------------------------------------


def test_the_payload_parser_is_never_called_before_the_mac_verifies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[bytes] = []

    def spy(payload: bytes) -> object:
        calls.append(payload)
        raise AssertionError("the parser ran on unverified bytes")

    monkeypatch.setattr(codec, "parse_payload", spy)
    data = encoded().data
    start = data.index(b"\n") + 1
    damaged_variants = [
        data[:-1],
        data + b"x",
        data[:start] + b"[]",
        data[:start] + data[start:].replace(b"lab-01", b"lab-02"),
    ]
    for damaged in damaged_variants:
        refused(damaged)
    refused(data, key=OTHER_KEY)
    assert calls == []


def test_the_parser_runs_exactly_once_and_only_on_verified_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = codec.parse_payload
    calls: list[bytes] = []

    def spy(payload: bytes) -> Any:
        calls.append(payload)
        return real(payload)

    monkeypatch.setattr(codec, "parse_payload", spy)
    data = encoded().data
    codec.decode_baseline(data, KEY, max_bytes=MAX)
    assert calls == [data.split(b"\n", 1)[1]]


def test_json_is_only_applied_to_the_small_envelope_before_the_mac_verifies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = json.loads
    sizes: list[int] = []

    def spy(text: str, **kwargs: Any) -> Any:
        sizes.append(len(text))
        return real(text, **kwargs)

    monkeypatch.setattr("fim.services.baseline_codec.json.loads", spy)
    data = encoded().data
    damaged = data.replace(b"lab-01", b"lab-02")
    refused(damaged)
    assert sizes
    assert all(size <= codec.ENVELOPE_MAX_BYTES for size in sizes)


# ---- a signed but invalid payload is still refused (exit 3) -------------------------------------


def signed(document: Any) -> bytes:
    payload = dumps(document)
    return join(sign(payload), payload)


def good_document() -> dict[str, Any]:
    document: dict[str, Any] = json.loads((DATA_DIR / "golden_payload.json").read_bytes())
    return document


def test_signed_garbage_is_refused_with_exit_3() -> None:
    documents: list[Any] = [[], {}, {"header": {}, "records": []}, {"header": 1, "records": 1}]
    for document in documents:
        error = refused(signed(document))
        assert "signed but its content is invalid" in error.message


def test_a_signed_payload_that_is_not_json_or_not_ascii_is_refused() -> None:
    for payload in (b"not json", b"\xff\xfe", b"", b"{" * 3000):
        refused(join(sign(payload), payload))


def test_a_signed_payload_with_a_tampered_policy_digest_is_refused() -> None:
    document = good_document()
    document["header"]["policy"]["digest"] = "0" * 64
    assert "digest" in refused(signed(document)).message


def test_a_signed_payload_with_a_changed_policy_but_old_digest_is_refused() -> None:
    document = good_document()
    document["header"]["policy"]["roots"][0]["severity"] = "low"
    assert "digest" in refused(signed(document)).message


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["records"][0].update(type="spaceship"),
        lambda d: d["records"][0].update(hash_status="maybe"),
        lambda d: d["records"][1].update(sha256="xyz"),
        lambda d: d["records"][1].update(sha256=None),
        lambda d: d["records"][1].update(size=-1),
        lambda d: d["records"][1].update(size=True),
        lambda d: d["records"][1].update(size=1.5),
        lambda d: d["records"][1].update(path="a/../b"),
        lambda d: d["records"][1].update(path="/abs"),
        lambda d: d["records"][1].update(root_index=7),
        lambda d: d["records"][1].update(extra=1),
        lambda d: d["records"][1].pop("mode"),
        lambda d: d["records"][1].update(mode=0o777777),
        lambda d: d["records"][1].update(mode=1, win_attrs=1),
        lambda d: d["records"][1].update(path=5),
        lambda d: d["records"][1].update(link_target="x"),
        lambda d: d["header"].update(sequence=0),
        lambda d: d["header"].update(sequence="1"),
        lambda d: d["header"].update(created_at="2026-03-04"),
        lambda d: d["header"].update(created_at="2026-13-04T05:06:07.890123Z"),
        lambda d: d["header"].update(complete="yes"),
        lambda d: d["header"].update(host="a\u202eb"),
        lambda d: d["header"].update(extra=1),
        lambda d: d["header"].pop("limits"),
        lambda d: d["header"]["limits"].update(max_files=10**9),
        lambda d: d["header"]["limits"].pop("max_files"),
        lambda d: d["header"]["limits"].update(unknown=1),
        lambda d: d["header"]["policy"].update(version="fim-policy/2"),
        lambda d: d["header"]["policy"].update(roots=[]),
        lambda d: d["header"]["policy"].update(roots="x"),
        lambda d: d["header"]["policy"]["roots"][0].update(parts=["a", ".."]),
        lambda d: d["header"]["policy"]["roots"][0].update(flavour="amiga"),
        lambda d: d["header"]["policy"]["roots"][0].update(drive="C:"),
        lambda d: d["header"]["policy"]["roots"][0].update(severity="urgent"),
        lambda d: d["header"]["policy"]["roots"][0].update(one_file_system="yes"),
        lambda d: d["header"]["policy"]["roots"][0].update(parts=["srv", ""]),
        lambda d: d["header"]["policy"]["roots"][0].update(include=["[bad"]),
        lambda d: d["header"]["policy"].update(exclude="*.tmp"),
        lambda d: d["header"]["policy"]["roots"][0].update(include="*.conf"),
        lambda d: d.update(extra=1),
        lambda d: d.update(records="x"),
    ],
)
def test_signed_but_structurally_wrong_payloads_are_refused(mutate: Any) -> None:
    document = good_document()
    mutate(document)
    refused(signed(document))


def test_a_signed_payload_with_too_many_records_is_refused() -> None:
    document = good_document()
    policy = document["header"]["policy"]
    document["header"]["limits"]["max_files"] = 1
    policy["limits"]["max_files"] = 1
    # The policy digest no longer matches, so fix it with the real function to isolate the rule.
    from fim.core.policy import compute_digest

    parsed = codec.parse_payload(canonical_json(good_document()))
    limits = replace(DEFAULT_LIMITS, max_files=1)
    policy["digest"] = compute_digest(
        parsed.header.policy.roots,
        parsed.header.policy.exclude,
        parsed.header.policy.symlinks,
        limits,
    )
    document["records"] = document["records"] * 3
    assert "more records" in refused(signed(document)).message


def test_deeply_nested_signed_payload_is_refused_not_a_crash() -> None:
    payload = b"[" * 100_000 + b"]" * 100_000
    refused(join(sign(payload), payload))


def test_error_messages_never_contain_the_key() -> None:
    secret = KEY.secret.hex()
    data = encoded().data
    for damaged in (data[:-1], data + b"x", data[:50], data.replace(b"fim-baseline", b"nope")):
        assert secret not in refused(damaged).message
    assert secret not in refused(data, key=OTHER_KEY).message
    assert secret not in data.decode("ascii")


# ---- the rollback anchor -------------------------------------------------------------------------

DIGEST = "e3" * 32
BID = "b1" * 8  # the id of the baseline file the anchor belongs to
OTHER_BID = "c2" * 8


def anchor_bytes(
    sequence: int = 4, digest: str = DIGEST, key: Key = KEY, baseline_id: str = BID
) -> bytes:
    return codec.encode_anchor(key, baseline_id, sequence, digest)


def refused_anchor(data: bytes, key: Key = KEY, baseline_id: str = BID) -> BaselineIntegrityError:
    with pytest.raises(BaselineIntegrityError) as raised:
        codec.decode_anchor(data, key, baseline_id)
    assert raised.value.exit_code == ExitCode.INTEGRITY
    return raised.value


def test_anchor_round_trip() -> None:
    anchor = codec.decode_anchor(anchor_bytes(), KEY, BID)
    assert anchor == codec.Anchor(
        key_id=KEY.key_id, baseline_id=BID, sequence=4, payload_sha256=DIGEST
    )


def test_anchor_file_starts_with_its_fixed_header_line() -> None:
    data = anchor_bytes()
    assert data.startswith(b"FIM-ANCHOR v2\n")
    assert data.decode("ascii").count("\n") == 6
    assert f"baseline_id {BID}\n" in data.decode("ascii")
    assert data.endswith(b"\n")


def test_anchor_holds_no_key_material() -> None:
    assert KEY.secret.hex().encode() not in anchor_bytes()


def test_one_flipped_byte_anywhere_in_the_anchor_is_refused() -> None:
    data = anchor_bytes()
    for position in range(len(data)):
        for flip in (0x01, 0x80):
            damaged = bytearray(data)
            damaged[position] ^= flip
            refused_anchor(bytes(damaged))


@pytest.mark.parametrize("keep", range(0, 160, 7))
def test_truncated_anchor_is_refused(keep: int) -> None:
    data = anchor_bytes()
    if keep >= len(data) - 1:
        pytest.skip("not truncated")
    refused_anchor(data[:keep])


@pytest.mark.parametrize("extra", [b"\n", b"x", b"mac 00\n", b"\r\n"])
def test_anchor_with_trailing_bytes_is_refused(extra: bytes) -> None:
    refused_anchor(anchor_bytes() + extra)


def test_anchor_made_with_another_key_names_the_key_problem() -> None:
    error = refused_anchor(anchor_bytes(key=OTHER_KEY))
    assert "different key" in error.message
    assert "move the old anchor file away" in error.message


def test_an_anchor_for_another_baseline_is_refused() -> None:
    """One key protects several baselines; each has its own anchor, bound by its baseline id."""
    error = refused_anchor(anchor_bytes(baseline_id=OTHER_BID))
    assert "belongs to another baseline file" in error.message
    assert OTHER_BID in error.message
    assert BID in error.message


def test_an_anchor_cannot_be_retargeted_by_editing_its_baseline_id() -> None:
    text = anchor_bytes(baseline_id=OTHER_BID).decode().replace(OTHER_BID, BID)
    assert "MAC does not verify" in refused_anchor(text.encode()).message


def test_an_anchor_in_the_old_one_per_key_format_says_so() -> None:
    old = "FIM-ANCHOR v1\nkey_id " + KEY.key_id + "\n"
    assert "old one-anchor-per-key format" in refused_anchor(old.encode()).message


def test_anchor_with_changed_sequence_or_digest_fails_its_mac() -> None:
    text = anchor_bytes().decode()
    refused_anchor(text.replace("sequence 4", "sequence 5").encode())
    refused_anchor(text.replace(DIGEST, "e4" * 32).encode())


def test_a_baseline_style_mac_is_not_accepted_as_an_anchor_mac() -> None:
    """Domain separation: the same fields signed with the baseline prefix do not verify."""
    fields = (KEY.key_id.encode(), BID.encode(), b"4", DIGEST.encode())
    message = b"\x00".join(fields)
    wrong = hmac.new(KEY.secret, b"fim-baseline\x00v1\x00" + message, hashlib.sha256).hexdigest()
    lines = (
        f"FIM-ANCHOR v2\nkey_id {KEY.key_id}\nbaseline_id {BID}\nsequence 4\n"
        f"payload_sha256 {DIGEST}\nmac {wrong}\n"
    )
    assert "MAC does not verify" in refused_anchor(lines.encode()).message
    right = hmac.new(KEY.secret, b"fim-anchor\x00v2\x00" + message, hashlib.sha256).hexdigest()
    good = lines.replace(wrong, right)
    assert codec.decode_anchor(good.encode(), KEY, BID).sequence == 4


def test_the_key_id_and_baseline_mac_domains_are_distinct() -> None:
    domains = {b"fim-baseline\x00v1\x00", b"fim-anchor\x00v2\x00", b"fim key id v1"}
    assert len(domains) == 3


@pytest.mark.parametrize(
    "mutation",
    [
        lambda t: t.replace("FIM-ANCHOR v2", "FIM-ANCHOR v3"),
        lambda t: t.replace("FIM-ANCHOR v2", "FIM-ANCHOR v1"),
        lambda t: t.replace(f"baseline_id {BID}\n", ""),
        lambda t: t.replace(f"baseline_id {BID}", "baseline_id XYZ"),
        lambda t: t.replace(f"baseline_id {BID}", "baseline_id " + BID.upper()),
        lambda t: t.replace("key_id ", "baseline_id ", 1),
        lambda t: t.replace("\n", "\r\n"),
        lambda t: t.replace("sequence 4", "sequence 04"),
        lambda t: t.replace("sequence 4", "sequence 0"),
        lambda t: t.replace("sequence 4", "sequence -4"),
        lambda t: t.replace("sequence 4", "sequence 4 "),
        lambda t: t.replace("sequence 4", "sequence 99999999999999999"),
        lambda t: t.replace("sequence 4", "sequence 9007199254740993"),
        lambda t: t.replace("key_id ", "key-id "),
        lambda t: t.replace("payload_sha256 ", "payload_sha256  "),
        lambda t: t.upper(),
        lambda t: t.replace("\nsequence 4\npayload_sha256", "\npayload_sha256"),
        lambda t: "\n" + t,
        lambda _t: "",
        lambda t: t.replace("mac ", "mac"),
    ],
)
def test_malformed_anchors_are_refused(mutation: Any) -> None:
    refused_anchor(mutation(anchor_bytes().decode()).encode())


def test_non_ascii_anchor_is_refused() -> None:
    refused_anchor(anchor_bytes() + "\u00e9".encode())


def test_anchor_arguments_are_validated() -> None:
    for sequence in (0, -1, True, 2**53 + 1, "3"):
        with pytest.raises(ModelError):
            codec.encode_anchor(KEY, BID, sequence, DIGEST)  # type: ignore[arg-type]  # bad type
    for digest in ("", "ab", "G" * 64, DIGEST.upper()):
        with pytest.raises(ModelError):
            codec.encode_anchor(KEY, BID, 1, digest)
    for baseline_id in ("", "ab", "G" * 16, BID.upper(), BID + "0"):
        with pytest.raises(ModelError):
            codec.encode_anchor(KEY, baseline_id, 1, DIGEST)


def test_next_sequence_is_one_without_an_anchor_and_plus_one_with_one() -> None:
    assert codec.next_sequence(None) == 1
    anchor = codec.decode_anchor(anchor_bytes(sequence=7), KEY, BID)
    assert codec.next_sequence(anchor) == 8


# ---- comparing a baseline with the anchor --------------------------------------------------------


def anchor_for(result: codec.EncodedBaseline) -> codec.Anchor:
    return codec.decode_anchor(
        codec.encode_anchor(KEY, BID, result.sequence, result.payload_sha256), KEY, BID
    )


def test_a_baseline_that_matches_its_anchor_passes() -> None:
    result = encoded(3)
    decoded = codec.decode_baseline(result.data, KEY, max_bytes=MAX)
    codec.verify_against_anchor(anchor_for(result), decoded)


def test_an_older_validly_signed_baseline_is_refused_as_a_rollback() -> None:
    old = codec.decode_baseline(encoded(2).data, KEY, max_bytes=MAX)
    with pytest.raises(BaselineIntegrityError) as raised:
        codec.verify_against_anchor(anchor_for(encoded(3)), old)
    assert raised.value.exit_code == ExitCode.INTEGRITY
    assert "sequence 2" in raised.value.message
    assert "sequence 3" in raised.value.message


def test_a_baseline_newer_than_the_anchor_is_refused_too() -> None:
    newer = codec.decode_baseline(encoded(4).data, KEY, max_bytes=MAX)
    with pytest.raises(BaselineIntegrityError):
        codec.verify_against_anchor(anchor_for(encoded(3)), newer)


def test_a_different_baseline_with_the_same_sequence_is_refused_as_a_substitution() -> None:
    base = helpers.sample_baseline(3)
    other = replace(base, header=replace(base.header, host="elsewhere"))
    substitute = codec.decode_baseline(codec.encode_baseline(other, KEY).data, KEY, max_bytes=MAX)
    with pytest.raises(BaselineIntegrityError) as raised:
        codec.verify_against_anchor(anchor_for(encoded(3)), substitute)
    assert "different content" in raised.value.message
