from __future__ import annotations

import stat

import pytest

from anvilogic_cli.io import (
    load_json_input,
    parse_headers,
    parse_pairs,
    response_bytes_and_format,
    write_output,
)


def test_json_input_is_strict() -> None:
    assert load_json_input('{"ok": true}', None) == {"ok": True}
    with pytest.raises(ValueError, match="line 1"):
        load_json_input("{", None)
    with pytest.raises(ValueError, match="non-finite"):
        load_json_input('{"score": NaN}', None)
    with pytest.raises(ValueError, match="duplicate"):
        load_json_input('{"score": 1, "score": 2}', None)


def test_parse_pairs_preserves_repeated_query_keys() -> None:
    assert parse_pairs(["tag=one", "tag=two"]) == [("tag", "one"), ("tag", "two")]


def test_parse_headers_rejects_duplicates_case_insensitively() -> None:
    with pytest.raises(ValueError, match="Duplicate"):
        parse_headers(["X-Test: one", "x-test: two"])


def test_response_json_is_pretty_and_deterministic() -> None:
    body, selected = response_bytes_and_format(b'{"b":2,"a":1}', "application/json", "auto")

    assert selected == "json"
    assert body == b'{\n  "a": 1,\n  "b": 2\n}\n'


def test_write_output_is_private_and_refuses_overwrite(tmp_path) -> None:
    path = tmp_path / "response.json"
    write_output(path, b"first")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(ValueError, match="already exists"):
        write_output(path, b"second")
    write_output(path, b"second", force=True)
    assert path.read_bytes() == b"second"
