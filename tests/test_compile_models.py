from __future__ import annotations

import json

import pytest

from scripts.compile_models import compile_export, render_catalog


def fragment(name: str, schema: dict) -> str:
    payload = {
        "openapi": "3.0.0",
        "info": {"version": "1.2.3"},
        "components": {"schemas": {name: schema}},
    }
    return f"```json\n{json.dumps(payload)}\n```\n"


def test_compilation_is_sorted_and_deterministic() -> None:
    source = (fragment("Z", {"type": "string"}) + fragment("A", {"type": "integer"})).encode()

    catalog = compile_export(source, source_name="models.md")

    assert list(catalog["components"]["schemas"]) == ["A", "Z"]
    assert render_catalog(catalog) == render_catalog(catalog)
    assert catalog["x-anvilogic-source"]["fragments"] == 2


def test_compilation_rejects_conflicts() -> None:
    source = (fragment("A", {"type": "string"}) + fragment("A", {"type": "integer"})).encode()

    with pytest.raises(ValueError, match="conflicting"):
        compile_export(source, source_name="models.md")


def test_compilation_rejects_ambiguous_json() -> None:
    source = b'```json\n{"components":{"schemas":{"A":{},"A":{}}}}\n```\n'

    with pytest.raises(ValueError, match="duplicate"):
        compile_export(source, source_name="models.md")
