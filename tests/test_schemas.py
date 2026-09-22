from __future__ import annotations

import json
from pathlib import Path

import pytest

from anvilogic_cli.errors import ModelCatalogError
from anvilogic_cli.schemas import ModelCatalog

FIXTURE_CATALOG = Path(__file__).parent / "fixtures" / "model_catalog.json"


def supplied_catalog() -> ModelCatalog:
    return ModelCatalog.from_path(FIXTURE_CATALOG)


def test_caller_supplied_catalog_loads_exported_models() -> None:
    catalog = supplied_catalog()

    assert catalog.stats()["models"] == 2
    assert catalog.version == "test-1"
    assert "AddCommentRequest" in catalog.names()


def test_search_matches_name_description_and_properties() -> None:
    catalog = supplied_catalog()

    assert "ApiKeySpec" in catalog.names("apikey")
    assert "AddCommentRequest" in catalog.names("parent_comment_id")


def test_get_accepts_case_insensitive_exact_name() -> None:
    catalog = supplied_catalog()

    assert catalog.get("addcommentrequest")["type"] == "object"


def test_unknown_model_fails() -> None:
    with pytest.raises(ModelCatalogError, match="Unknown model"):
        supplied_catalog().get("DefinitelyNotAModel")


def test_validate_reports_required_and_length_errors() -> None:
    catalog = supplied_catalog()

    missing = catalog.validate("AddCommentRequest", {})
    empty = catalog.validate("AddCommentRequest", {"comment": ""})

    assert any(issue.validator == "required" for issue in missing)
    assert any(issue.path == "$.comment" and issue.validator == "minLength" for issue in empty)
    assert catalog.validate("AddCommentRequest", {"comment": "looks good"}) == []


def test_sample_includes_required_fields() -> None:
    sample = supplied_catalog().sample("AddCommentRequest")

    assert sample == {"comment": "string"}


def test_resolve_marks_recursive_references() -> None:
    catalog = ModelCatalog(
        {
            "Node": {
                "type": "object",
                "properties": {"child": {"$ref": "#/components/schemas/Node"}},
            }
        }
    )

    resolved = catalog.resolved("Node")

    assert resolved["properties"]["child"]["properties"]["child"]["x-anvilogic-recursive"]


def test_markdown_conflicts_fail() -> None:
    one = {"components": {"schemas": {"A": {"type": "string"}}}}
    two = {"components": {"schemas": {"A": {"type": "integer"}}}}
    markdown = f"```json\n{json.dumps(one)}\n```\n```json\n{json.dumps(two)}\n```"

    with pytest.raises(ModelCatalogError, match="Conflicting"):
        ModelCatalog.from_markdown(markdown)


def test_openapi_formats_are_checked_without_optional_format_dependencies() -> None:
    catalog = ModelCatalog(
        {
            "Formatted": {
                "type": "object",
                "properties": {
                    "count": {"type": "integer", "format": "int32"},
                    "timestamp": {"type": "string", "format": "date-time"},
                },
            }
        }
    )

    issues = catalog.validate(
        "Formatted",
        {"count": 2**40, "timestamp": "2026-09-02T20:00:00"},
    )

    assert len(issues) == 2
    assert all(issue.validator == "format" for issue in issues)
