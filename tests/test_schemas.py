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


def test_local_openapi_yaml_catalog_loads_models(tmp_path: Path) -> None:
    path = tmp_path / "models.yaml"
    path.write_text(
        """openapi: 3.0.0
info:
  title: Local models
  version: yaml-1
components:
  schemas:
    LocalRequest:
      type: object
      required: [name]
      properties:
        name:
          type: string
""",
        encoding="utf-8",
    )

    catalog = ModelCatalog.from_path(path)

    assert catalog.version == "yaml-1"
    assert catalog.names() == ["LocalRequest"]


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("components: [", "not valid YAML"),
        ("- components", "YAML root must be an object"),
        ("openapi: 3.0.0\ninfo: {}\n", "components.schemas"),
        ("components:\n  schemas: []\n", "components.schemas"),
    ],
)
def test_malformed_yaml_catalogs_report_clear_errors(
    tmp_path: Path, body: str, message: str
) -> None:
    path = tmp_path / "models.yml"
    path.write_text(body, encoding="utf-8")

    with pytest.raises(ModelCatalogError, match=message):
        ModelCatalog.from_path(path)


def test_yaml_safe_loader_rejects_python_objects(tmp_path: Path) -> None:
    path = tmp_path / "models.yaml"
    path.write_text("!!python/object/apply:os.system ['echo unsafe']\n", encoding="utf-8")

    with pytest.raises(ModelCatalogError, match="not valid YAML"):
        ModelCatalog.from_path(path)


def test_yaml_catalog_normalizes_timestamp_scalars(tmp_path: Path) -> None:
    path = tmp_path / "models.yaml"
    path.write_text(
        "components:\n  schemas:\n    Dated:\n      type: string\n      example: 2026-09-22\n",
        encoding="utf-8",
    )

    assert ModelCatalog.from_path(path).sample("Dated") == "2026-09-22"


def test_yaml_catalog_uses_yaml_12_boolean_keys(tmp_path: Path) -> None:
    path = tmp_path / "models.yaml"
    path.write_text(
        "components:\n  schemas:\n    Switch:\n      type: object\n"
        "      properties:\n        on: {type: string}\n        off: {type: string}\n"
        "        12:34: {type: string}\n        <<: {type: string}\n",
        encoding="utf-8",
    )

    properties = ModelCatalog.from_path(path).get("Switch")["properties"]
    assert list(properties) == ["on", "off", "12:34", "<<"]


def test_yaml_catalog_uses_yaml_12_numeric_scalars(tmp_path: Path) -> None:
    path = tmp_path / "models.yaml"
    path.write_text(
        "components:\n  schemas:\n    Numbers:\n      type: object\n      example:\n"
        "        leading: 012\n        exponent: 1e3\n        duration: 1:20\n"
        "        octal: 0o12\n",
        encoding="utf-8",
    )

    assert ModelCatalog.from_path(path).sample("Numbers") == {
        "leading": 12,
        "exponent": 1000.0,
        "duration": "1:20",
        "octal": 10,
    }


def test_yaml_catalog_rejects_duplicate_keys(tmp_path: Path) -> None:
    path = tmp_path / "models.yaml"
    path.write_text(
        "components:\n  schemas:\n    Duplicate: {type: string}\n"
        "    Duplicate: {type: integer}\n",
        encoding="utf-8",
    )

    with pytest.raises(ModelCatalogError, match="not valid YAML"):
        ModelCatalog.from_path(path)


def test_yaml_catalog_rejects_acyclic_alias_expansion(tmp_path: Path) -> None:
    path = tmp_path / "models.yaml"
    path.write_text(
        "components:\n  schemas:\n    Alias:\n      example: &base [one, two]\n"
        "      enum: [*base, *base]\n",
        encoding="utf-8",
    )

    with pytest.raises(ModelCatalogError) as caught:
        ModelCatalog.from_path(path)

    assert "aliases are not supported" in str(caught.value)
    assert "convert it to JSON" in str(caught.value)
    assert "will not convert or copy" in str(caught.value)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("components:\n  schemas:\n    1: {}\n", "non-string key"),
        (
            "components:\n  schemas:\n    Loop:\n      example: &loop [*loop]\n",
            "aliases are not supported",
        ),
        ("components:\n  schemas:\n    Number:\n      example: .nan\n", "non-finite"),
    ],
)
def test_yaml_catalog_rejects_non_json_trees(
    tmp_path: Path, body: str, message: str
) -> None:
    path = tmp_path / "models.yaml"
    path.write_text(body, encoding="utf-8")

    with pytest.raises(ModelCatalogError, match=message):
        ModelCatalog.from_path(path)


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
