from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from anvilogic_cli.contracts import ContractError, OpenAPIContractCatalog


def document() -> dict:
    payload = {
        "openapi": "3.0.3",
        "info": {"title": "Synthetic contract", "version": "test"},
        "paths": {
            "/items/{item_id}": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Item"}
                            }
                        },
                    },
                    "responses": {
                        "201": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["created"],
                                        "properties": {"created": {"enum": [True]}},
                                    }
                                }
                            }
                        },
                        "2XX": {
                            "content": {
                                "application/json": {
                                    "schema": {"type": "string", "pattern": "^family$"}
                                }
                            }
                        },
                        "default": {
                            "content": {
                                "application/json": {
                                    "schema": {"type": "string", "pattern": "^default$"}
                                }
                            }
                        },
                    },
                }
            },
            "/optional": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {"schema": {"type": "object"}}
                        }
                    },
                    "responses": {},
                }
            },
            "/bodyless": {"get": {"responses": {}}},
        },
    }
    payload["components"] = dict(
        schemas={
            "Item": {
                "type": "object",
                "required": ["name"],
                "properties": {"name": {"type": "string", "minLength": 1}},
            }
        }
    )
    return payload


def test_loads_full_openapi_json_and_yaml(tmp_path: Path) -> None:
    json_path = tmp_path / "contract.json"
    yaml_path = tmp_path / "contract.yaml"
    json_path.write_text(json.dumps(document()), encoding="utf-8")
    yaml_path.write_text(yaml.safe_dump(document(), sort_keys=False), encoding="utf-8")

    assert OpenAPIContractCatalog.from_path(json_path).source == str(json_path)
    for path in (json_path, yaml_path):
        catalog = OpenAPIContractCatalog.from_path(path)
        assert catalog.validate_request(
            "POST",
            "/items/{item_id}",
            {"name": "safe"},
            body_supplied=True,
            registry_has_body=True,
        ) == []
        assert catalog.validate_response(
            "POST", "/items/{item_id}", 201, "application/json", {"created": True}
        ) == []


def test_alias_bearing_yaml_has_actionable_offline_remediation(tmp_path: Path) -> None:
    path = tmp_path / "contract.yaml"
    path.write_text(
        "openapi: 3.0.3\n"
        "info: {title: Synthetic, version: test}\n"
        "paths:\n"
        "  /first: &path\n"
        "    get: {responses: {}}\n"
        "  /second: *path\n",
        encoding="utf-8",
    )

    with pytest.raises(ContractError) as caught:
        OpenAPIContractCatalog.from_path(path)

    assert "aliases are not supported" in str(caught.value)
    assert "trusted local document" in str(caught.value)
    assert "convert it to JSON" in str(caught.value)
    assert "will not convert or copy" in str(caught.value)

@pytest.mark.parametrize("version", ["3.1.0", "2.0", "3.0", 3])
def test_requires_openapi_30x(version: object) -> None:
    payload = document()
    payload["openapi"] = version

    with pytest.raises(ContractError, match="OpenAPI 3.0.x"):
        OpenAPIContractCatalog(payload)


def test_markdown_and_schema_only_catalogs_cannot_resolve_contracts(tmp_path: Path) -> None:
    markdown = tmp_path / "models.md"
    schemas = tmp_path / "models.json"
    markdown.write_text("```json\n{}\n```\n", encoding="utf-8")
    schemas.write_text(
        json.dumps(dict(components=dict(schemas={"A": {}}))), encoding="utf-8"
    )

    with pytest.raises(ContractError, match="Markdown"):
        OpenAPIContractCatalog.from_path(markdown)
    with pytest.raises(ContractError, match="OpenAPI 3.0.x"):
        OpenAPIContractCatalog.from_path(schemas)


def test_request_validation_supports_inline_and_local_reference_schemas() -> None:
    catalog = OpenAPIContractCatalog(document())

    assert catalog.validate_request(
        "POST",
        "/items/{item_id}",
        {"name": "safe"},
        body_supplied=True,
        registry_has_body=True,
    ) == []
    issues = catalog.validate_request(
        "POST",
        "/items/{item_id}",
        {},
        body_supplied=True,
        registry_has_body=True,
    )
    assert [issue.validator for issue in issues] == ["required"]
    assert catalog.validate_request(
        "POST", "/optional", None, body_supplied=False, registry_has_body=True
    ) == []


def test_required_body_and_registry_conflicts_fail_closed() -> None:
    catalog = OpenAPIContractCatalog(document())

    with pytest.raises(ContractError, match="requires"):
        catalog.validate_request(
            "POST",
            "/items/{item_id}",
            None,
            body_supplied=False,
            registry_has_body=True,
        )
    with pytest.raises(ContractError, match="conflicts"):
        catalog.validate_request(
            "GET", "/bodyless", None, body_supplied=False, registry_has_body=True
        )


def test_exact_operation_matching_and_normalized_conflicts() -> None:
    catalog = OpenAPIContractCatalog(document())

    with pytest.raises(ContractError, match="exact operation"):
        catalog.validate_request(
            "POST", "/items", {}, body_supplied=True, registry_has_body=True
        )

    payload = document()
    payload["paths"]["/optional/"] = payload["paths"]["/optional"]
    with pytest.raises(ContractError, match="conflicting definitions"):
        OpenAPIContractCatalog(payload)


@pytest.mark.parametrize(
    ("reference", "message"),
    [
        ("https://example.com/schema.json", "Only local JSON Pointer"),
        ("#/components/schemas/Missing", "cannot be resolved"),
    ],
)
def test_external_and_unresolved_references_fail_without_fetching(
    reference: str, message: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = document()
    payload["paths"]["/items/{item_id}"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"] = {"$ref": reference}
    fetched = False

    def forbidden_fetch(*_args: object, **_kwargs: object) -> None:
        nonlocal fetched
        fetched = True
        raise AssertionError("runtime fetching is forbidden")

    monkeypatch.setattr("urllib.request.urlopen", forbidden_fetch)
    catalog = OpenAPIContractCatalog(payload)
    with pytest.raises(ContractError, match=message):
        catalog.validate_request(
            "POST",
            "/items/{item_id}",
            {"name": "safe"},
            body_supplied=True,
            registry_has_body=True,
        )
    assert fetched is False


def test_missing_json_schema_and_non_json_content_fail_closed() -> None:
    payload = document()
    media = payload["paths"]["/optional"]["post"]["requestBody"]["content"]
    media["text/plain"] = media.pop("application/json")
    catalog = OpenAPIContractCatalog(payload)

    with pytest.raises(ContractError, match="application/json"):
        catalog.validate_request(
            "POST", "/optional", {}, body_supplied=True, registry_has_body=True
        )

    payload = document()
    del payload["paths"]["/optional"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    catalog = OpenAPIContractCatalog(payload)
    with pytest.raises(ContractError, match="JSON schema"):
        catalog.validate_request(
            "POST", "/optional", {}, body_supplied=True, registry_has_body=True
        )


def test_response_selection_prefers_exact_then_family_then_default() -> None:
    catalog = OpenAPIContractCatalog(document())

    assert catalog.validate_response(
        "POST", "/items/{item_id}", 201, "application/json; charset=utf-8", {"created": True}
    ) == []
    assert catalog.validate_response(
        "POST", "/items/{item_id}", 202, "application/json", "family"
    ) == []
    assert catalog.validate_response(
        "POST", "/items/{item_id}", 418, "application/json", "default"
    ) == []
    assert catalog.validate_response(
        "POST", "/items/{item_id}", 201, "application/json", "family"
    )[0].validator == "type"


def test_response_validation_rejects_undocumented_or_non_json_responses() -> None:
    payload = document()
    payload["paths"]["/bodyless"]["get"]["responses"] = {
        "200": {
            "content": {"application/json": {"schema": {"type": "object"}}}
        }
    }
    catalog = OpenAPIContractCatalog(payload)

    with pytest.raises(ContractError, match="undocumented"):
        catalog.validate_response("GET", "/bodyless", 404, "application/json", {})
    with pytest.raises(ContractError, match="not application/json"):
        catalog.validate_response("GET", "/bodyless", 200, "text/plain", {})


def test_recursive_references_composition_and_nullable_values() -> None:
    payload = document()
    payload["components"]["schemas"]["Node"] = {
        "type": "object",
        "required": ["value"],
        "properties": {
            "value": {"type": "string"},
            "next": {
                "type": "object",
                "nullable": True,
                "allOf": [{"$ref": "#/components/schemas/Node"}],
            },
        },
    }
    payload["paths"]["/optional"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"] = {
        "allOf": [
            {"$ref": "#/components/schemas/Node"},
            {
                "type": "object",
                "properties": {
                    "kind": {"oneOf": [{"enum": ["a"]}, {"enum": ["b"]}]}
                },
            },
        ]
    }
    catalog = OpenAPIContractCatalog(payload)

    valid = {"value": "root", "next": {"value": "child", "next": None}, "kind": "a"}
    assert catalog.validate_request(
        "POST", "/optional", valid, body_supplied=True, registry_has_body=True
    ) == []
    issues = catalog.validate_request(
        "POST",
        "/optional",
        {"value": "root", "next": {"next": None}, "kind": "c"},
        body_supplied=True,
        registry_has_body=True,
    )
    assert {issue.validator for issue in issues} == {"anyOf", "oneOf"}


def test_constraints_are_enforced_after_openapi_30_conversion() -> None:
    payload = document()
    payload["paths"]["/optional"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"] = {
        "type": "object",
        "additionalProperties": False,
        "minProperties": 2,
        "required": ["score", "tags"],
        "properties": {
            "score": {
                "type": "number",
                "minimum": 0,
                "exclusiveMinimum": True,
                "maximum": 10,
            },
            "tags": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": {"type": "string", "minLength": 2, "pattern": "^[a-z]+$"},
            },
        },
    }
    catalog = OpenAPIContractCatalog(payload)

    assert catalog.validate_request(
        "POST",
        "/optional",
        {"score": 1, "tags": ["ok"]},
        body_supplied=True,
        registry_has_body=True,
    ) == []
    issues = catalog.validate_request(
        "POST",
        "/optional",
        {"score": 0, "tags": ["A", "A"], "extra": True},
        body_supplied=True,
        registry_has_body=True,
    )
    assert {issue.validator for issue in issues} >= {
        "additionalProperties",
        "exclusiveMinimum",
        "uniqueItems",
    }


def test_read_only_and_write_only_properties_follow_payload_direction() -> None:
    payload = document()
    directional = {
        "type": "object",
        "additionalProperties": False,
        "required": ["id", "name", "secret"],
        "properties": {
            "id": {"type": "string", "readOnly": True},
            "name": {"type": "string"},
            "secret": {"type": "string", "writeOnly": True},
        },
    }
    operation = payload["paths"]["/items/{item_id}"]["post"]
    operation["requestBody"]["content"]["application/json"]["schema"] = directional
    operation["responses"]["201"]["content"]["application/json"]["schema"] = directional
    catalog = OpenAPIContractCatalog(payload)

    assert catalog.validate_request(
        "POST",
        "/items/{item_id}",
        {"name": "item", "secret": "sanitized"},
        body_supplied=True,
        registry_has_body=True,
    ) == []
    assert catalog.validate_response(
        "POST", "/items/{item_id}", 201, "application/json", {"id": "1", "name": "item"}
    ) == []
    request_issues = catalog.validate_request(
        "POST",
        "/items/{item_id}",
        {"id": "1", "name": "item", "secret": "sanitized"},
        body_supplied=True,
        registry_has_body=True,
    )
    response_issues = catalog.validate_response(
        "POST",
        "/items/{item_id}",
        201,
        "application/json",
        {"id": "1", "name": "item", "secret": "sanitized"},
    )
    assert request_issues
    assert response_issues


def test_annotation_only_keywords_do_not_change_validation() -> None:
    payload = document()
    payload["paths"]["/optional"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"] = {
        "type": "string",
        "title": "Annotation",
        "description": "Synthetic description",
        "default": "default",
        "example": "example",
        "deprecated": True,
        "discriminator": {"propertyName": "kind"},
        "externalDocs": {"url": "https://example.com/docs"},
        "xml": {"name": "value"},
        "x-synthetic-note": {"ignored": True},
    }
    catalog = OpenAPIContractCatalog(payload)

    assert catalog.validate_request(
        "POST", "/optional", "value", body_supplied=True, registry_has_body=True
    ) == []
    assert catalog.validate_request(
        "POST", "/optional", 1, body_supplied=True, registry_has_body=True
    )[0].validator == "type"


@pytest.mark.parametrize("keyword", ["const", "contains", "if", "patternProperties"])
def test_unsupported_validation_keywords_fail_closed(keyword: str) -> None:
    payload = document()
    payload["paths"]["/optional"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"] = {"type": "object", keyword: {}}
    catalog = OpenAPIContractCatalog(payload)

    with pytest.raises(ContractError, match="Unsupported OpenAPI 3.0 schema keyword"):
        catalog.validate_request(
            "POST", "/optional", {}, body_supplied=True, registry_has_body=True
        )


def test_nullable_without_an_explicit_openapi_type_fails_closed() -> None:
    payload = document()
    payload["paths"]["/optional"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"] = {"nullable": True, "allOf": [{"type": "string"}]}
    catalog = OpenAPIContractCatalog(payload)

    with pytest.raises(ContractError, match="nullable requires an explicit type"):
        catalog.validate_request(
            "POST", "/optional", None, body_supplied=True, registry_has_body=True
        )
