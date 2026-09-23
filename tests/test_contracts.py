from __future__ import annotations

import json
from pathlib import Path

import pytest

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
                                        "properties": {"created": {"const": True}},
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
    yaml_path.write_text(
        "openapi: 3.0.1\n"
        "info: {title: Synthetic, version: test}\n"
        "paths:\n"
        "  /bodyless:\n"
        "    get:\n"
        "      responses: {}\n",
        encoding="utf-8",
    )

    assert OpenAPIContractCatalog.from_path(json_path).source == str(json_path)
    assert (
        OpenAPIContractCatalog.from_path(yaml_path).validate_request(
            "GET", "/bodyless", None, body_supplied=False, registry_has_body=False
        )
        == []
    )


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
