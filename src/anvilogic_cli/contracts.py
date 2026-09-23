"""Offline OpenAPI 3.0 operation-contract resolution and payload validation."""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, cast
from urllib.parse import unquote

import yaml
from jsonschema import Draft7Validator
from jsonschema.exceptions import SchemaError, UnknownType
from referencing import Registry, Resource
from referencing.exceptions import Unresolvable
from referencing.jsonschema import DRAFT7
from yaml.events import AliasEvent

from anvilogic_cli.errors import ModelCatalogError, ModelValidationError
from anvilogic_cli.json_utils import loads_json
from anvilogic_cli.schemas import (
    FORMAT_CHECKER,
    CatalogSafeLoader,
    ValidationIssue,
    _normalize_yaml_json,
)

OPENAPI_30_RE = re.compile(r"^3\.0\.\d+$")
HTTP_METHODS = {"delete", "get", "head", "options", "patch", "post", "put"}
CONTRACT_URI = "urn:anvilogic:local-openapi-contract"


class ContractError(ModelValidationError):
    """Raised when a local OpenAPI operation contract cannot be used safely."""


class OpenAPIContractCatalog:
    """Resolve exact operation contracts from one operator-controlled OpenAPI document."""

    def __init__(self, document: dict[str, Any], *, source: str = "unknown") -> None:
        version = document.get("openapi")
        if not isinstance(version, str) or not OPENAPI_30_RE.fullmatch(version):
            raise ContractError("Contract validation requires an OpenAPI 3.0.x document.")
        info = document.get("info")
        paths = document.get("paths")
        if not isinstance(info, dict) or not isinstance(info.get("title"), str):
            raise ContractError("OpenAPI contract must contain an info object with a title.")
        if not isinstance(info.get("version"), str):
            raise ContractError("OpenAPI contract info must contain a string version.")
        if not isinstance(paths, dict):
            raise ContractError("OpenAPI contract must contain a paths object.")
        self.document = copy.deepcopy(document)
        self.source = source
        validation_document = _openapi_schema_to_draft7(self.document)
        resource = Resource.from_contents(validation_document, default_specification=DRAFT7)
        self._registry = Registry().with_resource(CONTRACT_URI, resource)
        self._operations = self._index_operations(paths)

    @classmethod
    def from_path(cls, path: Path) -> OpenAPIContractCatalog:
        if path.suffix.casefold() in {".md", ".markdown"}:
            raise ContractError(
                "Contract validation requires a full local OpenAPI 3.0.x JSON/YAML "
                "document; Markdown model exports cannot resolve operations."
            )
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise ContractError(f"Could not read OpenAPI contract: {path}") from exc
        try:
            if path.suffix.casefold() in {".yaml", ".yml"}:
                if any(
                    isinstance(event, AliasEvent)
                    for event in yaml.parse(text, Loader=CatalogSafeLoader)
                ):
                    raise ContractError("OpenAPI contract YAML aliases are not supported.")
                payload = _normalize_yaml_json(yaml.load(text, Loader=CatalogSafeLoader))
            else:
                payload = loads_json(text)
        except ContractError:
            raise
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError, yaml.YAMLError) as exc:
            raise ContractError(f"OpenAPI contract is not valid JSON/YAML: {path}") from exc
        except ModelCatalogError as exc:
            raise ContractError(str(exc).replace("Model catalog", "OpenAPI contract")) from exc
        if not isinstance(payload, dict):
            raise ContractError("OpenAPI contract root must be an object.")
        return cls(payload, source=str(path))

    def validate_request(
        self,
        method: str,
        path: str,
        payload: Any,
        *,
        body_supplied: bool,
        registry_has_body: bool,
    ) -> list[ValidationIssue]:
        operation = self._operation(method, path)
        has_request_body = "requestBody" in operation
        if has_request_body != registry_has_body:
            raise ContractError(
                f"OpenAPI request-body contract conflicts with the registry for "
                f"{method.upper()} {_normalize_path(path)}."
            )
        if not has_request_body:
            if body_supplied:
                raise ContractError("The OpenAPI operation does not define a request body.")
            return []
        request_body = self._resolve_object(
            operation["requestBody"], label="request body"
        )
        required = request_body.get("required", False)
        if not isinstance(required, bool):
            raise ContractError("OpenAPI requestBody.required must be boolean.")
        schema = self._json_schema(request_body, label="request body")
        if not body_supplied:
            if required:
                raise ContractError("The OpenAPI operation requires a JSON request body.")
            return []
        return self._validate(schema, payload)

    def validate_response(
        self,
        method: str,
        path: str,
        status_code: int,
        content_type: str,
        payload: Any,
    ) -> list[ValidationIssue]:
        operation = self._operation(method, path)
        responses = operation.get("responses")
        if not isinstance(responses, dict):
            raise ContractError("OpenAPI operation does not define response contracts.")
        if not all(isinstance(key, str) for key in responses):
            raise ContractError("OpenAPI response status keys must be strings.")
        exact = str(status_code)
        family = f"{status_code // 100}XX"
        selected_key = next(
            (key for key in (exact, family, "default") if key in responses),
            None,
        )
        if selected_key is None:
            raise ContractError(f"HTTP {status_code} is undocumented for this operation.")
        media_type = content_type.split(";", 1)[0].strip().casefold()
        if media_type != "application/json":
            raise ContractError(
                f"HTTP {status_code} response is not application/json and cannot be validated."
            )
        response = self._resolve_object(
            responses[selected_key], label=f"response {selected_key}"
        )
        schema = self._json_schema(response, label=f"response {selected_key}")
        return self._validate(schema, payload)

    def _index_operations(
        self, paths: dict[str, Any]
    ) -> dict[tuple[str, str], dict[str, Any]]:
        indexed: dict[tuple[str, str], dict[str, Any]] = {}
        for raw_path, raw_path_item in paths.items():
            normalized_path = _normalize_path(raw_path)
            path_item = self._resolve_object(raw_path_item, label=f"path {normalized_path}")
            normalized_methods: set[str] = set()
            for raw_method, raw_operation in path_item.items():
                method = str(raw_method).casefold()
                if method not in HTTP_METHODS:
                    continue
                if method in normalized_methods:
                    raise ContractError(
                        f"OpenAPI contract repeats {method.upper()} {normalized_path}."
                    )
                normalized_methods.add(method)
                operation = self._resolve_object(
                    raw_operation,
                    label=f"operation {method.upper()} {normalized_path}",
                )
                key = (method.upper(), normalized_path)
                if key in indexed:
                    raise ContractError(
                        f"OpenAPI contract has conflicting definitions for "
                        f"{key[0]} {normalized_path}."
                    )
                indexed[key] = operation
        return indexed

    def _operation(self, method: str, path: str) -> dict[str, Any]:
        key = (method.strip().upper(), _normalize_path(path))
        operation = self._operations.get(key)
        if operation is None:
            raise ContractError(
                f"OpenAPI contract does not contain exact operation {key[0]} {key[1]}."
            )
        return operation

    def _resolve_object(
        self,
        value: Any,
        *,
        label: str,
        seen: frozenset[str] = frozenset(),
    ) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ContractError(f"OpenAPI {label} must be an object.")
        reference = value.get("$ref")
        if reference is None:
            return value
        if len(value) != 1:
            raise ContractError(f"OpenAPI {label} has conflicting $ref sibling fields.")
        if not isinstance(reference, str) or reference in seen:
            raise ContractError(f"OpenAPI {label} has a cyclic or invalid reference.")
        target = self._resolve_pointer(reference)
        if not isinstance(target, dict):
            raise ContractError(f"OpenAPI {label} reference does not resolve to an object.")
        return self._resolve_object(target, label=label, seen=seen | {reference})

    def _resolve_pointer(self, reference: Any) -> Any:
        if not isinstance(reference, str) or not (
            reference == "#" or reference.startswith("#/")
        ):
            raise ContractError(
                "Only local JSON Pointer references are allowed in OpenAPI contracts."
            )
        fragment = unquote(reference[1:])
        if not fragment:
            return self.document
        current: Any = self.document
        for raw_token in fragment[1:].split("/"):
            if re.search(r"~(?![01])", raw_token):
                raise ContractError(f"OpenAPI reference has an invalid JSON Pointer: {reference}")
            token = raw_token.replace("~1", "/").replace("~0", "~")
            if isinstance(current, dict) and token in current:
                current = current[token]
            elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
                current = current[int(token)]
            else:
                raise ContractError(f"OpenAPI reference cannot be resolved: {reference}")
        return current

    def _json_schema(self, container: dict[str, Any], *, label: str) -> dict[str, Any]:
        content = container.get("content")
        if not isinstance(content, dict):
            raise ContractError(f"OpenAPI {label} does not define content.")
        media = content.get("application/json")
        if not isinstance(media, dict):
            raise ContractError(f"OpenAPI {label} does not define application/json content.")
        schema = media.get("schema")
        if not isinstance(schema, dict):
            raise ContractError(f"OpenAPI {label} does not define a JSON schema.")
        self._check_schema_references(schema, seen=set())
        return cast(dict[str, Any], _openapi_schema_to_draft7(schema))

    def _check_schema_references(self, value: Any, *, seen: set[str]) -> None:
        if isinstance(value, list):
            for item in value:
                self._check_schema_references(item, seen=seen)
            return
        if not isinstance(value, dict):
            return
        reference = value.get("$ref")
        if reference is not None:
            if not isinstance(reference, str) or not reference.startswith("#/"):
                raise ContractError(
                    "Only local JSON Pointer references are allowed in OpenAPI schemas."
                )
            target = self._resolve_pointer(reference)
            if not isinstance(target, dict):
                raise ContractError(
                    f"OpenAPI schema reference does not resolve to an object: {reference}"
                )
            if reference not in seen:
                seen.add(reference)
                self._check_schema_references(target, seen=seen)
        for key, item in value.items():
            if key != "$ref":
                self._check_schema_references(item, seen=seen)

    def _validate(self, schema: dict[str, Any], payload: Any) -> list[ValidationIssue]:
        try:
            validator = Draft7Validator(
                schema,
                registry=self._registry,
                format_checker=FORMAT_CHECKER,
            )
            errors = sorted(
                validator.iter_errors(payload),
                key=lambda item: tuple(str(part) for part in item.absolute_path),
            )
        except (SchemaError, UnknownType, Unresolvable, TypeError, ValueError) as exc:
            raise ContractError(f"OpenAPI schema could not be evaluated: {exc}") from exc
        issues: list[ValidationIssue] = []
        for error in errors:
            path = "$"
            for part in error.absolute_path:
                path += f"[{part}]" if isinstance(part, int) else f".{part}"
            issues.append(
                ValidationIssue(path=path, message=error.message, validator=str(error.validator))
            )
        return issues


def _normalize_path(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or "//" in value
        or "?" in value
        or "#" in value
        or ".." in value.split("/")
    ):
        raise ContractError(f"Invalid OpenAPI path template: {value!r}.")
    return value.rstrip("/") or "/"


def _openapi_schema_to_draft7(value: Any) -> Any:
    if isinstance(value, list):
        return [_openapi_schema_to_draft7(item) for item in value]
    if not isinstance(value, dict):
        return copy.deepcopy(value)
    converted = {
        key: _openapi_schema_to_draft7(item)
        for key, item in value.items()
        if key != "nullable"
    }
    reference = converted.get("$ref")
    if isinstance(reference, str) and reference.startswith("#"):
        converted["$ref"] = CONTRACT_URI + reference
    if value.get("nullable") is True:
        schema_type = converted.get("type")
        if isinstance(schema_type, str):
            converted["type"] = [schema_type, "null"]
        elif "$ref" in converted:
            referenced = {"$ref": converted.pop("$ref")}
            converted["anyOf"] = [referenced, {"type": "null"}]
    for keyword, boundary in (
        ("exclusiveMinimum", "minimum"),
        ("exclusiveMaximum", "maximum"),
    ):
        exclusive = converted.get(keyword)
        if isinstance(exclusive, bool):
            converted.pop(keyword)
            if exclusive and boundary in converted:
                converted[keyword] = converted.pop(boundary)
    return converted
