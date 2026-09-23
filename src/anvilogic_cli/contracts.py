"""Offline OpenAPI 3.0 operation-contract resolution and payload validation."""

from __future__ import annotations

import copy
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import unquote

from jsonschema import Draft7Validator
from jsonschema.exceptions import SchemaError, UnknownType
from referencing import Registry, Resource
from referencing.exceptions import Unresolvable
from referencing.jsonschema import DRAFT7

from anvilogic_cli.documents import StructuredDocumentError, load_structured_document
from anvilogic_cli.errors import ModelValidationError
from anvilogic_cli.schemas import FORMAT_CHECKER, ValidationIssue

OPENAPI_30_RE = re.compile(r"^3\.0\.\d+$")
HTTP_METHODS = {"delete", "get", "head", "options", "patch", "post", "put"}
CONTRACT_URI = "urn:anvilogic:local-openapi-contract"
SchemaDirection = Literal["request", "response"]

SCHEMA_KEYWORDS = {
    "$ref",
    "additionalProperties",
    "allOf",
    "anyOf",
    "default",
    "deprecated",
    "description",
    "discriminator",
    "enum",
    "example",
    "exclusiveMaximum",
    "exclusiveMinimum",
    "externalDocs",
    "format",
    "items",
    "maximum",
    "maxItems",
    "maxLength",
    "maxProperties",
    "minimum",
    "minItems",
    "minLength",
    "minProperties",
    "multipleOf",
    "not",
    "nullable",
    "oneOf",
    "pattern",
    "properties",
    "readOnly",
    "required",
    "title",
    "type",
    "uniqueItems",
    "writeOnly",
    "xml",
}
SCHEMA_TYPES = {"array", "boolean", "integer", "number", "object", "string"}
COMPOSITION_KEYWORDS = ("allOf", "anyOf", "oneOf")
BOOLEAN_KEYWORDS = ("deprecated", "nullable", "readOnly", "writeOnly")


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
        self._registries: dict[SchemaDirection, Registry[Any]] = {}
        self._operations = self._index_operations(paths)

    @classmethod
    def from_path(cls, path: Path) -> OpenAPIContractCatalog:
        if path.suffix.casefold() in {".md", ".markdown"}:
            raise ContractError(
                "Contract validation requires a full local OpenAPI 3.0.x JSON/YAML "
                "document; Markdown model exports cannot resolve operations."
            )
        try:
            loaded = load_structured_document(path, label="OpenAPI contract")
        except StructuredDocumentError as exc:
            raise ContractError(str(exc)) from exc
        if not isinstance(loaded.value, dict):
            raise ContractError("OpenAPI contract root must be an object.")
        return cls(loaded.value, source=str(path))

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
        request_body = self._resolve_object(operation["requestBody"], label="request body")
        required = request_body.get("required", False)
        if not isinstance(required, bool):
            raise ContractError("OpenAPI requestBody.required must be boolean.")
        schema = self._json_schema(request_body, label="request body", direction="request")
        if not body_supplied:
            if required:
                raise ContractError("The OpenAPI operation requires a JSON request body.")
            return []
        return self._validate(schema, payload, direction="request")

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
        response = self._resolve_object(responses[selected_key], label=f"response {selected_key}")
        schema = self._json_schema(
            response,
            label=f"response {selected_key}",
            direction="response",
        )
        return self._validate(schema, payload, direction="response")

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

    def _json_schema(
        self,
        container: dict[str, Any],
        *,
        label: str,
        direction: SchemaDirection,
    ) -> dict[str, Any]:
        content = container.get("content")
        if not isinstance(content, dict):
            raise ContractError(f"OpenAPI {label} does not define content.")
        media = content.get("application/json")
        if not isinstance(media, dict):
            raise ContractError(f"OpenAPI {label} does not define application/json content.")
        schema = media.get("schema")
        if not isinstance(schema, dict):
            raise ContractError(f"OpenAPI {label} does not define a JSON schema.")
        self._check_schema(schema, seen=set())
        converted = _openapi_schema_to_draft7(
            schema,
            direction=direction,
            directional_property=self._directional_property,
        )
        return cast(dict[str, Any], converted)

    def _check_schema(self, value: Any, *, seen: set[str]) -> None:
        if not isinstance(value, dict):
            raise ContractError("OpenAPI schemas must be objects.")
        unsupported = sorted(
            key for key in value if key not in SCHEMA_KEYWORDS and not key.startswith("x-")
        )
        if unsupported:
            names = ", ".join(unsupported)
            raise ContractError(f"Unsupported OpenAPI 3.0 schema keyword(s): {names}.")

        reference = value.get("$ref")
        if reference is not None:
            if len(value) != 1:
                raise ContractError("OpenAPI schema has conflicting $ref sibling fields.")
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
                self._check_schema(target, seen=seen)
            return

        schema_type = value.get("type")
        if schema_type is not None and (
            not isinstance(schema_type, str) or schema_type not in SCHEMA_TYPES
        ):
            raise ContractError(f"OpenAPI schema has unsupported type: {schema_type!r}.")
        for keyword in BOOLEAN_KEYWORDS:
            if keyword in value and not isinstance(value[keyword], bool):
                raise ContractError(f"OpenAPI schema {keyword} must be boolean.")
        if value.get("nullable") is True and schema_type is None:
            raise ContractError("OpenAPI 3.0 schema nullable requires an explicit type.")
        if value.get("readOnly") is True and value.get("writeOnly") is True:
            raise ContractError("OpenAPI schema cannot be both readOnly and writeOnly.")
        for keyword in ("exclusiveMinimum", "exclusiveMaximum"):
            if keyword in value and not isinstance(value[keyword], bool):
                raise ContractError(f"OpenAPI 3.0 schema {keyword} must be boolean.")
            boundary = "minimum" if keyword == "exclusiveMinimum" else "maximum"
            if value.get(keyword) is True and boundary not in value:
                raise ContractError(f"OpenAPI schema {keyword} requires {boundary}.")
        if schema_type == "array" and "items" not in value:
            raise ContractError("OpenAPI array schemas must define items.")

        properties = value.get("properties")
        if properties is not None:
            if not isinstance(properties, dict):
                raise ContractError("OpenAPI schema properties must be an object.")
            for property_schema in properties.values():
                self._check_schema(property_schema, seen=seen)
        items = value.get("items")
        if items is not None:
            self._check_schema(items, seen=seen)
        additional = value.get("additionalProperties")
        if additional is not None and not isinstance(additional, bool):
            self._check_schema(additional, seen=seen)
        negated = value.get("not")
        if negated is not None:
            self._check_schema(negated, seen=seen)
        for keyword in COMPOSITION_KEYWORDS:
            options = value.get(keyword)
            if options is None:
                continue
            if not isinstance(options, list) or not options:
                raise ContractError(f"OpenAPI schema {keyword} must be a non-empty array.")
            for option in options:
                self._check_schema(option, seen=seen)

    def _directional_property(
        self,
        value: Any,
        keyword: str,
        seen: frozenset[str] = frozenset(),
    ) -> bool:
        if not isinstance(value, dict):
            return False
        if value.get(keyword) is True:
            return True
        reference = value.get("$ref")
        if isinstance(reference, str) and reference.startswith("#/") and reference not in seen:
            return self._directional_property(
                self._resolve_pointer(reference), keyword, seen | {reference}
            )
        for composition in COMPOSITION_KEYWORDS:
            options = value.get(composition)
            if isinstance(options, list) and any(
                self._directional_property(option, keyword, seen) for option in options
            ):
                return True
        return False

    def _registry(self, direction: SchemaDirection) -> Registry[Any]:
        registry = self._registries.get(direction)
        if registry is None:
            validation_document = _openapi_schema_to_draft7(
                self.document,
                direction=direction,
                directional_property=self._directional_property,
            )
            resource = Resource.from_contents(
                validation_document,
                default_specification=DRAFT7,
            )
            registry = Registry().with_resource(CONTRACT_URI, resource)
            self._registries[direction] = registry
        return registry

    def _validate(
        self,
        schema: dict[str, Any],
        payload: Any,
        *,
        direction: SchemaDirection,
    ) -> list[ValidationIssue]:
        try:
            Draft7Validator.check_schema(schema)
            validator = Draft7Validator(
                schema,
                registry=self._registry(direction),
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


def _openapi_schema_to_draft7(
    value: Any,
    *,
    direction: SchemaDirection,
    directional_property: Callable[[Any, str], bool],
) -> Any:
    if isinstance(value, list):
        return [
            _openapi_schema_to_draft7(
                item,
                direction=direction,
                directional_property=directional_property,
            )
            for item in value
        ]
    if not isinstance(value, dict):
        return copy.deepcopy(value)

    converted = {
        key: _openapi_schema_to_draft7(
            item,
            direction=direction,
            directional_property=directional_property,
        )
        for key, item in value.items()
        if key not in {"nullable", "readOnly", "writeOnly"}
    }
    reference = converted.get("$ref")
    if isinstance(reference, str) and reference.startswith("#"):
        converted["$ref"] = CONTRACT_URI + reference

    properties = value.get("properties")
    if isinstance(properties, dict):
        forbidden_keyword = "readOnly" if direction == "request" else "writeOnly"
        forbidden = {
            name
            for name, schema in properties.items()
            if directional_property(schema, forbidden_keyword)
        }
        converted_properties = converted.get("properties")
        if isinstance(converted_properties, dict):
            for name in forbidden:
                converted_properties[name] = False
        required = converted.get("required")
        if isinstance(required, list):
            converted["required"] = [name for name in required if name not in forbidden]

    for keyword, boundary in (
        ("exclusiveMinimum", "minimum"),
        ("exclusiveMaximum", "maximum"),
    ):
        exclusive = converted.get(keyword)
        if isinstance(exclusive, bool):
            converted.pop(keyword)
            if exclusive and boundary in converted:
                converted[keyword] = converted.pop(boundary)

    if value.get("nullable") is True:
        return {"anyOf": [converted, {"type": "null"}]}
    return converted
