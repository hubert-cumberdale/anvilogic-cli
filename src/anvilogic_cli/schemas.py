from __future__ import annotations

import base64
import copy
import json
import math
import re
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

import yaml
from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7
from yaml.constructor import ConstructorError
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, ScalarNode

from anvilogic_cli.errors import ModelCatalogError
from anvilogic_cli.json_utils import loads_json

JSON_BLOCK_RE = re.compile(r"^```json\s*\n(.*?)\n```\s*$", re.MULTILINE | re.DOTALL)
CATALOG_URI = "urn:anvilogic:models"
FORMAT_CHECKER = FormatChecker()


class CatalogSafeLoader(yaml.SafeLoader):
    """Safe loader with YAML 1.2 scalar resolution and duplicate-key rejection."""

    yaml_implicit_resolvers = {
        key: [
            (tag, regex)
            for tag, regex in resolvers
            if tag
            not in {
                "tag:yaml.org,2002:bool",
                "tag:yaml.org,2002:float",
                "tag:yaml.org,2002:int",
                "tag:yaml.org,2002:merge",
                "tag:yaml.org,2002:timestamp",
            }
        ]
        for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        if not isinstance(node, MappingNode):
            raise ConstructorError(
                None, None, f"expected a mapping node, found {node.id}", node.start_mark
            )
        self.flatten_mapping(node)
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as exc:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable key",
                    key_node.start_mark,
                ) from exc
            if duplicate:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


CatalogSafeLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", re.IGNORECASE),
    list("tTfF"),
)
CatalogSafeLoader.add_implicit_resolver(
    "tag:yaml.org,2002:int",
    re.compile(r"^[-+]?(?:[0-9][0-9_]*|0o[0-7_]+|0x[0-9a-fA-F_]+)$"),
    list("-+0123456789"),
)
CatalogSafeLoader.add_implicit_resolver(
    "tag:yaml.org,2002:float",
    re.compile(
        r"^[-+]?(?:(?:[0-9][0-9_]*\.[0-9_]*|\.[0-9][0-9_]*)"
        r"(?:[eE][-+]?[0-9]+)?|[0-9][0-9_]*[eE][-+]?[0-9]+|"
        r"\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$"
    ),
    list("-+0123456789."),
)


def _construct_yaml12_int(loader: CatalogSafeLoader, node: ScalarNode) -> int:
    value = loader.construct_scalar(node).replace("_", "")
    sign = -1 if value.startswith("-") else 1
    unsigned = value[1:] if value.startswith(("-", "+")) else value
    if unsigned.startswith("0o"):
        return sign * int(unsigned[2:], 8)
    if unsigned.startswith("0x"):
        return sign * int(unsigned[2:], 16)
    return sign * int(unsigned, 10)


CatalogSafeLoader.add_constructor("tag:yaml.org,2002:int", _construct_yaml12_int)


def _normalize_yaml_json(value: Any, *, path: str = "$", active: set[int] | None = None) -> Any:
    """Return an acyclic JSON-compatible tree from safely loaded YAML."""
    if value is None or isinstance(value, str | bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ModelCatalogError(f"Model catalog YAML contains a non-finite number at {path}.")
        return value
    if isinstance(value, datetime | date):
        return value.isoformat()
    if not isinstance(value, list | dict):
        raise ModelCatalogError(
            f"Model catalog YAML contains a non-JSON value at {path}: "
            f"{type(value).__name__}."
        )

    ancestors = active if active is not None else set()
    identity = id(value)
    if identity in ancestors:
        raise ModelCatalogError(f"Model catalog YAML contains a cyclic alias at {path}.")
    ancestors.add(identity)
    try:
        if isinstance(value, list):
            return [
                _normalize_yaml_json(item, path=f"{path}[{index}]", active=ancestors)
                for index, item in enumerate(value)
            ]
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ModelCatalogError(
                    f"Model catalog YAML contains a non-string key at {path}."
                )
            normalized[key] = _normalize_yaml_json(
                item, path=f"{path}.{key}", active=ancestors
            )
        return normalized
    finally:
        ancestors.remove(identity)


@FORMAT_CHECKER.checks("byte", raises=(ValueError, TypeError))
def _valid_base64(value: object) -> bool:
    if not isinstance(value, str):
        return True
    base64.b64decode(value, validate=True)
    return True


@FORMAT_CHECKER.checks("date", raises=ValueError)
def _valid_date(value: object) -> bool:
    if not isinstance(value, str):
        return True
    date.fromisoformat(value)
    return True


@FORMAT_CHECKER.checks("date-time", raises=ValueError)
@FORMAT_CHECKER.checks("datetime", raises=ValueError)
def _valid_datetime(value: object) -> bool:
    if not isinstance(value, str):
        return True
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    return "T" in value and parsed.tzinfo is not None


@FORMAT_CHECKER.checks("int32")
def _valid_int32(value: object) -> bool:
    return not isinstance(value, int) or isinstance(value, bool) or -(2**31) <= value < 2**31


@FORMAT_CHECKER.checks("int64")
def _valid_int64(value: object) -> bool:
    return not isinstance(value, int) or isinstance(value, bool) or -(2**63) <= value < 2**63


@FORMAT_CHECKER.checks("float")
@FORMAT_CHECKER.checks("double")
def _valid_float(value: object) -> bool:
    return (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or math.isfinite(value)
    )


@FORMAT_CHECKER.checks("uri")
def _valid_uri(value: object) -> bool:
    if not isinstance(value, str):
        return True
    parsed = urlsplit(value)
    return bool(parsed.scheme)


@dataclass(frozen=True)
class ValidationIssue:
    path: str
    message: str
    validator: str


class ModelCatalog:
    """Search, resolve, sample, and validate exported OpenAPI component schemas."""

    def __init__(
        self,
        schemas: dict[str, dict[str, Any]],
        *,
        version: str = "unknown",
        source: str = "unknown",
    ) -> None:
        if not schemas:
            raise ModelCatalogError("Model catalog does not contain any schemas.")
        invalid_names = [name for name in schemas if not isinstance(name, str)]
        if invalid_names:
            raise ModelCatalogError("Schema names must be strings.")
        malformed = [name for name, schema in schemas.items() if not isinstance(schema, dict)]
        if malformed:
            raise ModelCatalogError(f"Schemas must be JSON objects: {', '.join(malformed[:5])}")
        self.schemas = dict(sorted(schemas.items(), key=lambda item: str(item[0]).casefold()))
        self.version = version
        self.source = source
        self.document: dict[str, Any] = {
            "openapi": "3.0.0",
            "info": {"title": "Anvilogic exported models", "version": version},
            "components": {"schemas": self.schemas},
        }
        resource = Resource.from_contents(self.document, default_specification=DRAFT7)
        self._registry = Registry().with_resource(CATALOG_URI, resource)

    @classmethod
    def from_path(cls, path: Path) -> ModelCatalog:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ModelCatalogError(f"Could not read model catalog: {path}") from exc
        if path.suffix.casefold() in {".md", ".markdown"}:
            return cls.from_markdown(text, source=str(path))
        if path.suffix.casefold() in {".yaml", ".yml"}:
            try:
                if any(
                    isinstance(event, AliasEvent)
                    for event in yaml.parse(text, Loader=CatalogSafeLoader)
                ):
                    raise ModelCatalogError("Model catalog YAML aliases are not supported.")
                payload = _normalize_yaml_json(yaml.load(text, Loader=CatalogSafeLoader))
            except yaml.YAMLError as exc:
                raise ModelCatalogError(f"Model catalog is not valid YAML: {path}") from exc
            if not isinstance(payload, dict):
                raise ModelCatalogError("Model catalog YAML root must be an object.")
            return cls._from_mapping(payload, source=str(path), format_name="YAML")
        try:
            payload = loads_json(text)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ModelCatalogError(f"Model catalog is not valid JSON: {path}") from exc
        if not isinstance(payload, dict):
            raise ModelCatalogError("Model catalog JSON root must be an object.")
        return cls._from_mapping(payload, source=str(path), format_name="JSON")

    @classmethod
    def from_markdown(cls, text: str, *, source: str = "models.md") -> ModelCatalog:
        schemas: dict[str, dict[str, Any]] = {}
        versions: set[str] = set()
        blocks = JSON_BLOCK_RE.findall(text)
        if not blocks:
            raise ModelCatalogError("Markdown model export contains no fenced JSON blocks.")
        for block_number, block in enumerate(blocks, start=1):
            try:
                payload = loads_json(block)
                components = payload["components"]["schemas"]
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                raise ModelCatalogError(
                    f"Markdown JSON block {block_number} is not an OpenAPI schema fragment."
                ) from exc
            if not isinstance(components, dict) or not components:
                raise ModelCatalogError(
                    f"Markdown JSON block {block_number} has no component schemas."
                )
            version = payload.get("info", {}).get("version")
            if isinstance(version, str):
                versions.add(version)
            for name, schema in components.items():
                if not isinstance(name, str) or not isinstance(schema, dict):
                    raise ModelCatalogError(
                        f"Markdown JSON block {block_number} contains an invalid schema."
                    )
                previous = schemas.get(name)
                if previous is not None and previous != schema:
                    raise ModelCatalogError(f"Conflicting definitions found for model '{name}'.")
                schemas[name] = schema
        version_label = ", ".join(sorted(versions)) if versions else "unknown"
        return cls(schemas, version=version_label, source=source)

    @classmethod
    def _from_mapping(
        cls, payload: dict[str, Any], *, source: str, format_name: str
    ) -> ModelCatalog:
        components = payload.get("components")
        if isinstance(components, dict):
            schemas = components.get("schemas")
        else:
            schemas = payload.get("schemas")
        if not isinstance(schemas, dict):
            raise ModelCatalogError(
                f"Model catalog {format_name} must contain components.schemas."
            )
        info = payload.get("info")
        version = info.get("version", "unknown") if isinstance(info, dict) else "unknown"
        return cls(schemas, version=str(version), source=source)

    def names(self, query: str | None = None) -> list[str]:
        if not query:
            return list(self.schemas)
        needle = query.casefold()
        matches: list[str] = []
        for name, schema in self.schemas.items():
            searchable = [name, str(schema.get("description", ""))]
            properties = schema.get("properties")
            if isinstance(properties, dict):
                searchable.extend(str(key) for key in properties)
            if needle in " ".join(searchable).casefold():
                matches.append(name)
        return matches

    def get(self, name: str) -> dict[str, Any]:
        schema = self.schemas.get(name)
        if schema is None:
            candidates = [
                candidate
                for candidate in self.schemas
                if candidate.casefold() == name.casefold()
            ]
            if len(candidates) == 1:
                schema = self.schemas[candidates[0]]
        if schema is None:
            suggestions = self.names(name)[:5]
            suffix = f" Similar models: {', '.join(suggestions)}." if suggestions else ""
            raise ModelCatalogError(f"Unknown model '{name}'.{suffix}")
        return copy.deepcopy(schema)

    def resolved(self, name: str) -> dict[str, Any]:
        return cast(dict[str, Any], self._resolve(self.get(name), stack=()))

    def _resolve(self, value: Any, *, stack: tuple[str, ...]) -> Any:
        if isinstance(value, list):
            return [self._resolve(item, stack=stack) for item in value]
        if not isinstance(value, dict):
            return copy.deepcopy(value)
        reference = value.get("$ref")
        if isinstance(reference, str) and reference.startswith("#/components/schemas/"):
            model_name = reference.rsplit("/", 1)[-1]
            if model_name not in self.schemas:
                raise ModelCatalogError(f"Model '{model_name}' referenced by schema is missing.")
            if model_name in stack:
                return {"$ref": reference, "x-anvilogic-recursive": True}
            resolved = self._resolve(self.schemas[model_name], stack=(*stack, model_name))
            siblings = {key: item for key, item in value.items() if key != "$ref"}
            if siblings:
                if not isinstance(resolved, dict):
                    return resolved
                resolved.update(self._resolve(siblings, stack=stack))
            return resolved
        return {key: self._resolve(item, stack=stack) for key, item in value.items()}

    def sample(self, name: str, *, all_fields: bool = False) -> Any:
        return self._sample(self.get(name), all_fields=all_fields, stack=(name,))

    def _sample(self, schema: dict[str, Any], *, all_fields: bool, stack: tuple[str, ...]) -> Any:
        if "example" in schema:
            return copy.deepcopy(schema["example"])
        if "default" in schema:
            return copy.deepcopy(schema["default"])
        if "const" in schema:
            return copy.deepcopy(schema["const"])
        enum = schema.get("enum")
        if isinstance(enum, list) and enum:
            return copy.deepcopy(enum[0])
        reference = schema.get("$ref")
        if isinstance(reference, str) and reference.startswith("#/components/schemas/"):
            model_name = reference.rsplit("/", 1)[-1]
            if model_name in stack:
                return None
            target = self.schemas.get(model_name)
            if target is None:
                raise ModelCatalogError(f"Model '{model_name}' referenced by schema is missing.")
            return self._sample(target, all_fields=all_fields, stack=(*stack, model_name))
        all_of = schema.get("allOf")
        if isinstance(all_of, list):
            combined: dict[str, Any] = {}
            for option in all_of:
                if isinstance(option, dict):
                    value = self._sample(option, all_fields=all_fields, stack=stack)
                    if isinstance(value, dict):
                        combined.update(value)
            return combined
        for keyword in ("oneOf", "anyOf"):
            options = schema.get(keyword)
            if isinstance(options, list):
                viable = [
                    option
                    for option in options
                    if isinstance(option, dict) and option.get("type") != "null"
                ]
                if viable:
                    return self._sample(viable[0], all_fields=all_fields, stack=stack)
        schema_type = schema.get("type")
        if schema_type == "object" or "properties" in schema:
            properties = schema.get("properties", {})
            required = set(schema.get("required", []))
            if not isinstance(properties, dict):
                return {}
            selected = properties if all_fields else {
                key: value for key, value in properties.items() if key in required
            }
            return {
                key: self._sample(value, all_fields=all_fields, stack=stack)
                for key, value in selected.items()
                if isinstance(value, dict)
            }
        if schema_type == "array":
            item_schema = schema.get("items")
            if isinstance(item_schema, dict):
                return [self._sample(item_schema, all_fields=all_fields, stack=stack)]
            return []
        if schema_type == "boolean":
            return False
        if schema_type == "integer":
            return int(schema.get("minimum", 0))
        if schema_type == "number":
            return float(schema.get("minimum", 0))
        if schema_type == "null":
            return None
        fmt = schema.get("format")
        examples = {
            "date": "1970-01-01",
            "date-time": "1970-01-01T00:00:00Z",
            "email": "user@example.com",
            "hostname": "example.com",
            "ipv4": "192.0.2.1",
            "ipv6": "2001:db8::1",
            "uri": "https://example.com",
            "uuid": "00000000-0000-0000-0000-000000000000",
        }
        min_length = schema.get("minLength", 0)
        placeholder = examples.get(str(fmt), "string")
        if isinstance(min_length, int) and len(placeholder) < min_length:
            placeholder += "x" * (min_length - len(placeholder))
        return placeholder

    def validate(self, name: str, instance: Any) -> list[ValidationIssue]:
        canonical_name = next(
            (
                candidate
                for candidate in self.schemas
                if candidate.casefold() == name.casefold()
            ),
            name,
        )
        self.get(canonical_name)
        pointer_name = canonical_name.replace("~", "~0").replace("/", "~1")
        validator = Draft7Validator(
            {"$ref": f"{CATALOG_URI}#/components/schemas/{pointer_name}"},
            registry=self._registry,
            format_checker=FORMAT_CHECKER,
        )
        issues: list[ValidationIssue] = []
        for error in sorted(validator.iter_errors(instance), key=lambda item: list(item.path)):
            path = "$"
            for part in error.absolute_path:
                path += f"[{part}]" if isinstance(part, int) else f".{part}"
            issues.append(
                ValidationIssue(path=path, message=error.message, validator=str(error.validator))
            )
        return issues

    def stats(self) -> dict[str, Any]:
        enums = sum(1 for schema in self.schemas.values() if "enum" in schema)
        objects = sum(
            1
            for schema in self.schemas.values()
            if schema.get("type") == "object" or "properties" in schema
        )
        return {
            "models": len(self.schemas),
            "objects": objects,
            "enums": enums,
            "version": self.version,
            "source": self.source,
        }
