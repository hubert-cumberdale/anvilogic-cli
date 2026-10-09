"""Strict, offline loading for operator-controlled JSON and YAML documents."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml
from yaml.constructor import ConstructorError
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, ScalarNode

from anvilogic_cli.json_utils import loads_json

ALIAS_REMEDIATION = (
    "For a trusted local document, expand aliases offline and convert it to JSON, then pass "
    "the JSON path; the CLI will not convert or copy the document."
)


class StructuredDocumentError(ValueError):
    """Raised when a local structured document cannot be loaded safely."""


@dataclass(frozen=True)
class StructuredDocument:
    """A parsed JSON-compatible document and its source format."""

    value: Any
    format_name: str


class StructuredDocumentLoader(yaml.SafeLoader):
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


StructuredDocumentLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", re.IGNORECASE),
    list("tTfF"),
)
StructuredDocumentLoader.add_implicit_resolver(
    "tag:yaml.org,2002:int",
    re.compile(r"^[-+]?(?:[0-9][0-9_]*|0o[0-7_]+|0x[0-9a-fA-F_]+)$"),
    list("-+0123456789"),
)
StructuredDocumentLoader.add_implicit_resolver(
    "tag:yaml.org,2002:float",
    re.compile(
        r"^[-+]?(?:(?:[0-9][0-9_]*\.[0-9_]*|\.[0-9][0-9_]*)"
        r"(?:[eE][-+]?[0-9]+)?|[0-9][0-9_]*[eE][-+]?[0-9]+|"
        r"\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$"
    ),
    list("-+0123456789."),
)


def _construct_yaml12_int(loader: StructuredDocumentLoader, node: ScalarNode) -> int:
    value = loader.construct_scalar(node).replace("_", "")
    sign = -1 if value.startswith("-") else 1
    unsigned = value[1:] if value.startswith(("-", "+")) else value
    if unsigned.startswith("0o"):
        return sign * int(unsigned[2:], 8)
    if unsigned.startswith("0x"):
        return sign * int(unsigned[2:], 16)
    return sign * int(unsigned, 10)


StructuredDocumentLoader.add_constructor("tag:yaml.org,2002:int", _construct_yaml12_int)


def load_structured_document(path: Path, *, label: str) -> StructuredDocument:
    """Load a local JSON/YAML document without aliases, fetching, or persistence."""
    display_label = label if label[:1].isupper() else label.capitalize()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise StructuredDocumentError(f"Could not read {label}: {path}") from exc

    if path.suffix.casefold() in {".yaml", ".yml"}:
        try:
            if any(
                isinstance(event, AliasEvent)
                for event in yaml.parse(text, Loader=StructuredDocumentLoader)
            ):
                raise StructuredDocumentError(
                    f"{display_label} YAML aliases are not supported. {ALIAS_REMEDIATION}"
                )
            value = _normalize_yaml_json(
                yaml.load(text, Loader=StructuredDocumentLoader), label=label
            )
        except StructuredDocumentError:
            raise
        except yaml.YAMLError as exc:
            raise StructuredDocumentError(
                f"{display_label} is not valid YAML: {path}"
            ) from exc
        return StructuredDocument(value=value, format_name="YAML")

    try:
        value = loads_json(text)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise StructuredDocumentError(f"{display_label} is not valid JSON: {path}") from exc
    return StructuredDocument(value=value, format_name="JSON")


def _normalize_yaml_json(
    value: Any,
    *,
    label: str,
    path: str = "$",
    active: set[int] | None = None,
) -> Any:
    """Return an acyclic JSON-compatible tree from safely loaded YAML."""
    display_label = label if label[:1].isupper() else label.capitalize()
    if value is None or isinstance(value, str | bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise StructuredDocumentError(
                f"{display_label} YAML contains a non-finite number at {path}."
            )
        return value
    if isinstance(value, datetime | date):
        return value.isoformat()
    if not isinstance(value, list | dict):
        raise StructuredDocumentError(
            f"{display_label} YAML contains a non-JSON value at {path}: "
            f"{type(value).__name__}."
        )

    ancestors = active if active is not None else set()
    identity = id(value)
    if identity in ancestors:
        raise StructuredDocumentError(f"{display_label} YAML contains a cyclic alias at {path}.")
    ancestors.add(identity)
    try:
        if isinstance(value, list):
            return [
                _normalize_yaml_json(
                    item,
                    label=label,
                    path=f"{path}[{index}]",
                    active=ancestors,
                )
                for index, item in enumerate(value)
            ]
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise StructuredDocumentError(
                    f"{display_label} YAML contains a non-string key at {path}."
                )
            normalized[key] = _normalize_yaml_json(
                item,
                label=label,
                path=f"{path}.{key}",
                active=ancestors,
            )
        return normalized
    finally:
        ancestors.remove(identity)
