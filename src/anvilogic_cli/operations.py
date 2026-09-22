from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date
from importlib.resources import files
from typing import Any
from urllib.parse import quote

from anvilogic_cli.errors import AnvilogicError
from anvilogic_cli.json_utils import loads_json

OPERATION_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
PATH_PARAMETER_RE = re.compile(r"{([a-zA-Z][a-zA-Z0-9_]*)}")
VALID_RISKS = {"read", "write", "bulk", "destructive"}
VALID_CONFIDENCE = {"confirmed", "publicly-documented"}
VALID_EVIDENCE = {"distilled-private-traffic", "public-openapi"}


class OperationCatalogError(AnvilogicError):
    """Raised when the bundled reviewed-operation registry is invalid."""


@dataclass(frozen=True)
class Operation:
    operation_id: str
    method: str
    path: str
    query_params: tuple[str, ...]
    request_body: bool
    risk: str
    confidence: str
    evidence: tuple[str, ...]
    last_verified: str

    @property
    def path_params(self) -> tuple[str, ...]:
        return tuple(PATH_PARAMETER_RE.findall(self.path))

    @property
    def requires_apply(self) -> bool:
        return self.method not in {"GET", "HEAD", "OPTIONS"}

    def render_path(self, values: list[tuple[str, str]]) -> str:
        supplied: dict[str, str] = {}
        for name, value in values:
            if name in supplied:
                raise ValueError(f"Duplicate path parameter: {name}")
            if not value:
                raise ValueError(f"Path parameter '{name}' cannot be empty.")
            supplied[name] = value
        expected = set(self.path_params)
        missing = expected - supplied.keys()
        unknown = supplied.keys() - expected
        if missing:
            raise ValueError("Missing path parameter(s): " + ", ".join(sorted(missing)))
        if unknown:
            raise ValueError("Unknown path parameter(s): " + ", ".join(sorted(unknown)))
        rendered = self.path
        for name, value in supplied.items():
            rendered = rendered.replace("{" + name + "}", quote(value, safe=""))
        return rendered

    def validate_query(self, values: list[tuple[str, str]]) -> None:
        allowed = set(self.query_params)
        unknown = sorted({name for name, _value in values} - allowed)
        if unknown:
            raise ValueError(
                "Unreviewed query parameter(s) for this operation: " + ", ".join(unknown)
            )

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.operation_id,
            "method": self.method,
            "path": self.path,
            "path_params": list(self.path_params),
            "query_params": list(self.query_params),
            "request_body": self.request_body,
            "risk": self.risk,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "last_verified": self.last_verified,
            "requires_apply": self.requires_apply,
        }


class OperationCatalog:
    def __init__(self, operations: list[Operation], source: dict[str, Any]) -> None:
        self._operations = tuple(sorted(operations, key=lambda item: item.operation_id))
        self._by_id = {item.operation_id.casefold(): item for item in self._operations}
        self.source = source

    @classmethod
    def bundled(cls) -> OperationCatalog:
        resource = files("anvilogic_cli").joinpath("operations.json")
        try:
            payload = loads_json(resource.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise OperationCatalogError(
                "The bundled operation catalog could not be loaded."
            ) from exc
        return cls.from_dict(payload)

    @classmethod
    def from_dict(cls, payload: object) -> OperationCatalog:
        if not isinstance(payload, dict):
            raise OperationCatalogError("The operation registry must be a JSON object.")
        if payload.get("version") != 3:
            raise OperationCatalogError("The operation registry version is unsupported.")
        raw_operations = payload.get("operations")
        source = payload.get("source")
        if not isinstance(raw_operations, list) or not isinstance(source, dict):
            raise OperationCatalogError("The operation registry has an invalid shape.")
        _validate_source(source)
        operations = [_parse_operation(item) for item in raw_operations]
        identifiers = [item.operation_id.casefold() for item in operations]
        if len(identifiers) != len(set(identifiers)):
            raise OperationCatalogError("The operation registry has duplicate IDs.")
        return cls(operations, source)

    def names(self, search: str | None = None) -> list[str]:
        if not search:
            return [item.operation_id for item in self._operations]
        term = search.casefold()
        return [
            item.operation_id
            for item in self._operations
            if term in item.operation_id.casefold() or term in item.path.casefold()
        ]

    def matching(self, search: str | None = None) -> list[Operation]:
        names = set(self.names(search))
        return [item for item in self._operations if item.operation_id in names]

    def get(self, operation_id: str) -> Operation:
        operation = self._by_id.get(operation_id.casefold())
        if operation is None:
            raise OperationCatalogError(f"Unknown reviewed operation: {operation_id}")
        return operation

    def stats(self) -> dict[str, Any]:
        return {
            "operations": len(self._operations),
            "methods": {
                method: sum(item.method == method for item in self._operations)
                for method in sorted({item.method for item in self._operations})
            },
            "risks": _count_values(item.risk for item in self._operations),
            "confidence": _count_values(item.confidence for item in self._operations),
            "evidence": {
                evidence: sum(evidence in item.evidence for item in self._operations)
                for evidence in sorted(VALID_EVIDENCE)
            },
            "source": self.source,
        }


def _count_values(values: Iterable[str]) -> dict[str, int]:
    materialized = tuple(values)
    return {value: materialized.count(value) for value in sorted(set(materialized))}


def _validate_source(source: dict[str, Any]) -> None:
    expected = {
        "kind": "distilled_operation_fact_registry",
        "contract_status": "public_openapi_authoritative_for_documented_wire_facts",
        "private_evidence_provenance": "distilled private traffic",
        "private_evidence_retained": False,
        "public_openapi": {
            "retrieved": "2026-09-22",
            "sha256": "0e96b604ed12ef29007b38f209855f9a5577ae198ee330fa06692ddf876f884c",
            "title": "Search API Manual Documentation",
            "url": (
                "https://openapi.gitbook.com/o/j9GRuNhp1hds6GRILKW4/spec/"
                "anvilogic-combined-apis.yaml"
            ),
            "version": "8.1.0.0",
        },
    }
    if source != expected:
        raise OperationCatalogError("The operation registry has invalid source metadata.")


def _parse_operation(raw: object) -> Operation:
    if not isinstance(raw, dict):
        raise OperationCatalogError("Every operation must be a JSON object.")
    expected_fields = {
        "id",
        "method",
        "path",
        "query_params",
        "request_body",
        "risk",
        "confidence",
        "evidence",
        "last_verified",
    }
    if set(raw) != expected_fields:
        raise OperationCatalogError("An operation has missing or unsupported metadata fields.")
    operation_id = raw.get("id")
    method = raw.get("method")
    path = raw.get("path")
    query_params = raw.get("query_params", [])
    request_body = raw.get("request_body")
    risk = raw.get("risk")
    confidence = raw.get("confidence")
    evidence = raw.get("evidence")
    last_verified = raw.get("last_verified")
    if not isinstance(operation_id, str) or not OPERATION_ID_RE.fullmatch(operation_id):
        raise OperationCatalogError("An operation has an invalid ID.")
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        raise OperationCatalogError(f"Operation '{operation_id}' has an invalid method.")
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or "?" in path
        or "#" in path
        or ".." in path.split("/")
    ):
        raise OperationCatalogError(f"Operation '{operation_id}' has an invalid path.")
    if not isinstance(query_params, list) or not all(
        isinstance(item, str) and item for item in query_params
    ):
        raise OperationCatalogError(f"Operation '{operation_id}' has invalid query parameters.")
    if len(query_params) != len(set(query_params)):
        raise OperationCatalogError(f"Operation '{operation_id}' repeats a query parameter.")
    if not isinstance(request_body, bool):
        raise OperationCatalogError(f"Operation '{operation_id}' has an invalid body marker.")
    if risk not in VALID_RISKS:
        raise OperationCatalogError(f"Operation '{operation_id}' has an invalid risk.")
    if confidence not in VALID_CONFIDENCE:
        raise OperationCatalogError(f"Operation '{operation_id}' has invalid confidence.")
    if (
        not isinstance(evidence, list)
        or not evidence
        or not all(item in VALID_EVIDENCE for item in evidence)
        or len(evidence) != len(set(evidence))
    ):
        raise OperationCatalogError(f"Operation '{operation_id}' has invalid evidence metadata.")
    if "public-openapi" in evidence and confidence != "publicly-documented":
        raise OperationCatalogError(
            f"Operation '{operation_id}' has inconsistent public confidence."
        )
    if "public-openapi" not in evidence and confidence != "confirmed":
        raise OperationCatalogError(
            f"Operation '{operation_id}' has inconsistent private confidence."
        )
    if not isinstance(last_verified, str):
        raise OperationCatalogError(f"Operation '{operation_id}' has invalid last-verified date.")
    try:
        date.fromisoformat(last_verified)
    except ValueError as exc:
        raise OperationCatalogError(
            f"Operation '{operation_id}' has invalid last-verified date."
        ) from exc
    return Operation(
        operation_id=operation_id,
        method=method,
        path=path,
        query_params=tuple(query_params),
        request_body=request_body,
        risk=risk,
        confidence=confidence,
        evidence=tuple(evidence),
        last_verified=last_verified,
    )
