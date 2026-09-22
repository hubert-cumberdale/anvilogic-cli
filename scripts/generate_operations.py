#!/usr/bin/env python3
"""Generate the distilled operation registry from the pinned public OpenAPI document."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / "src" / "anvilogic_cli" / "operations.json"

OPENAPI_URL = (
    "https://openapi.gitbook.com/o/j9GRuNhp1hds6GRILKW4/spec/"
    "anvilogic-combined-apis.yaml"
)
OPENAPI_FILENAME = "anvilogic-combined-apis.yaml"
OPENAPI_TITLE = "Search API Manual Documentation"
OPENAPI_VERSION = "8.1.0.0"
OPENAPI_RETRIEVED = "2026-09-22"
OPENAPI_SHA256 = "0e96b604ed12ef29007b38f209855f9a5577ae198ee330fa06692ddf876f884c"
PRIVATE_SEED_SHA256 = "1beaf8f654e024350053c2051a788f31ee5778237835d8b8921ff3d0303d5081"
EXPECTED_METHODS = {"DELETE": 18, "GET": 140, "PATCH": 17, "POST": 132, "PUT": 10}
EXPECTED_PUBLIC_OPERATIONS = 317
EXPECTED_PRIVATE_EVIDENCE_OPERATIONS = 74
EXPECTED_OVERLAPPING_OPERATIONS = 47
EXPECTED_UNION_METHODS = {"DELETE": 18, "GET": 155, "PATCH": 17, "POST": 144, "PUT": 10}
EXPECTED_UNION_OPERATIONS = 344

HTTP_METHODS = {method.casefold() for method in EXPECTED_METHODS}
PRIVATE_EVIDENCE = "distilled-private-traffic"
PUBLIC_EVIDENCE = "public-openapi"
PATH_PARAMETER_RE = re.compile(r"^\{([A-Za-z][A-Za-z0-9_]*)\}$")


def load_openapi(source: bytes) -> dict[str, Any]:
    """Safely parse an OpenAPI YAML byte string and require an object root."""
    try:
        document = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise ValueError(f"OpenAPI source is not valid YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError("OpenAPI source root must be an object.")
    return document


def verify_pinned_digest(source: bytes) -> None:
    """Reject bytes other than the exact reviewed public document before parsing."""
    digest = hashlib.sha256(source).hexdigest()
    if digest != OPENAPI_SHA256:
        raise ValueError(f"OpenAPI SHA-256 is {digest}; expected {OPENAPI_SHA256}.")


def verify_pinned_metadata(document: dict[str, Any]) -> None:
    """Verify the identifying metadata in the checksum-pinned document."""
    if document.get("openapi") != "3.0.0":
        raise ValueError("OpenAPI source must declare OpenAPI 3.0.0.")
    info = document.get("info")
    if not isinstance(info, dict):
        raise ValueError("OpenAPI source must contain an info object.")
    if info.get("title") != OPENAPI_TITLE:
        raise ValueError(f"OpenAPI title must be {OPENAPI_TITLE!r}.")
    if info.get("version") != OPENAPI_VERSION:
        raise ValueError(f"OpenAPI version must be {OPENAPI_VERSION!r}.")


def verify_pinned_source(source: bytes, document: dict[str, Any]) -> None:
    """Fail closed unless the exact reviewed public document was supplied."""
    verify_pinned_digest(source)
    verify_pinned_metadata(document)


def load_private_seed(source: bytes) -> dict[str, Any]:
    """Load only the exact immutable v0.3.2 private-fact seed."""
    digest = hashlib.sha256(source).hexdigest()
    if digest != PRIVATE_SEED_SHA256:
        raise ValueError(
            f"Private seed SHA-256 is {digest}; expected {PRIVATE_SEED_SHA256}."
        )
    try:
        payload = json.loads(source)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Private seed is not valid UTF-8 JSON.") from exc
    if not isinstance(payload, dict) or payload.get("version") != 2:
        raise ValueError("Private seed must be the v0.3.2 version 2 registry.")
    return payload


def normalize_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or "//" in value
        or "?" in value
        or "#" in value
        or ".." in value.split("/")
    ):
        raise ValueError(f"Invalid OpenAPI path: {value!r}.")
    return value.rstrip("/") or "/"


def _slug(value: str) -> str:
    with_boundaries = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", value)
    return re.sub(r"[^A-Za-z0-9]+", "-", with_boundaries).strip("-").casefold()


def operation_id(method: str, path: str) -> str:
    """Derive a stable ID, representing parameter segments as ``by-<name>``."""
    segments: list[str] = []
    for raw_segment in path.strip("/").split("/"):
        parameter = PATH_PARAMETER_RE.fullmatch(raw_segment)
        segment = f"by-{_slug(parameter.group(1))}" if parameter else _slug(raw_segment)
        if not segment:
            raise ValueError(f"Cannot derive an operation ID from path {path!r}.")
        segments.append(segment)
    return ".".join([method.casefold(), *segments])


def _query_names(path_item: dict[str, Any], operation: dict[str, Any]) -> list[str]:
    query_names: set[str] = set()
    path_parameters = path_item.get("parameters", [])
    operation_parameters = operation.get("parameters", [])
    if not isinstance(path_parameters, list) or not isinstance(operation_parameters, list):
        raise ValueError("OpenAPI parameters must be arrays.")
    parameters = [*path_parameters, *operation_parameters]
    for parameter in parameters:
        if not isinstance(parameter, dict):
            raise ValueError("OpenAPI parameter entries must be objects.")
        if "$ref" in parameter:
            raise ValueError("Referenced OpenAPI parameters are not supported by the distiller.")
        if parameter.get("in") != "query":
            continue
        name = parameter.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("OpenAPI query parameters must have non-empty string names.")
        query_names.add(name)
    return sorted(query_names)


def _private_seed_operations(payload: object) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("operations"), list):
        raise ValueError("Existing registry must contain an operations array.")
    version = payload.get("version")
    if version not in {2, 3}:
        raise ValueError("Existing registry version is unsupported.")
    private: list[dict[str, Any]] = []
    for raw in payload["operations"]:
        if not isinstance(raw, dict):
            raise ValueError("Existing registry operations must be objects.")
        if version == 2:
            is_private = raw.get("evidence_class") == PRIVATE_EVIDENCE
        else:
            evidence = raw.get("evidence")
            is_private = isinstance(evidence, list) and PRIVATE_EVIDENCE in evidence
        if is_private:
            private.append(raw)
    return private


def _seed_value(raw: dict[str, Any], field: str, expected_type: type[Any]) -> Any:
    value = raw.get(field)
    if not isinstance(value, expected_type):
        raise ValueError(f"Existing registry operation has invalid {field!r} metadata.")
    return value


def build_registry(
    document: dict[str, Any], existing_registry: object
) -> dict[str, Any]:
    """Build the public/private operation union without retaining schema bodies."""
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise ValueError("OpenAPI source must contain a paths object.")

    private_operations = _private_seed_operations(existing_registry)
    private_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in private_operations:
        method = _seed_value(raw, "method", str).upper()
        path = normalize_path(_seed_value(raw, "path", str))
        key = (method, path)
        if key in private_by_key:
            raise ValueError(f"Existing registry repeats {method} {path}.")
        private_by_key[key] = raw

    generated: list[dict[str, Any]] = []
    public_keys: set[tuple[str, str]] = set()
    for raw_path, raw_path_item in paths.items():
        path = normalize_path(raw_path)
        if not isinstance(raw_path_item, dict):
            raise ValueError(f"OpenAPI path item for {path!r} must be an object.")
        for raw_method, raw_operation in raw_path_item.items():
            method = str(raw_method).casefold()
            if method not in HTTP_METHODS:
                continue
            if not isinstance(raw_operation, dict):
                raise ValueError(f"OpenAPI operation {method.upper()} {path} must be an object.")
            key = (method.upper(), path)
            if key in public_keys:
                raise ValueError(f"OpenAPI source repeats {key[0]} {path}.")
            public_keys.add(key)
            private = private_by_key.get(key)
            public_query = _query_names(raw_path_item, raw_operation)
            if private is None:
                identifier = operation_id(key[0], path)
                query_params = public_query
                request_body = "requestBody" in raw_operation
                evidence = [PUBLIC_EVIDENCE]
                risk = (
                    "read"
                    if key[0] == "GET"
                    else "destructive"
                    if key[0] == "DELETE"
                    else "write"
                )
            else:
                identifier = _seed_value(private, "id", str)
                raw_query = private.get("query_params")
                if not isinstance(raw_query, list) or not all(
                    isinstance(item, str) and item for item in raw_query
                ):
                    raise ValueError(
                        f"Existing operation {identifier!r} has invalid query metadata."
                    )
                query_params = sorted(set(raw_query) | set(public_query))
                request_body = _seed_value(
                    private, "request_body", bool
                ) or "requestBody" in raw_operation
                evidence = [PUBLIC_EVIDENCE, PRIVATE_EVIDENCE]
                risk = _seed_value(private, "risk", str)
            generated.append(
                {
                    "confidence": "publicly-documented",
                    "evidence": evidence,
                    "id": identifier,
                    "last_verified": OPENAPI_RETRIEVED,
                    "method": key[0],
                    "path": path,
                    "query_params": query_params,
                    "request_body": request_body,
                    "risk": risk,
                }
            )

    for key, private in private_by_key.items():
        if key in public_keys:
            continue
        identifier = _seed_value(private, "id", str)
        raw_query = private.get("query_params")
        if not isinstance(raw_query, list) or not all(
            isinstance(item, str) and item for item in raw_query
        ):
            raise ValueError(f"Existing operation {identifier!r} has invalid query metadata.")
        generated.append(
            {
                "confidence": "confirmed",
                "evidence": [PRIVATE_EVIDENCE],
                "id": identifier,
                "last_verified": _seed_value(private, "last_verified", str),
                "method": key[0],
                "path": key[1],
                "query_params": list(raw_query),
                "request_body": _seed_value(private, "request_body", bool),
                "risk": _seed_value(private, "risk", str),
            }
        )

    identifiers: dict[str, tuple[str, str]] = {}
    for operation in generated:
        folded = operation["id"].casefold()
        key = (operation["method"], operation["path"])
        if folded in identifiers:
            previous = identifiers[folded]
            raise ValueError(
                f"Operation ID collision for {operation['id']!r}: "
                f"{previous[0]} {previous[1]} and {key[0]} {key[1]}."
            )
        identifiers[folded] = key

    return {
        "operations": sorted(generated, key=lambda item: item["id"]),
        "source": {
            "contract_status": "public_openapi_authoritative_for_documented_wire_facts",
            "kind": "distilled_operation_fact_registry",
            "private_evidence_provenance": "distilled private traffic",
            "private_evidence_retained": False,
            "public_openapi": {
                "retrieved": OPENAPI_RETRIEVED,
                "sha256": OPENAPI_SHA256,
                "title": OPENAPI_TITLE,
                "url": OPENAPI_URL,
                "version": OPENAPI_VERSION,
            },
        },
        "version": 3,
    }


def validate_public_counts(registry: dict[str, Any]) -> None:
    public = [
        operation
        for operation in registry["operations"]
        if PUBLIC_EVIDENCE in operation["evidence"]
    ]
    counts = dict(sorted(Counter(operation["method"] for operation in public).items()))
    if len(public) != EXPECTED_PUBLIC_OPERATIONS:
        raise ValueError(
            f"OpenAPI registry contains {len(public)} public operations; "
            f"expected {EXPECTED_PUBLIC_OPERATIONS}."
        )
    if counts != EXPECTED_METHODS:
        raise ValueError(f"OpenAPI method totals are {counts}; expected {EXPECTED_METHODS}.")
    private = [
        operation
        for operation in registry["operations"]
        if PRIVATE_EVIDENCE in operation["evidence"]
    ]
    overlap = [
        operation for operation in public if PRIVATE_EVIDENCE in operation["evidence"]
    ]
    if len(private) != EXPECTED_PRIVATE_EVIDENCE_OPERATIONS:
        raise ValueError(
            f"Operation registry contains {len(private)} private-evidence operations; "
            f"expected {EXPECTED_PRIVATE_EVIDENCE_OPERATIONS}."
        )
    if len(overlap) != EXPECTED_OVERLAPPING_OPERATIONS:
        raise ValueError(
            f"Operation registry contains {len(overlap)} evidence overlaps; "
            f"expected {EXPECTED_OVERLAPPING_OPERATIONS}."
        )
    union_counts = dict(
        sorted(Counter(operation["method"] for operation in registry["operations"]).items())
    )
    if len(registry["operations"]) != EXPECTED_UNION_OPERATIONS:
        raise ValueError(
            f"Operation union contains {len(registry['operations'])} operations; "
            f"expected {EXPECTED_UNION_OPERATIONS}."
        )
    if union_counts != EXPECTED_UNION_METHODS:
        raise ValueError(
            f"Operation union method totals are {union_counts}; "
            f"expected {EXPECTED_UNION_METHODS}."
        )


def render_registry(registry: dict[str, Any]) -> bytes:
    return (json.dumps(registry, indent=2, sort_keys=True) + "\n").encode("utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Local pinned OpenAPI YAML.")
    parser.add_argument("--output", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument(
        "--existing",
        required=True,
        type=Path,
        help="Exact v0.3.2 registry containing the immutable reviewed private facts.",
    )
    parser.add_argument("--check", action="store_true", help="Fail if the output is stale.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(argv or sys.argv[1:])
    try:
        if arguments.existing.resolve() == arguments.output.resolve():
            raise ValueError("Private seed and output must be different files.")
        source = arguments.input.read_bytes()
        verify_pinned_digest(source)
        document = load_openapi(source)
        verify_pinned_metadata(document)
        existing = load_private_seed(arguments.existing.read_bytes())
        registry = build_registry(document, existing)
        validate_public_counts(registry)
        rendered = render_registry(registry)
    except (OSError, ValueError) as exc:
        print(f"Operation generation failed: {exc}", file=sys.stderr)
        return 2
    if arguments.check:
        try:
            current = arguments.output.read_bytes()
        except OSError:
            current = b""
        if current != rendered:
            print("Bundled operation registry is stale.", file=sys.stderr)
            return 1
        print(f"Operation registry is current ({len(registry['operations'])} operations).")
        return 0
    try:
        arguments.output.write_bytes(rendered)
    except OSError as exc:
        print(f"Operation generation failed: {exc}", file=sys.stderr)
        return 2
    print(f"Wrote {len(registry['operations'])} operations to {arguments.output}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
