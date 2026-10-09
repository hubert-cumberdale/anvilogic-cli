"""Aggregate-only offline assessment of sanitized operation contract fixtures."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Literal, TypedDict

from anvilogic_cli.contracts import ContractError, OpenAPIContractCatalog
from anvilogic_cli.documents import StructuredDocumentError, load_structured_document
from anvilogic_cli.errors import ModelValidationError
from anvilogic_cli.operations import OperationCatalog, OperationCatalogError

FIXTURE_FORMAT_VERSION = 1
MAX_FIXTURES = 10_000
Direction = Literal["request", "response"]


class AdoptionError(ModelValidationError):
    """Raised when an adoption input cannot be assessed safely."""


class OutcomeCounts(TypedDict):
    evaluated: int
    valid: int
    invalid: int
    unusable: int


class AdoptionSummary(TypedDict):
    fixture_format_version: int
    total: OutcomeCounts
    request: OutcomeCounts
    response: OutcomeCounts


def assess_contract_fixtures(
    contract_path: Path,
    fixtures_path: Path,
    *,
    operations: OperationCatalog | None = None,
) -> AdoptionSummary:
    """Validate local fixtures and return counts without retaining or echoing payloads."""
    try:
        contract = OpenAPIContractCatalog.from_path(contract_path)
    except ContractError as exc:
        raise AdoptionError("OpenAPI contract could not be loaded safely.") from exc
    fixtures = _load_fixtures(fixtures_path)
    catalog = operations or OperationCatalog.bundled()
    counters: dict[str, Counter[str]] = {
        "total": Counter(),
        "request": Counter(),
        "response": Counter(),
    }

    for fixture in fixtures:
        direction = fixture["direction"]
        outcome = _assess_fixture(contract, catalog, fixture)
        counters[direction][outcome] += 1
        counters[direction]["evaluated"] += 1
        counters["total"][outcome] += 1
        counters["total"]["evaluated"] += 1

    return {
        "fixture_format_version": FIXTURE_FORMAT_VERSION,
        "total": _outcome_counts(counters["total"]),
        "request": _outcome_counts(counters["request"]),
        "response": _outcome_counts(counters["response"]),
    }


def _load_fixtures(path: Path) -> list[dict[str, Any]]:
    try:
        loaded = load_structured_document(path, label="adoption fixture document")
    except StructuredDocumentError as exc:
        raise AdoptionError(str(exc)) from exc
    document = loaded.value
    if not isinstance(document, dict):
        raise AdoptionError("Adoption fixture document root must be an object.")
    if set(document) != {"version", "fixtures"}:
        raise AdoptionError("Adoption fixture document must contain only version and fixtures.")
    version = document.get("version")
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version != FIXTURE_FORMAT_VERSION
    ):
        raise AdoptionError(
            f"Adoption fixture document version must be {FIXTURE_FORMAT_VERSION}."
        )
    fixtures = document.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        raise AdoptionError("Adoption fixture document must contain a non-empty fixtures array.")
    if len(fixtures) > MAX_FIXTURES:
        raise AdoptionError(f"Adoption fixture document exceeds {MAX_FIXTURES} fixtures.")
    return [_validate_fixture(item, index=index) for index, item in enumerate(fixtures, start=1)]


def _validate_fixture(value: Any, *, index: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdoptionError(f"Adoption fixture {index} must be an object.")
    direction = value.get("direction")
    if direction not in {"request", "response"}:
        raise AdoptionError(f"Adoption fixture {index} direction must be request or response.")
    if not isinstance(value.get("operation_id"), str) or not value["operation_id"].strip():
        raise AdoptionError(f"Adoption fixture {index} operation_id must be a non-empty string.")

    if direction == "request":
        allowed = {"direction", "operation_id", "payload"}
    else:
        allowed = {
            "content_type",
            "direction",
            "operation_id",
            "payload",
            "status_code",
        }
        status_code = value.get("status_code")
        if (
            isinstance(status_code, bool)
            or not isinstance(status_code, int)
            or not 100 <= status_code <= 599
        ):
            raise AdoptionError(
                f"Adoption fixture {index} response status_code must be an integer from 100 to 599."
            )
        if not isinstance(value.get("content_type"), str) or not value["content_type"].strip():
            raise AdoptionError(
                f"Adoption fixture {index} response content_type must be a non-empty string."
            )
        if "payload" not in value:
            raise AdoptionError(f"Adoption fixture {index} response must contain payload.")
    if not set(value) <= allowed:
        raise AdoptionError(f"Adoption fixture {index} contains unsupported fields.")
    return value


def _assess_fixture(
    contract: OpenAPIContractCatalog,
    operations: OperationCatalog,
    fixture: dict[str, Any],
) -> str:
    try:
        operation = operations.get(fixture["operation_id"])
        if fixture["direction"] == "request":
            body_supplied = "payload" in fixture
            issues = contract.validate_request(
                operation.method,
                operation.path,
                fixture.get("payload"),
                body_supplied=body_supplied,
                registry_has_body=operation.request_body,
            )
        else:
            issues = contract.validate_response(
                operation.method,
                operation.path,
                fixture["status_code"],
                fixture["content_type"],
                fixture["payload"],
            )
    except (ContractError, OperationCatalogError):
        return "unusable"
    return "invalid" if issues else "valid"


def _outcome_counts(counter: Counter[str]) -> OutcomeCounts:
    return {
        "evaluated": counter["evaluated"],
        "valid": counter["valid"],
        "invalid": counter["invalid"],
        "unusable": counter["unusable"],
    }
