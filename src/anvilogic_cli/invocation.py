"""Request validation and transport orchestration independent of CLI parsing/rendering."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

from anvilogic_cli.client import (
    SAFE_RETRY_METHODS,
    AnvilogicClient,
    RequestPlan,
    prepare_request,
)
from anvilogic_cli.contracts import OpenAPIContractCatalog
from anvilogic_cli.errors import ConfigError, ModelValidationError
from anvilogic_cli.operations import Operation
from anvilogic_cli.schemas import ModelCatalog, ValidationIssue


class PayloadValidationError(ModelValidationError):
    """Raised when a request or response payload does not satisfy its selected schema."""

    def __init__(self, issues: list[ValidationIssue]) -> None:
        super().__init__(f"Payload validation failed with {len(issues)} issue(s).")
        self.issues = issues


@dataclass(frozen=True)
class InvocationRequest:
    method: str
    path: str
    query: list[tuple[str, str]]
    headers: dict[str, str]
    body: Any
    body_supplied: bool
    base_url: str
    api_key: str | None
    auth_scheme: str
    timeout: float
    verify_tls: bool
    dry_run: bool
    apply: bool
    request_model: str | None = None
    response_model: str | None = None
    contract_operation: Operation | None = None
    validate_request: bool = False
    validate_response: bool = False


@dataclass(frozen=True)
class InvocationOutcome:
    plan: RequestPlan
    response: httpx.Response | None
    mutation_preview: bool


def will_send_request(method: str, *, dry_run: bool, apply: bool) -> bool:
    normalized_method = method.strip().upper()
    return not dry_run and (normalized_method in SAFE_RETRY_METHODS or apply)


def execute_invocation(
    request: InvocationRequest,
    *,
    catalog: ModelCatalog | None,
    contract: OpenAPIContractCatalog | None,
    client_class: type[AnvilogicClient] = AnvilogicClient,
    before_send: Callable[[], None] | None = None,
) -> InvocationOutcome:
    """Validate, prepare, and optionally send one request without rendering output."""
    normalized_method = request.method.strip().upper()
    will_send = will_send_request(
        normalized_method,
        dry_run=request.dry_run,
        apply=request.apply,
    )
    if request.validate_response and not will_send:
        raise ValueError(
            "--validate-response requires a request that will be sent; "
            "do not use --dry-run and pass --apply for mutations."
        )
    if will_send and request.auth_scheme != "none" and not request.api_key:
        raise ConfigError("API key is required. Set ANVILOGIC_API_KEY or run auth set.")

    preview_key = request.api_key or "not-configured"
    plan = prepare_request(
        method=normalized_method,
        base_url=request.base_url,
        path=request.path,
        query=request.query,
        custom_headers=request.headers,
        api_key=preview_key,
        auth_scheme=request.auth_scheme,
        json_body=request.body,
    )
    _validate_request_payload(request, catalog=catalog, contract=contract)

    mutation_preview = normalized_method not in SAFE_RETRY_METHODS and not request.dry_run
    if not will_send:
        return InvocationOutcome(
            plan=plan,
            response=None,
            mutation_preview=mutation_preview,
        )

    if before_send is not None:
        before_send()
    with client_class(verify_tls=request.verify_tls, timeout=request.timeout) as client:
        response = client.send(plan)
    _validate_response_payload(request, response, catalog=catalog, contract=contract)
    return InvocationOutcome(
        plan=plan,
        response=response,
        mutation_preview=False,
    )


def _validate_request_payload(
    request: InvocationRequest,
    *,
    catalog: ModelCatalog | None,
    contract: OpenAPIContractCatalog | None,
) -> None:
    if request.request_model:
        if not request.body_supplied:
            raise ValueError("--request-model requires --data or --data-file.")
        if catalog is None:  # pragma: no cover - guarded by the CLI adapter.
            raise AssertionError("request model validation requires a catalog")
        issues = catalog.validate(request.request_model, request.body)
        if issues:
            raise PayloadValidationError(issues)
    if request.validate_request:
        if contract is None or request.contract_operation is None:  # pragma: no cover
            raise AssertionError("operation request validation requires a contract")
        operation = request.contract_operation
        issues = contract.validate_request(
            operation.method,
            operation.path,
            request.body,
            body_supplied=request.body_supplied,
            registry_has_body=operation.request_body,
        )
        if issues:
            raise PayloadValidationError(issues)


def _validate_response_payload(
    request: InvocationRequest,
    response: httpx.Response,
    *,
    catalog: ModelCatalog | None,
    contract: OpenAPIContractCatalog | None,
) -> None:
    if not request.response_model and not request.validate_response:
        return
    try:
        response_payload = response.json()
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        if request.validate_response:
            message = "Response is not valid JSON and cannot be validated."
        else:
            message = "Response is not JSON and cannot be validated."
        raise ModelValidationError(message) from exc
    if request.response_model:
        if catalog is None:  # pragma: no cover - guarded by the CLI adapter.
            raise AssertionError("response model validation requires a catalog")
        issues = catalog.validate(request.response_model, response_payload)
        if issues:
            raise PayloadValidationError(issues)
    if request.validate_response:
        if contract is None or request.contract_operation is None:  # pragma: no cover
            raise AssertionError("operation response validation requires a contract")
        operation = request.contract_operation
        issues = contract.validate_response(
            operation.method,
            operation.path,
            response.status_code,
            response.headers.get("Content-Type", ""),
            response_payload,
        )
        if issues:
            raise PayloadValidationError(issues)
