from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, NoReturn

import typer
from rich import box
from rich.console import Console
from rich.table import Table

from anvilogic_cli import __version__
from anvilogic_cli.cli_threat_scenarios import threat_scenarios_app
from anvilogic_cli.client import (
    SAFE_RETRY_METHODS,
    AnvilogicClient,
    prepare_request,
    redacted_plan,
)
from anvilogic_cli.config import (
    CliConfig,
    effective_api_key,
    effective_auth_scheme,
    effective_base_url,
    effective_models_path,
    load_config,
    normalize_base_url,
    save_config,
    validate_auth_scheme,
    validate_effective_config,
    validate_timeout,
)
from anvilogic_cli.contracts import ContractError, OpenAPIContractCatalog
from anvilogic_cli.errors import AnvilogicError, ExitCode, ModelCatalogError
from anvilogic_cli.io import (
    load_json_input,
    parse_headers,
    parse_pairs,
    response_bytes_and_format,
    write_output,
)
from anvilogic_cli.operations import Operation, OperationCatalog, OperationCatalogError
from anvilogic_cli.schemas import ModelCatalog, ValidationIssue

console = Console()
error_console = Console(stderr=True)


def _typer(**kwargs: Any) -> typer.Typer:
    return typer.Typer(pretty_exceptions_show_locals=False, **kwargs)


app = _typer(
    add_completion=True,
    no_args_is_help=True,
    help="Secure, schema-aware access to the Anvilogic API.",
)
config_app = _typer(no_args_is_help=True, help="Manage local settings.")
auth_app = _typer(no_args_is_help=True, help="Manage the locally stored API key.")
models_app = _typer(no_args_is_help=True, help="Explore and validate exported API models.")
operations_app = _typer(
    no_args_is_help=True,
    help="Explore the reviewed API operation fact registry.",
)
app.add_typer(config_app, name="config")
app.add_typer(auth_app, name="auth")
app.add_typer(models_app, name="models")
app.add_typer(operations_app, name="operations")
app.add_typer(threat_scenarios_app, name="threat-scenarios")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"anvilogic-cli {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    _version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
    models_path: str | None = typer.Option(
        None,
        "--models-path",
        metavar="PATH",
        help="Caller-supplied Markdown export or local OpenAPI JSON/YAML document.",
    ),
) -> None:
    ctx.ensure_object(dict)
    ctx.obj["models_path"] = models_path


def _load_config_or_exit() -> CliConfig:
    try:
        return load_config()
    except AnvilogicError as exc:
        _abort(exc)


def _catalog(ctx: typer.Context) -> ModelCatalog:
    try:
        override = effective_models_path(ctx.obj.get("models_path"))
        if override is None:
            raise ModelCatalogError(
                "A model catalog is required. Pass --models-path or set "
                "ANVILOGIC_MODELS_PATH."
            )
        return ModelCatalog.from_path(override)
    except AnvilogicError as exc:
        _abort(exc)


def _contract_catalog(ctx: typer.Context) -> OpenAPIContractCatalog:
    try:
        override = effective_models_path(ctx.obj.get("models_path"))
        if override is None:
            raise ContractError(
                "Operation contract validation requires a full local OpenAPI 3.0.x document. "
                "Pass --models-path or set ANVILOGIC_MODELS_PATH."
            )
        return OpenAPIContractCatalog.from_path(override)
    except AnvilogicError as exc:
        _abort(exc, ExitCode.VALIDATION)


def _operations() -> OperationCatalog:
    try:
        return OperationCatalog.bundled()
    except OperationCatalogError as exc:
        _abort(exc)


def _abort(exc: Exception, code: int | ExitCode | None = None) -> NoReturn:
    error_console.print(f"[red]Error:[/red] {exc}")
    selected = code
    if selected is None:
        selected = exc.exit_code if isinstance(exc, AnvilogicError) else ExitCode.ERROR
    raise typer.Exit(code=int(selected))


def _emit_json(value: Any) -> None:
    typer.echo(json.dumps(value, indent=2, sort_keys=True))


def _mask_secret(value: str | None) -> str:
    if not value:
        return ""
    if len(value) < 5:
        return "***"
    return f"{value[:2]}***{value[-2:]}"


@config_app.command("show")
def show_config(
    as_json: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    config = _load_config_or_exit()
    payload = {
        "base_url": config.base_url,
        "api_key": _mask_secret(config.api_key),
        "auth_scheme": config.auth_scheme,
        "verify_tls": config.verify_tls,
        "timeout": config.timeout,
    }
    if as_json:
        _emit_json(payload)
        return
    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Setting")
    table.add_column("Stored value")
    for key, value in payload.items():
        table.add_row(key, "" if value is None else str(value))
    console.print(table)


@config_app.command("set")
def set_config(
    base_url: str | None = typer.Option(None, help="Anvilogic API base URL."),
    auth_scheme: str | None = typer.Option(
        None, help="Authentication scheme: bearer, x-api-key, token, or none."
    ),
    verify_tls: bool | None = typer.Option(
        None, "--verify-tls/--no-verify-tls", help="Enable or disable TLS verification."
    ),
    timeout: float | None = typer.Option(None, help="Request timeout in seconds."),
) -> None:
    config = _load_config_or_exit()
    try:
        if base_url is not None:
            config.base_url = normalize_base_url(base_url)
        if auth_scheme is not None:
            config.auth_scheme = validate_auth_scheme(auth_scheme)
        if verify_tls is not None:
            config.verify_tls = verify_tls
        if timeout is not None:
            config.timeout = validate_timeout(timeout)
        path = save_config(config)
    except AnvilogicError as exc:
        _abort(exc)
    typer.echo(f"Config saved to {path}")


@config_app.command("validate")
def validate_config() -> None:
    config = _load_config_or_exit()
    errors, warnings = validate_effective_config(config)
    for warning in warnings:
        error_console.print(f"[yellow]Warning:[/yellow] {warning}")
    if errors:
        for error in errors:
            error_console.print(f"[red]Error:[/red] {error}")
        raise typer.Exit(code=int(ExitCode.CONFIG))
    typer.echo("Config OK")


@auth_app.command("set")
def set_auth(
    api_key: str = typer.Option(
        ...,
        prompt="API key",
        hide_input=True,
        confirmation_prompt=True,
        help="API key to store in the user-only config file.",
    ),
) -> None:
    cleaned = api_key.strip()
    if not cleaned:
        raise typer.BadParameter("API key cannot be empty.")
    config = _load_config_or_exit()
    config.api_key = cleaned
    try:
        path = save_config(config)
    except AnvilogicError as exc:
        _abort(exc)
    typer.echo(f"API key stored at {path}")


@auth_app.command("clear")
def clear_auth() -> None:
    config = _load_config_or_exit()
    config.api_key = None
    try:
        save_config(config)
    except AnvilogicError as exc:
        _abort(exc)
    typer.echo("Stored API key cleared. Environment variables are unchanged.")


@models_app.command("stats")
def model_stats(ctx: typer.Context) -> None:
    _emit_json(_catalog(ctx).stats())


@models_app.command("list")
def list_models(
    ctx: typer.Context,
    search: str | None = typer.Option(None, "--search", "-s", help="Match names and fields."),
    output_format: str = typer.Option(
        "table", "--output-format", "-o", help="Output format: table, json, or names."
    ),
    limit: int = typer.Option(100, min=1, max=10000, help="Maximum models to display."),
    show_all: bool = typer.Option(False, "--all", help="Display every matching model."),
) -> None:
    if output_format not in {"table", "json", "names"}:
        raise typer.BadParameter("output-format must be table, json, or names.")
    catalog = _catalog(ctx)
    matches = catalog.names(search)
    displayed = matches if show_all else matches[:limit]
    if output_format == "json":
        _emit_json({"count": len(matches), "models": displayed})
    elif output_format == "names":
        typer.echo("\n".join(displayed))
    else:
        table = Table(box=box.SIMPLE_HEAVY)
        table.add_column("Model")
        table.add_column("Kind")
        table.add_column("Description")
        for name in displayed:
            schema = catalog.get(name)
            kind = str(schema.get("type") or ("enum" if "enum" in schema else "composed"))
            table.add_row(name, kind, str(schema.get("description", "")))
        console.print(table)
        if len(displayed) < len(matches):
            error_console.print(
                f"Showing {len(displayed)} of {len(matches)} models; use --all or raise --limit."
            )


@models_app.command("show")
def show_model(
    ctx: typer.Context,
    name: str = typer.Argument(help="Model name (case-insensitive exact matches are accepted)."),
    resolve: bool = typer.Option(False, "--resolve", help="Inline non-recursive model references."),
) -> None:
    catalog = _catalog(ctx)
    try:
        schema = catalog.resolved(name) if resolve else catalog.get(name)
    except ModelCatalogError as exc:
        _abort(exc)
    _emit_json(schema)


@models_app.command("sample")
def sample_model(
    ctx: typer.Context,
    name: str = typer.Argument(help="Model name."),
    all_fields: bool = typer.Option(
        False, "--all-fields", help="Include optional properties as well as required properties."
    ),
) -> None:
    try:
        _emit_json(_catalog(ctx).sample(name, all_fields=all_fields))
    except ModelCatalogError as exc:
        _abort(exc)


@models_app.command("validate")
def validate_model(
    ctx: typer.Context,
    name: str = typer.Argument(help="Model name."),
    data: str | None = typer.Option(None, help="Inline JSON value."),
    data_file: Path | None = typer.Option(
        None, "--data-file", exists=True, readable=True, help="JSON file to validate."
    ),
) -> None:
    if data is None and data_file is None:
        raise typer.BadParameter("Provide --data or --data-file.")
    try:
        payload = load_json_input(data, data_file)
        issues = _catalog(ctx).validate(name, payload)
    except (ValueError, ModelCatalogError) as exc:
        _abort(exc, ExitCode.VALIDATION)
    if issues:
        _print_validation_issues(issues)
        raise typer.Exit(code=int(ExitCode.VALIDATION))
    typer.echo(f"Valid {name}")


@operations_app.command("stats")
def operation_stats() -> None:
    _emit_json(_operations().stats())


@operations_app.command("list")
def list_operations(
    search: str | None = typer.Option(
        None, "--search", "-s", help="Match operation IDs and paths."
    ),
    output_format: str = typer.Option(
        "table", "--output-format", "-o", help="Output format: table, json, or names."
    ),
    limit: int = typer.Option(100, min=1, max=10000, help="Maximum operations to display."),
    show_all: bool = typer.Option(False, "--all", help="Display every matching operation."),
) -> None:
    if output_format not in {"table", "json", "names"}:
        raise typer.BadParameter("output-format must be table, json, or names.")
    matches = _operations().matching(search)
    displayed = matches if show_all else matches[:limit]
    if output_format == "json":
        _emit_json({"count": len(matches), "operations": [item.as_dict() for item in displayed]})
    elif output_format == "names":
        typer.echo("\n".join(item.operation_id for item in displayed))
    else:
        table = Table(box=box.SIMPLE_HEAVY)
        table.add_column("Operation")
        table.add_column("Method")
        table.add_column("Path")
        table.add_column("Risk")
        table.add_column("Confidence")
        for operation in displayed:
            table.add_row(
                operation.operation_id,
                operation.method,
                operation.path,
                operation.risk,
                operation.confidence,
            )
        console.print(table)
        if len(displayed) < len(matches):
            error_console.print(
                f"Showing {len(displayed)} of {len(matches)} operations; "
                "use --all or raise --limit."
            )


@operations_app.command("show")
def show_operation(
    operation_id: str = typer.Argument(help="Reviewed operation ID."),
) -> None:
    try:
        operation = _operations().get(operation_id)
    except OperationCatalogError as exc:
        _abort(exc, ExitCode.USAGE)
    _emit_json(operation.as_dict())


@app.command("invoke")
def invoke_operation(
    ctx: typer.Context,
    operation_id: str = typer.Argument(help="Reviewed operation ID."),
    path_param: list[str] | None = typer.Option(
        None, "--path-param", help="Repeatable path parameter as NAME=VALUE."
    ),
    query: list[str] | None = typer.Option(
        None, "--query", "-q", help="Repeatable observed query parameter as NAME=VALUE."
    ),
    header: list[str] | None = typer.Option(
        None, "--header", "-H", help="Repeatable custom header as NAME:VALUE."
    ),
    data: str | None = typer.Option(None, help="Inline JSON request body."),
    data_file: Path | None = typer.Option(
        None, "--data-file", exists=True, readable=True, help="JSON request body file."
    ),
    validate_request: bool = typer.Option(
        False,
        "--validate-request",
        help="Validate against this operation in a local OpenAPI 3.0.x document.",
    ),
    validate_response: bool = typer.Option(
        False,
        "--validate-response",
        help="Validate the actual response using a local OpenAPI 3.0.x document.",
    ),
    base_url: str | None = typer.Option(None, help="Override the configured API base URL."),
    api_key: str | None = typer.Option(
        None, help="Override the API key; prefer ANVILOGIC_API_KEY for automation."
    ),
    auth_scheme: str | None = typer.Option(
        None, help="Override auth: bearer, x-api-key, token, or none."
    ),
    timeout: float | None = typer.Option(None, help="Override request timeout in seconds."),
    insecure: bool = typer.Option(False, help="Disable TLS verification for this request."),
    dry_run: bool = typer.Option(False, help="Print a redacted request plan without sending."),
    apply: bool = typer.Option(
        False, help="Send non-safe operations; otherwise only preview the request."
    ),
    output: Path | None = typer.Option(None, help="Write the response body to a 0600 file."),
    output_format: str = typer.Option(
        "auto", help="Response output format: auto, json, or raw."
    ),
    force: bool = typer.Option(False, help="Replace an existing --output file."),
) -> None:
    try:
        operation = _operations().get(operation_id)
        path_values = parse_pairs(path_param or [])
        query_values = parse_pairs(query or [])
        operation.validate_query(query_values)
        rendered_path = operation.render_path(path_values)
    except (OperationCatalogError, ValueError) as exc:
        _abort(exc, ExitCode.USAGE)
    body_supplied = data is not None or data_file is not None
    if not operation.request_body and body_supplied:
        raise typer.BadParameter("This operation does not accept a JSON request body.")
    if (
        operation.request_body
        and operation.request_body_required is not False
        and not body_supplied
    ):
        raise typer.BadParameter(
            "This operation requires a JSON body; provide --data or --data-file."
        )
    _execute_call(
        ctx=ctx,
        method=operation.method,
        path=rendered_path,
        query=query,
        header=header,
        data=data,
        data_file=data_file,
        request_model=None,
        response_model=None,
        contract_operation=operation,
        validate_request=validate_request,
        validate_response=validate_response,
        base_url=base_url,
        api_key=api_key,
        auth_scheme=auth_scheme,
        timeout=timeout,
        insecure=insecure,
        dry_run=dry_run,
        apply=apply,
        output=output,
        output_format=output_format,
        force=force,
    )


@app.command("call")
def call_api(
    ctx: typer.Context,
    method: str = typer.Argument(help="HTTP method."),
    path: str = typer.Argument(help="Relative API path."),
    query: list[str] | None = typer.Option(
        None, "--query", "-q", help="Repeatable query parameter as NAME=VALUE."
    ),
    header: list[str] | None = typer.Option(
        None, "--header", "-H", help="Repeatable custom header as NAME:VALUE."
    ),
    data: str | None = typer.Option(None, help="Inline JSON request body."),
    data_file: Path | None = typer.Option(
        None, "--data-file", exists=True, readable=True, help="JSON request body file."
    ),
    request_model: str | None = typer.Option(
        None, help="Validate the request body against an exported model."
    ),
    response_model: str | None = typer.Option(
        None, help="Validate a JSON response against an exported model."
    ),
    base_url: str | None = typer.Option(None, help="Override the configured API base URL."),
    api_key: str | None = typer.Option(
        None, help="Override the API key; prefer ANVILOGIC_API_KEY for automation."
    ),
    auth_scheme: str | None = typer.Option(
        None, help="Override auth: bearer, x-api-key, token, or none."
    ),
    timeout: float | None = typer.Option(None, help="Override request timeout in seconds."),
    insecure: bool = typer.Option(False, help="Disable TLS verification for this request."),
    dry_run: bool = typer.Option(False, help="Print a redacted request plan without sending."),
    apply: bool = typer.Option(
        False, help="Send POST, PUT, PATCH, or DELETE requests; otherwise only preview."
    ),
    output: Path | None = typer.Option(None, help="Write the response body to a 0600 file."),
    output_format: str = typer.Option(
        "auto", help="Response output format: auto, json, or raw."
    ),
    force: bool = typer.Option(False, help="Replace an existing --output file."),
) -> None:
    _execute_call(
        ctx=ctx,
        method=method,
        path=path,
        query=query,
        header=header,
        data=data,
        data_file=data_file,
        request_model=request_model,
        response_model=response_model,
        contract_operation=None,
        validate_request=False,
        validate_response=False,
        base_url=base_url,
        api_key=api_key,
        auth_scheme=auth_scheme,
        timeout=timeout,
        insecure=insecure,
        dry_run=dry_run,
        apply=apply,
        output=output,
        output_format=output_format,
        force=force,
    )


def _execute_call(
    *,
    ctx: typer.Context,
    method: str,
    path: str,
    query: list[str] | None,
    header: list[str] | None,
    data: str | None,
    data_file: Path | None,
    request_model: str | None,
    response_model: str | None,
    contract_operation: Operation | None,
    validate_request: bool,
    validate_response: bool,
    base_url: str | None,
    api_key: str | None,
    auth_scheme: str | None,
    timeout: float | None,
    insecure: bool,
    dry_run: bool,
    apply: bool,
    output: Path | None,
    output_format: str,
    force: bool,
) -> None:
    if dry_run and apply:
        raise typer.BadParameter("Use either --dry-run or --apply, not both.")
    if output_format not in {"auto", "json", "raw"}:
        raise typer.BadParameter("output-format must be auto, json, or raw.")
    normalized_method = method.strip().upper()
    will_send = not dry_run and (normalized_method in SAFE_RETRY_METHODS or apply)
    if validate_response and not will_send:
        raise typer.BadParameter(
            "--validate-response requires a request that will be sent; "
            "do not use --dry-run and pass --apply for mutations."
        )
    catalog = _catalog(ctx) if request_model or response_model else None
    contract = _contract_catalog(ctx) if validate_request or validate_response else None
    config = _load_config_or_exit()
    try:
        resolved_base_url = effective_base_url(config, base_url)
        resolved_scheme = effective_auth_scheme(config, auth_scheme)
        resolved_timeout = validate_timeout(timeout if timeout is not None else config.timeout)
        body = load_json_input(data, data_file)
        query_pairs = parse_pairs(query or [])
        custom_headers = parse_headers(header or [])
    except (AnvilogicError, ValueError) as exc:
        _abort(exc, ExitCode.USAGE)
    if not resolved_base_url:
        _abort(
            AnvilogicError("Base URL is required. Set ANVILOGIC_BASE_URL or run config set."),
            ExitCode.CONFIG,
        )
    resolved_api_key = effective_api_key(config, api_key)
    if will_send and resolved_scheme != "none" and not resolved_api_key:
        _abort(
            AnvilogicError("API key is required. Set ANVILOGIC_API_KEY or run auth set."),
            ExitCode.CONFIG,
        )
    preview_key = resolved_api_key or "not-configured"
    try:
        plan = prepare_request(
            method=normalized_method,
            base_url=resolved_base_url,
            path=path,
            query=query_pairs,
            custom_headers=custom_headers,
            api_key=preview_key,
            auth_scheme=resolved_scheme,
            json_body=body,
        )
    except (AnvilogicError, ValueError) as exc:
        _abort(exc, ExitCode.USAGE)
    body_supplied = data is not None or data_file is not None
    if request_model:
        if not body_supplied:
            raise typer.BadParameter("--request-model requires --data or --data-file.")
        assert catalog is not None
        issues = _validate_payload(catalog, request_model, body)
        if issues:
            _print_validation_issues(issues)
            raise typer.Exit(code=int(ExitCode.VALIDATION))
    if validate_request:
        assert contract is not None
        assert contract_operation is not None
        try:
            issues = contract.validate_request(
                contract_operation.method,
                contract_operation.path,
                body,
                body_supplied=body_supplied,
                registry_has_body=contract_operation.request_body,
            )
        except ContractError as exc:
            _abort(exc, ExitCode.VALIDATION)
        if issues:
            _print_validation_issues(issues)
            raise typer.Exit(code=int(ExitCode.VALIDATION))
    if not will_send:
        _emit_json(redacted_plan(plan))
        if normalized_method not in SAFE_RETRY_METHODS and not dry_run:
            error_console.print("Mutation preview only; pass --apply to send this request.")
        return
    verify_tls = config.verify_tls and not insecure
    if resolved_base_url.startswith("http://") or not verify_tls:
        error_console.print("[yellow]Warning:[/yellow] request transport is not fully verified.")
    try:
        with AnvilogicClient(verify_tls=verify_tls, timeout=resolved_timeout) as client:
            response = client.send(plan)
    except AnvilogicError as exc:
        _abort(exc)
    if response_model:
        try:
            response_payload = response.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            _abort(
                ValueError("Response is not JSON and cannot be validated."),
                ExitCode.VALIDATION,
            )
        assert catalog is not None
        issues = _validate_payload(catalog, response_model, response_payload)
        if issues:
            _print_validation_issues(issues)
            raise typer.Exit(code=int(ExitCode.VALIDATION))
    if validate_response:
        assert contract is not None
        assert contract_operation is not None
        try:
            response_payload = response.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            _abort(
                ValueError("Response is not valid JSON and cannot be validated."),
                ExitCode.VALIDATION,
            )
        try:
            issues = contract.validate_response(
                contract_operation.method,
                contract_operation.path,
                response.status_code,
                response.headers.get("Content-Type", ""),
                response_payload,
            )
        except ContractError as exc:
            _abort(exc, ExitCode.VALIDATION)
        if issues:
            _print_validation_issues(issues)
            raise typer.Exit(code=int(ExitCode.VALIDATION))
    try:
        rendered, _chosen_format = response_bytes_and_format(
            response.content, response.headers.get("Content-Type", ""), output_format
        )
        if output:
            write_output(output, rendered, force=force)
            error_console.print(f"Wrote {len(rendered)} bytes to {output}")
        else:
            sys.stdout.buffer.write(rendered)
            sys.stdout.buffer.flush()
    except (OSError, ValueError) as exc:
        _abort(exc)
    if response.is_error:
        error_console.print(f"HTTP {response.status_code} returned by Anvilogic API.")
        raise typer.Exit(code=int(ExitCode.HTTP))


def _validate_payload(
    catalog: ModelCatalog, model: str, payload: Any
) -> list[ValidationIssue]:
    try:
        return catalog.validate(model, payload)
    except ModelCatalogError as exc:
        _abort(exc, ExitCode.VALIDATION)


def _print_validation_issues(issues: list[ValidationIssue]) -> None:
    error_console.print(f"[red]Validation failed ({len(issues)} issue(s)):[/red]")
    for issue in issues:
        error_console.print(f"- {issue.path}: {issue.message}")


def app_main() -> None:  # pragma: no cover
    app()


if __name__ == "__main__":  # pragma: no cover
    app_main()
