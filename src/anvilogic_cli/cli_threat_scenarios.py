from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from rich.console import Console

from anvilogic_cli.client import AnvilogicClient, prepare_request
from anvilogic_cli.config import (
    effective_api_key,
    effective_auth_scheme,
    effective_base_url,
    load_config,
    validate_timeout,
)
from anvilogic_cli.errors import AnvilogicError, ExitCode
from anvilogic_cli.operations import OperationCatalog, OperationCatalogError
from anvilogic_cli.threat_scenarios import (
    SCENARIO_DETAIL_OPERATION,
    SCENARIO_GROUP_OPERATION,
    SCENARIO_LIST_OPERATION,
    ThreatScenarioCollectionError,
    ThreatScenarioCollector,
    threat_scenario_schema_bytes,
    write_collection,
)

console = Console()
error_console = Console(stderr=True)

threat_scenarios_app = typer.Typer(
    no_args_is_help=True,
    help="Collect normalized Anvilogic threat-scenario coverage data.",
    pretty_exceptions_show_locals=False,
)


def _fail(exc: Exception, code: ExitCode = ExitCode.ERROR) -> NoReturn:
    error_console.print(f"[red]Error:[/red] {exc}")
    if isinstance(exc, AnvilogicError):
        code = exc.exit_code
    raise typer.Exit(code=int(code))


@threat_scenarios_app.command("schema")
def show_threat_scenario_schema() -> None:
    """Print the exact bundled JSON Schema for one exported JSONL record."""

    try:
        body = threat_scenario_schema_bytes()
    except AnvilogicError as exc:
        _fail(exc)
    typer.echo(body.decode("utf-8"), nl=False)


@threat_scenarios_app.command("export")
def export_threat_scenarios(
    output_dir: Annotated[
        Path,
        typer.Option(
            "--output-dir",
            help="New or empty private run directory for the collection artifacts.",
        ),
    ],
    scope: Annotated[
        str,
        typer.Option("--scope", help="Collection scope; only all-visible is supported."),
    ] = "all-visible",
    page_size: Annotated[
        int,
        typer.Option("--page-size", min=1, max=100, help="Scenario list page size."),
    ] = 100,
    apply: Annotated[
        bool,
        typer.Option(
            "--apply",
            help="Send the traffic-derived POST reads and write private artifacts.",
        ),
    ] = False,
    base_url: Annotated[
        str | None,
        typer.Option("--base-url", help="Override the configured Anvilogic API base URL."),
    ] = None,
    api_key: Annotated[
        str | None,
        typer.Option(
            "--api-key",
            help="Override the API key; prefer ANVILOGIC_API_KEY for automation.",
        ),
    ] = None,
    auth_scheme: Annotated[
        str | None,
        typer.Option("--auth-scheme", help="Override bearer, x-api-key, token, or none."),
    ] = None,
    timeout: Annotated[
        float | None,
        typer.Option("--timeout", help="Override request timeout in seconds."),
    ] = None,
    insecure: Annotated[
        bool,
        typer.Option("--insecure", help="Disable TLS verification for this collection."),
    ] = False,
) -> None:
    if scope != "all-visible":
        raise typer.BadParameter("scope must be all-visible.")
    if not apply:
        typer.echo(
            json.dumps(
                {
                    "apply_required": True,
                    "operations": [
                        SCENARIO_LIST_OPERATION,
                        SCENARIO_DETAIL_OPERATION,
                        SCENARIO_GROUP_OPERATION,
                    ],
                    "output_dir": str(output_dir),
                    "page_size": page_size,
                    "scope": scope,
                    "sent": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        error_console.print("Collection preview only; pass --apply to send POST reads.")
        return

    try:
        config = load_config()
        resolved_base_url = effective_base_url(config, base_url)
        resolved_scheme = effective_auth_scheme(config, auth_scheme)
        resolved_key = effective_api_key(config, api_key)
        resolved_timeout = validate_timeout(timeout if timeout is not None else config.timeout)
    except AnvilogicError as exc:
        _fail(exc, ExitCode.CONFIG)
    if not resolved_base_url:
        _fail(
            AnvilogicError("Base URL is required. Set ANVILOGIC_BASE_URL or run config set."),
            ExitCode.CONFIG,
        )
    if resolved_scheme != "none" and not resolved_key:
        _fail(
            AnvilogicError("API key is required. Set ANVILOGIC_API_KEY or run auth set."),
            ExitCode.CONFIG,
        )
    verify_tls = config.verify_tls and not insecure
    if resolved_base_url.startswith("http://") or not verify_tls:
        error_console.print("[yellow]Warning:[/yellow] request transport is not fully verified.")

    try:
        catalog = OperationCatalog.bundled()
        with AnvilogicClient(verify_tls=verify_tls, timeout=resolved_timeout) as client:

            def request(
                operation_id: str,
                body: dict[str, Any] | None,
                query: list[tuple[str, str]],
            ) -> Any:
                operation = catalog.get(operation_id)
                operation.validate_query(query)
                plan = prepare_request(
                    method=operation.method,
                    base_url=resolved_base_url,
                    path=operation.path,
                    query=query,
                    custom_headers=None,
                    api_key=resolved_key,
                    auth_scheme=resolved_scheme,
                    json_body=body,
                )
                response = client.send(plan)
                if response.is_error:
                    raise AnvilogicError(
                        f"Anvilogic operation {operation_id!r} returned HTTP "
                        f"{response.status_code}."
                    )
                try:
                    return response.json()
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    raise ThreatScenarioCollectionError(
                        f"Anvilogic operation {operation_id!r} returned malformed JSON."
                    ) from exc

            result = ThreatScenarioCollector(request, page_size=page_size).collect()
        manifest = write_collection(output_dir, result)
    except (
        AnvilogicError,
        OperationCatalogError,
        OSError,
        ValueError,
    ) as exc:
        _fail(exc)
    counts = manifest["counts"]
    console.print(
        "[green]Complete:[/green] wrote "
        f"{counts['scenarios']} threat scenarios and {counts['stages']} stages to {output_dir}."
    )


__all__ = ["export_threat_scenarios", "show_threat_scenario_schema", "threat_scenarios_app"]
