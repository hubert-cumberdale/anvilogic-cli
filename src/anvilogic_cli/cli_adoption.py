"""CLI adapter for the offline adoption harness."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from anvilogic_cli.adoption import AdoptionError, assess_contract_fixtures
from anvilogic_cli.contracts import ContractError
from anvilogic_cli.errors import ExitCode
from anvilogic_cli.operations import OperationCatalogError

adoption_app = typer.Typer(
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
    help="Assess sanitized contract fixtures entirely offline.",
)


@adoption_app.command("assess")
def assess(
    contract: Annotated[
        Path,
        typer.Option(
            "--contract",
            exists=True,
            readable=True,
            help="Operator-controlled full OpenAPI 3.0.x JSON/YAML document.",
        ),
    ],
    fixtures: Annotated[
        Path,
        typer.Option(
            "--fixtures",
            exists=True,
            readable=True,
            help="Sanitized local request/response fixture document.",
        ),
    ],
) -> None:
    try:
        summary = assess_contract_fixtures(contract, fixtures)
    except (AdoptionError, ContractError, OperationCatalogError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.VALIDATION)) from exc
    typer.echo(json.dumps(summary, indent=2, sort_keys=True))
