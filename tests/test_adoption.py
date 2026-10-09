from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from anvilogic_cli.adoption import AdoptionError, assess_contract_fixtures
from anvilogic_cli.cli import app
from anvilogic_cli.operations import Operation, OperationCatalog


def operation_catalog() -> OperationCatalog:
    return OperationCatalog(
        [
            Operation(
                operation_id="post.synthetic.items",
                method="POST",
                path="/items",
                query_params=(),
                request_body=True,
                request_body_required=True,
                risk="read",
                confidence="publicly-documented",
                evidence=("public-openapi",),
                last_verified="2026-09-23",
            ),
            Operation(
                operation_id="get.synthetic.items",
                method="GET",
                path="/items",
                query_params=(),
                request_body=False,
                request_body_required=False,
                risk="read",
                confidence="publicly-documented",
                evidence=("public-openapi",),
                last_verified="2026-09-23",
            ),
        ],
        source={},
    )


def write_inputs(tmp_path: Path) -> tuple[Path, Path, str]:
    sensitive_marker = "fixture-value-must-never-be-diagnosed"
    contract = tmp_path / "contract.json"
    fixtures = tmp_path / "fixtures.json"
    contract.write_text(
        json.dumps(
            {
                "openapi": "3.0.3",
                "info": {"title": "Synthetic adoption contract", "version": "test"},
                "paths": {
                    "/items": {
                        "post": {
                            "requestBody": {
                                "required": True,
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "required": ["name"],
                                            "properties": {"name": {"enum": ["valid"]}},
                                        }
                                    }
                                },
                            },
                            "responses": {},
                        },
                        "get": {
                            "responses": {
                                "200": {
                                    "content": {
                                        "application/json": {
                                            "schema": {
                                                "type": "object",
                                                "required": ["name"],
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    fixtures.write_text(
        json.dumps(
            {
                "version": 1,
                "fixtures": [
                    {
                        "direction": "request",
                        "operation_id": "post.synthetic.items",
                        "payload": {"name": "valid"},
                    },
                    {
                        "direction": "request",
                        "operation_id": "post.synthetic.items",
                        "payload": {"name": sensitive_marker},
                    },
                    {
                        "direction": "response",
                        "operation_id": "get.synthetic.items",
                        "status_code": 200,
                        "content_type": "application/json",
                        "payload": {"name": "valid"},
                    },
                    {
                        "direction": "response",
                        "operation_id": "unknown.synthetic.operation",
                        "status_code": 200,
                        "content_type": "application/json",
                        "payload": {"name": sensitive_marker},
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return contract, fixtures, sensitive_marker


def test_adoption_assessment_reports_only_aggregate_outcomes(tmp_path: Path) -> None:
    contract, fixtures, marker = write_inputs(tmp_path)
    before = sorted(path.name for path in tmp_path.iterdir())

    summary = assess_contract_fixtures(
        contract,
        fixtures,
        operations=operation_catalog(),
    )

    assert summary == {
        "fixture_format_version": 1,
        "total": {"evaluated": 4, "valid": 2, "invalid": 1, "unusable": 1},
        "request": {"evaluated": 2, "valid": 1, "invalid": 1, "unusable": 0},
        "response": {"evaluated": 2, "valid": 1, "invalid": 0, "unusable": 1},
    }
    assert marker not in json.dumps(summary)
    assert sorted(path.name for path in tmp_path.iterdir()) == before


def test_adoption_cli_never_echoes_fixture_payloads_or_uses_network(
    tmp_path: Path, monkeypatch
) -> None:
    marker = "sanitized-but-private-marker"
    contract = tmp_path / "contract.json"
    fixtures = tmp_path / "fixtures.json"
    contract.write_text(
        json.dumps(
            {
                "openapi": "3.0.3",
                "info": {"title": "Synthetic CLI adoption contract", "version": "test"},
                "paths": {
                    "/api/info/user": {
                        "get": {
                            "responses": {
                                "200": {
                                    "content": {
                                        "application/json": {"schema": {"type": "string"}}
                                    }
                                }
                            }
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    fixtures.write_text(
        json.dumps(
            {
                "version": 1,
                "fixtures": [
                    {
                        "direction": "response",
                        "operation_id": "get.api.info.user",
                        "status_code": 200,
                        "content_type": "application/json",
                        "payload": marker,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    def forbidden_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("the adoption harness must remain offline")

    monkeypatch.setattr("httpx.Client.request", forbidden_network)
    monkeypatch.setattr("urllib.request.urlopen", forbidden_network)
    result = CliRunner().invoke(
        app,
        [
            "adoption",
            "assess",
            "--contract",
            str(contract),
            "--fixtures",
            str(fixtures),
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["total"]["valid"] == 1
    assert marker not in result.stdout
    assert marker not in result.stderr


def test_adoption_contract_diagnostics_do_not_expose_contract_content(tmp_path: Path) -> None:
    marker = "private-contract-marker"
    contract = tmp_path / "contract.json"
    fixtures = tmp_path / "fixtures.json"
    contract.write_text(
        json.dumps(
            {
                "openapi": "3.0.3",
                "info": {"title": "Synthetic", "version": "test"},
                "paths": {f"/{marker}?invalid": {}},
            }
        ),
        encoding="utf-8",
    )
    fixtures.write_text(
        json.dumps(
            {
                "version": 1,
                "fixtures": [
                    {"direction": "request", "operation_id": "get.api.info.user"}
                ],
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "adoption",
            "assess",
            "--contract",
            str(contract),
            "--fixtures",
            str(fixtures),
        ],
    )

    assert result.exit_code == 6
    assert "could not be loaded safely" in result.stderr
    assert marker not in result.stderr


def test_adoption_fixture_version_requires_literal_integer(tmp_path: Path) -> None:
    contract, fixtures, _marker = write_inputs(tmp_path)
    document = json.loads(fixtures.read_text(encoding="utf-8"))
    document["version"] = True
    fixtures.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(AdoptionError, match="version must be 1"):
        assess_contract_fixtures(contract, fixtures, operations=operation_catalog())
