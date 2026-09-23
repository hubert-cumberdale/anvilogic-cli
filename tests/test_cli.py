from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

import httpx
from typer.testing import CliRunner

from anvilogic_cli.cli import app

runner = CliRunner()
MODEL_CATALOG = Path(__file__).parent / "fixtures" / "model_catalog.json"


def with_models(*arguments: str) -> list[str]:
    return ["--models-path", str(MODEL_CATALOG), *arguments]


def write_contract(tmp_path: Path, paths: dict) -> Path:
    path = tmp_path / "openapi.json"
    path.write_text(
        json.dumps(
            {
                "openapi": "3.0.3",
                "info": {"title": "Synthetic CLI contract", "version": "test"},
                "paths": paths,
            }
        ),
        encoding="utf-8",
    )
    return path


def test_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == "anvilogic-cli 0.3.4"


def test_threat_scenario_schema_output_matches_bundled_file_exactly() -> None:
    expected = (
        resources.files("anvilogic_cli")
        .joinpath("threat_scenario_record.schema.json")
        .read_text(encoding="utf-8")
    )

    first = runner.invoke(app, ["threat-scenarios", "schema"])
    second = runner.invoke(app, ["threat-scenarios", "schema"])

    assert first.exit_code == 0
    assert first.stdout == expected
    assert second.stdout == expected


def test_models_require_a_caller_supplied_catalog() -> None:
    result = runner.invoke(app, ["models", "stats"])

    assert result.exit_code == 6
    assert "--models-path" in result.stderr
    assert "ANVILOGIC_MODELS_PATH" in result.stderr


def test_models_path_rejects_a_url_before_loading() -> None:
    result = runner.invoke(
        app,
        ["--models-path", "https://example.com/openapi.yaml", "models", "stats"],
    )

    assert result.exit_code == 3
    assert "local file, not a URI" in result.stderr


def test_model_stats_use_a_caller_supplied_catalog() -> None:
    result = runner.invoke(app, with_models("models", "stats"))

    assert result.exit_code == 0
    assert json.loads(result.stdout)["models"] == 2


def test_model_stats_use_environment_catalog(monkeypatch) -> None:
    monkeypatch.setenv("ANVILOGIC_MODELS_PATH", str(MODEL_CATALOG))

    result = runner.invoke(app, ["models", "stats"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["models"] == 2


def test_model_stats_accept_local_openapi_yaml(tmp_path: Path) -> None:
    path = tmp_path / "models.yaml"
    path.write_text(
        "components:\n  schemas:\n    Local:\n      type: string\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["--models-path", str(path), "models", "stats"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["models"] == 1


def test_model_list_names_can_search() -> None:
    result = runner.invoke(
        app,
        with_models(
            "models", "list", "--search", "AddCommentRequest", "--output-format", "names"
        ),
    )

    assert result.exit_code == 0
    assert "AddCommentRequest" in result.stdout.splitlines()


def test_model_validation_uses_stable_exit_code() -> None:
    result = runner.invoke(
        app,
        with_models(
            "models", "validate", "AddCommentRequest", "--data", '{"comment":""}'
        ),
    )

    assert result.exit_code == 6
    assert "$.comment" in result.stderr


def test_operation_list_can_search() -> None:
    result = runner.invoke(
        app, ["operations", "list", "--search", "alert.search", "--output-format", "names"]
    )

    assert result.exit_code == 0
    assert result.stdout.splitlines() == ["post.services.triage.alert.search"]


def test_observed_get_operation_can_be_previewed() -> None:
    result = runner.invoke(
        app,
        [
            "invoke",
            "get.api.info.user",
            "--base-url",
            "https://secure.anvilogic.com",
            "--dry-run",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["method"] == "GET"
    assert payload["url"].endswith("/api/info/user")
    assert payload["sent"] is False


def test_observed_post_remains_apply_gated() -> None:
    result = runner.invoke(
        app,
        [
            "invoke",
            "post.api.search.query",
            "--base-url",
            "https://secure.anvilogic.com",
            "--data",
            '{"query":"synthetic"}',
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["sent"] is False
    assert "Mutation preview only" in result.stderr


def test_invoke_allows_publicly_optional_body_omission() -> None:
    result = runner.invoke(
        app,
        [
            "invoke",
            "delete.services.allowlist.global.field",
            "--base-url",
            "https://secure.anvilogic.com",
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["body"] is None
    assert "Mutation preview only" in result.stderr


def test_invoke_requires_private_unknown_body_conservatively() -> None:
    result = runner.invoke(
        app,
        [
            "invoke",
            "post.api.cloudapp.get-users",
            "--base-url",
            "https://secure.anvilogic.com",
        ],
    )

    assert result.exit_code == 2
    assert "requires a JSON body" in result.stderr


def test_invoke_rejects_body_for_bodyless_operation() -> None:
    result = runner.invoke(
        app,
        [
            "invoke",
            "get.api.info.user",
            "--base-url",
            "https://secure.anvilogic.com",
            "--data",
            "{}",
            "--dry-run",
        ],
    )

    assert result.exit_code == 2
    assert "does not accept" in result.stderr


def test_documented_delete_remains_apply_gated() -> None:
    result = runner.invoke(
        app,
        [
            "invoke",
            "delete.services.allowlist.global-entry.by-id",
            "--base-url",
            "https://secure.anvilogic.com",
            "--path-param",
            "id=synthetic",
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["sent"] is False
    assert "Mutation preview only" in result.stderr


def test_invoke_rejects_unobserved_query_parameter() -> None:
    result = runner.invoke(
        app,
        [
            "invoke",
            "get.api.info.user",
            "--base-url",
            "https://secure.anvilogic.com",
            "--query",
            "unexpected=value",
            "--dry-run",
        ],
    )

    assert result.exit_code == 2
    assert "Unreviewed query parameter" in result.stderr


def test_read_only_dry_run_does_not_require_api_key() -> None:
    result = runner.invoke(
        app,
        [
            "call",
            "GET",
            "/api/example",
            "--base-url",
            "https://secure.anvilogic.com",
            "--dry-run",
            "--query",
            "page=1",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["sent"] is False
    assert payload["headers"]["Authorization"] == "***"


def test_mutations_preview_without_apply() -> None:
    result = runner.invoke(
        app,
        [
            "call",
            "POST",
            "/api/example",
            "--base-url",
            "https://secure.anvilogic.com",
            "--data",
            '{"password":"do-not-print","name":"visible"}',
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["body"] == {"password": "***", "name": "visible"}
    assert "Mutation preview only" in result.stderr


def test_threat_scenario_export_is_preview_only_without_apply(tmp_path) -> None:
    output_dir = tmp_path / "run"

    result = runner.invoke(
        app,
        [
            "threat-scenarios",
            "export",
            "--scope",
            "all-visible",
            "--page-size",
            "100",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["sent"] is False
    assert payload["apply_required"] is True
    assert not output_dir.exists()
    assert "pass --apply" in result.stderr


def test_request_model_blocks_invalid_body_before_network() -> None:
    result = runner.invoke(
        app,
        with_models(
            "call",
            "POST",
            "/api/comments",
            "--base-url",
            "https://secure.anvilogic.com",
            "--request-model",
            "AddCommentRequest",
            "--data",
            "{}",
            "--apply",
            "--auth-scheme",
            "none",
        ),
    )

    assert result.exit_code == 6
    assert "missing" not in result.stdout.casefold()
    assert "required" in result.stderr.casefold()


def test_explicit_request_validation_requires_model_catalog() -> None:
    result = runner.invoke(
        app,
        [
            "call",
            "POST",
            "/api/comments",
            "--base-url",
            "https://secure.anvilogic.com",
            "--request-model",
            "AddCommentRequest",
            "--data",
            "{}",
        ],
    )

    assert result.exit_code == 6
    assert "A model catalog is required" in result.stderr


def test_explicit_response_validation_requires_model_catalog() -> None:
    result = runner.invoke(
        app,
        [
            "call",
            "GET",
            "/api/example",
            "--base-url",
            "https://secure.anvilogic.com",
            "--response-model",
            "ApiKeySpec",
            "--dry-run",
        ],
    )

    assert result.exit_code == 6
    assert "A model catalog is required" in result.stderr


def test_invoke_request_validation_requires_full_openapi_document() -> None:
    result = runner.invoke(
        app,
        [
            "invoke",
            "get.api.info.user",
            "--base-url",
            "https://secure.anvilogic.com",
            "--dry-run",
            "--validate-request",
        ],
    )

    assert result.exit_code == 6
    assert "full local OpenAPI 3.0.x" in result.stderr


def test_invoke_request_validation_blocks_before_network(
    tmp_path: Path, monkeypatch
) -> None:
    contract = write_contract(
        tmp_path,
        {
            "/api/search/query": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["query"],
                                    "properties": {"query": {"type": "string"}},
                                }
                            }
                        },
                    },
                    "responses": {},
                }
            }
        },
    )
    called = False

    def forbidden_send(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("request validation must run before network access")

    monkeypatch.setattr("anvilogic_cli.cli.AnvilogicClient.send", forbidden_send)
    result = runner.invoke(
        app,
        [
            "--models-path",
            str(contract),
            "invoke",
            "post.api.search.query",
            "--base-url",
            "https://secure.anvilogic.com",
            "--auth-scheme",
            "none",
            "--data",
            "{}",
            "--validate-request",
            "--apply",
        ],
    )

    assert result.exit_code == 6
    assert "required" in result.stderr
    assert called is False


def test_invoke_request_validation_missing_exact_operation_exits_six(
    tmp_path: Path,
) -> None:
    contract = write_contract(
        tmp_path,
        {"/different": {"get": {"responses": {}}}},
    )

    result = runner.invoke(
        app,
        [
            "--models-path",
            str(contract),
            "invoke",
            "get.api.info.user",
            "--base-url",
            "https://secure.anvilogic.com",
            "--validate-request",
            "--dry-run",
        ],
    )

    assert result.exit_code == 6
    assert "exact operation GET /api/info/user" in result.stderr


def test_successful_request_validation_is_silent(tmp_path: Path) -> None:
    contract = write_contract(
        tmp_path,
        {
            "/api/search/query": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {"schema": {"type": "object"}}
                        },
                    },
                    "responses": {},
                }
            }
        },
    )

    result = runner.invoke(
        app,
        [
            "--models-path",
            str(contract),
            "invoke",
            "post.api.search.query",
            "--base-url",
            "https://secure.anvilogic.com",
            "--data",
            "{}",
            "--validate-request",
            "--dry-run",
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["sent"] is False
    assert result.stderr == ""


def test_invoke_response_validation_rejects_preview_modes(tmp_path: Path) -> None:
    contract = write_contract(
        tmp_path,
        {"/api/info/user": {"get": {"responses": {}}}},
    )
    dry_run = runner.invoke(
        app,
        [
            "--models-path",
            str(contract),
            "invoke",
            "get.api.info.user",
            "--base-url",
            "https://secure.anvilogic.com",
            "--validate-response",
            "--dry-run",
        ],
    )
    mutation = runner.invoke(
        app,
        [
            "--models-path",
            str(contract),
            "invoke",
            "delete.api.ttp.delete-platforms",
            "--base-url",
            "https://secure.anvilogic.com",
            "--validate-response",
        ],
    )

    assert dry_run.exit_code == 2
    assert mutation.exit_code == 2
    assert "requires a request that will be sent" in dry_run.stderr
    assert "requires a request that will be sent" in mutation.stderr


def test_valid_documented_http_error_renders_then_exits_http(
    tmp_path: Path, monkeypatch
) -> None:
    contract = write_contract(
        tmp_path,
        {
            "/api/info/user": {
                "get": {
                    "responses": {
                        "default": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["error"],
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    )

    def response(*_args, **_kwargs):
        return httpx.Response(
            404,
            headers={"Content-Type": "application/json"},
            json={"error": "synthetic"},
            request=httpx.Request("GET", "https://secure.anvilogic.com/api/info/user"),
        )

    monkeypatch.setattr("anvilogic_cli.cli.AnvilogicClient.send", response)
    result = runner.invoke(
        app,
        [
            "--models-path",
            str(contract),
            "invoke",
            "get.api.info.user",
            "--base-url",
            "https://secure.anvilogic.com",
            "--auth-scheme",
            "none",
            "--validate-response",
        ],
    )

    assert result.exit_code == 5
    assert json.loads(result.stdout) == {"error": "synthetic"}
    assert "HTTP 404" in result.stderr
    assert "Validation" not in result.stderr


def test_invalid_response_uses_validation_exit_and_emits_no_body(
    tmp_path: Path, monkeypatch
) -> None:
    contract = write_contract(
        tmp_path,
        {
            "/api/info/user": {
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
                }
            }
        },
    )

    def response(*_args, **_kwargs):
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            json={},
            request=httpx.Request("GET", "https://secure.anvilogic.com/api/info/user"),
        )

    monkeypatch.setattr("anvilogic_cli.cli.AnvilogicClient.send", response)
    result = runner.invoke(
        app,
        [
            "--models-path",
            str(contract),
            "invoke",
            "get.api.info.user",
            "--base-url",
            "https://secure.anvilogic.com",
            "--auth-scheme",
            "none",
            "--validate-response",
        ],
    )

    assert result.exit_code == 6
    assert result.stdout == ""
    assert "required" in result.stderr


def test_non_json_response_uses_validation_exit(tmp_path: Path, monkeypatch) -> None:
    contract = write_contract(
        tmp_path,
        {
            "/api/info/user": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {"schema": {"type": "object"}}
                            }
                        }
                    }
                }
            }
        },
    )

    def response(*_args, **_kwargs):
        return httpx.Response(
            200,
            headers={"Content-Type": "text/plain"},
            content=b"{}",
            request=httpx.Request("GET", "https://secure.anvilogic.com/api/info/user"),
        )

    monkeypatch.setattr("anvilogic_cli.cli.AnvilogicClient.send", response)
    result = runner.invoke(
        app,
        [
            "--models-path",
            str(contract),
            "invoke",
            "get.api.info.user",
            "--base-url",
            "https://secure.anvilogic.com",
            "--auth-scheme",
            "none",
            "--validate-response",
        ],
    )

    assert result.exit_code == 6
    assert "not application/json" in result.stderr
