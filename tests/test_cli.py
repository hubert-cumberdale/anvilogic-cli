from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

from typer.testing import CliRunner

from anvilogic_cli.cli import app

runner = CliRunner()
MODEL_CATALOG = Path(__file__).parent / "fixtures" / "model_catalog.json"


def with_models(*arguments: str) -> list[str]:
    return ["--models-path", str(MODEL_CATALOG), *arguments]


def test_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == "anvilogic-cli 0.3.2"


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


def test_model_stats_use_a_caller_supplied_catalog() -> None:
    result = runner.invoke(app, with_models("models", "stats"))

    assert result.exit_code == 0
    assert json.loads(result.stdout)["models"] == 2


def test_model_stats_use_environment_catalog(monkeypatch) -> None:
    monkeypatch.setenv("ANVILOGIC_MODELS_PATH", str(MODEL_CATALOG))

    result = runner.invoke(app, ["models", "stats"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["models"] == 2


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
