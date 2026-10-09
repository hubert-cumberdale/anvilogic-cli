from __future__ import annotations

import json
import stat

import pytest

from anvilogic_cli.config import (
    CliConfig,
    config_path,
    effective_api_key,
    effective_base_url,
    effective_models_path,
    load_config,
    normalize_base_url,
    save_config,
    validate_effective_config,
    validate_timeout,
)
from anvilogic_cli.errors import ConfigError


def test_config_round_trip_uses_private_permissions() -> None:
    path = save_config(
        CliConfig(base_url="https://secure.anvilogic.com/", api_key="example-secret")
    )

    assert path == config_path()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert load_config().base_url == "https://secure.anvilogic.com"
    assert load_config().api_key == "example-secret"


def test_environment_overrides_stored_values(monkeypatch: pytest.MonkeyPatch) -> None:
    config = CliConfig(base_url="https://stored.example", api_key="stored-key")
    monkeypatch.setenv("ANVILOGIC_BASE_URL", "https://env.example/api/")
    monkeypatch.setenv("ANVILOGIC_API_KEY", "env-key")

    assert effective_base_url(config) == "https://env.example/api"
    assert effective_api_key(config) == "env-key"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "secure.anvilogic.com",
        "ftp://example.com",
        "https://u:" + "p@example.com",
        "https://e/x?q=1",
    ],
)
def test_invalid_base_urls_fail(value: str) -> None:
    with pytest.raises(ConfigError):
        normalize_base_url(value)


@pytest.mark.parametrize("value", [0, 121, float("nan"), True, "10"])
def test_invalid_timeouts_fail(value: object) -> None:
    with pytest.raises(ConfigError):
        validate_timeout(value)


def test_malformed_config_fails() -> None:
    config_path().parent.mkdir(parents=True)
    config_path().write_text("[]", encoding="utf-8")

    with pytest.raises(ConfigError, match="JSON object"):
        load_config()


def test_unknown_config_keys_are_ignored() -> None:
    config_path().parent.mkdir(parents=True)
    config_path().write_text(json.dumps({"timeout": 10, "future": True}), encoding="utf-8")

    assert load_config().timeout == 10


def test_effective_config_requires_url_and_key() -> None:
    errors, warnings = validate_effective_config(CliConfig())

    assert len(errors) == 2
    assert warnings == []


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com/openapi.yaml",
        "http://example.com/a.yml",
        "ftp://example.com/openapi.yaml",
        "file:///tmp/openapi.yaml",
        "ssh://example.com/openapi.yaml",
        "data:text/yaml,components:%20{}",
    ],
)
def test_models_path_rejects_uris(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("ANVILOGIC_MODELS_PATH", value)

    with pytest.raises(ConfigError, match="local file"):
        effective_models_path()


@pytest.mark.parametrize("value", ["C:/models/openapi.yaml", r"C:\models\openapi.yaml"])
def test_models_path_preserves_windows_drive_paths(value: str) -> None:
    assert str(effective_models_path(value)) == value
