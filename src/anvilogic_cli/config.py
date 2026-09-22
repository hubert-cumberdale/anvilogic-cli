from __future__ import annotations

import json
import math
import os
import platform
import stat
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from anvilogic_cli.errors import ConfigError
from anvilogic_cli.json_utils import loads_json

CONFIG_FILENAME = "config.json"
ENV_CONFIG_DIR = "ANVILOGIC_CONFIG_DIR"
ENV_BASE_URL = "ANVILOGIC_BASE_URL"
ENV_API_KEY = "ANVILOGIC_API_KEY"
ENV_AUTH_SCHEME = "ANVILOGIC_AUTH_SCHEME"
ENV_MODELS_PATH = "ANVILOGIC_MODELS_PATH"

AUTH_SCHEMES = {"bearer", "x-api-key", "token", "none"}
TIMEOUT_MIN = 1.0
TIMEOUT_MAX = 120.0


@dataclass
class CliConfig:
    base_url: str | None = None
    api_key: str | None = None
    auth_scheme: str = "bearer"
    verify_tls: bool = True
    timeout: float = 30.0


def config_dir() -> Path:
    override = os.getenv(ENV_CONFIG_DIR)
    if override:
        return Path(override).expanduser()
    if platform.system().lower().startswith("win"):
        base = Path(os.getenv("APPDATA", Path.home() / "AppData" / "Roaming"))
        return base / "anvilogic-cli"
    xdg = os.getenv("XDG_CONFIG_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return base / "anvilogic-cli"


def config_path() -> Path:
    return config_dir() / CONFIG_FILENAME


def load_config() -> CliConfig:
    path = config_path()
    if not path.exists():
        return CliConfig()
    try:
        raw = loads_json(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"Could not read config file: {path}") from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise ConfigError(f"Config file is not valid JSON: {path}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"Config file must contain a JSON object: {path}")
    return _normalize(raw)


def save_config(config: CliConfig) -> Path:
    normalized = _normalize(asdict(config))
    directory = config_dir()
    temporary: Path | None = None
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        _tighten_directory_permissions(directory)
        path = config_path()
        descriptor, temporary_name = tempfile.mkstemp(prefix=".config.", dir=str(directory))
        temporary = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(normalized), indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        _tighten_file_permissions(temporary)
        temporary.replace(path)
        _tighten_file_permissions(path)
    except OSError as exc:
        if temporary is not None:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
        raise ConfigError(f"Could not write config file: {config_path()}") from exc
    return path


def effective_base_url(config: CliConfig, override: str | None = None) -> str | None:
    raw = override or os.getenv(ENV_BASE_URL) or config.base_url
    return normalize_base_url(raw) if raw else None


def effective_api_key(config: CliConfig, override: str | None = None) -> str | None:
    value = override or os.getenv(ENV_API_KEY) or config.api_key
    return value.strip() if value and value.strip() else None


def effective_auth_scheme(config: CliConfig, override: str | None = None) -> str:
    value = override or os.getenv(ENV_AUTH_SCHEME) or config.auth_scheme
    return validate_auth_scheme(value)


def effective_models_path(override: Path | None = None) -> Path | None:
    value = override or os.getenv(ENV_MODELS_PATH)
    return Path(value).expanduser() if value else None


def normalize_base_url(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        raise ConfigError("Base URL cannot be empty.")
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise ConfigError("Base URL must include http:// or https://.")
    if not parsed.hostname:
        raise ConfigError("Base URL must include a hostname.")
    if parsed.username or parsed.password:
        raise ConfigError("Base URL must not embed credentials.")
    if parsed.query or parsed.fragment:
        raise ConfigError("Base URL must not include a query string or fragment.")
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, path, "", ""))


def validate_auth_scheme(value: object) -> str:
    if not isinstance(value, str):
        raise ConfigError("auth_scheme must be a string.")
    normalized = value.strip().lower()
    if normalized not in AUTH_SCHEMES:
        choices = ", ".join(sorted(AUTH_SCHEMES))
        raise ConfigError(f"auth_scheme must be one of: {choices}.")
    return normalized


def validate_timeout(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ConfigError("timeout must be a number of seconds.")
    result = float(value)
    if not math.isfinite(result) or not TIMEOUT_MIN <= result <= TIMEOUT_MAX:
        raise ConfigError(f"timeout must be between {TIMEOUT_MIN} and {TIMEOUT_MAX} seconds.")
    return result


def validate_effective_config(config: CliConfig) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    try:
        base_url = effective_base_url(config)
    except ConfigError as exc:
        errors.append(str(exc))
    else:
        if not base_url:
            errors.append(f"Base URL is not set ({ENV_BASE_URL} or config).")
        elif base_url.startswith("http://"):
            warnings.append("Base URL uses HTTP; credentials and payloads will not be encrypted.")
    try:
        scheme = effective_auth_scheme(config)
    except ConfigError as exc:
        errors.append(str(exc))
        scheme = "none"
    if scheme != "none" and not effective_api_key(config):
        errors.append(f"API key is not set ({ENV_API_KEY} or config).")
    if not config.verify_tls:
        warnings.append("TLS verification is disabled in config.")
    return errors, warnings


def _normalize(raw: Mapping[Any, Any]) -> CliConfig:
    allowed = {field.name for field in fields(CliConfig)}
    result = {str(key): value for key, value in raw.items() if str(key) in allowed}
    base_url_value = result.get("base_url")
    base_url: str | None = None
    if base_url_value is not None:
        if not isinstance(base_url_value, str):
            raise ConfigError("base_url must be a string or null.")
        base_url = normalize_base_url(base_url_value) if base_url_value.strip() else None
    api_key_value = result.get("api_key")
    api_key: str | None = None
    if api_key_value is not None:
        if not isinstance(api_key_value, str):
            raise ConfigError("api_key must be a string or null.")
        api_key = api_key_value.strip() or None
    auth_scheme = validate_auth_scheme(result.get("auth_scheme", "bearer"))
    verify_tls = result.get("verify_tls", True)
    if not isinstance(verify_tls, bool):
        raise ConfigError("verify_tls must be true or false.")
    timeout = validate_timeout(result.get("timeout", 30.0))
    return CliConfig(
        base_url=base_url,
        api_key=api_key,
        auth_scheme=auth_scheme,
        verify_tls=verify_tls,
        timeout=timeout,
    )


def _tighten_directory_permissions(path: Path) -> None:
    with suppress(OSError, PermissionError):
        path.chmod(stat.S_IRWXU)


def _tighten_file_permissions(path: Path) -> None:
    with suppress(OSError, PermissionError):
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
