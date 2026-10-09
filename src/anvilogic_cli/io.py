from __future__ import annotations

import json
import os
import stat
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any

from anvilogic_cli.json_utils import loads_json


def load_json_input(data: str | None, data_file: Path | None) -> Any:
    if data is not None and data_file is not None:
        raise ValueError("Provide either --data or --data-file, not both.")
    if data_file is not None:
        try:
            raw = data_file.read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError(f"Could not read JSON file: {data_file}") from exc
        label = str(data_file)
    elif data is not None:
        raw = data
        label = "--data"
    else:
        return None
    try:
        return loads_json(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{label} is not valid JSON (line {exc.lineno}, column {exc.colno})."
        ) from exc
    except ValueError as exc:
        raise ValueError(f"{label} is not valid JSON ({exc}).") from exc
def parse_pairs(items: list[str], *, separator: str = "=") -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for item in items:
        if separator not in item:
            raise ValueError(f"Expected NAME{separator}VALUE, got {item!r}.")
        name, value = item.split(separator, 1)
        if not name.strip():
            raise ValueError("Names in key/value options cannot be empty.")
        result.append((name.strip(), value.strip()))
    return result


def parse_headers(items: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    folded: set[str] = set()
    for name, value in parse_pairs(items, separator=":"):
        if name.casefold() in folded:
            raise ValueError(f"Duplicate HTTP header: {name}")
        folded.add(name.casefold())
        parsed[name] = value
    return parsed


def response_bytes_and_format(
    body: bytes, content_type: str, requested: str
) -> tuple[bytes, str]:
    chosen = requested
    if chosen == "auto":
        chosen = "json" if "json" in content_type.casefold() else "raw"
    if chosen == "raw":
        return body, "raw"
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("Response body is not valid JSON; use --output-format raw.") from exc
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode(), "json"


def write_output(path: Path, body: bytes, *, force: bool = False) -> None:
    if path.exists() and not force:
        raise ValueError(f"Output file already exists: {path}. Use --force to replace it.")
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(stat.S_IRUSR | stat.S_IWUSR)
        if path.exists() and force:
            path.unlink()
        temporary.replace(path)
    except BaseException:
        with suppress(OSError):
            temporary.unlink(missing_ok=True)
        raise
