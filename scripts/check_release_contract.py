#!/usr/bin/env python3
"""Check release-version alignment and the bundled threat-scenario contract."""

from __future__ import annotations

import argparse
import json
import re
import sys
from importlib import resources
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_NAME = "threat_scenario_record.schema.json"
SCHEMA_PATH = ROOT / "src" / "anvilogic_cli" / SCHEMA_NAME
GOLDEN_PATH = ROOT / "tests" / "fixtures" / "threat_scenario_record_v1.json"
SCHEMA_ID = "urn:anvilogic-cli:threat-scenario-record:1"


def _match(pattern: str, text: str, label: str) -> str:
    match = re.search(pattern, text, flags=re.MULTILINE)
    if not match:
        raise ValueError(f"Could not find {label}.")
    return match.group(1)


def check_version_alignment() -> list[str]:
    errors: list[str] = []
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    package = (ROOT / "src" / "anvilogic_cli" / "__init__.py").read_text(encoding="utf-8")
    state = (ROOT / "docs" / "STATE.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    try:
        versions = {
            "pyproject.toml": _match(r'^version = "([^"]+)"$', pyproject, "project version"),
            "anvilogic_cli/__init__.py": _match(
                r'^__version__ = "([^"]+)"$', package, "package version"
            ),
            "docs/STATE.md": _match(r"^- Version: `([^`]+)`\.$", state, "state version"),
            "README.md": _match(r"^Current release: `([^`]+)`", readme, "README version"),
        }
    except ValueError as exc:
        return [str(exc)]
    expected = versions["pyproject.toml"]
    for label, actual in versions.items():
        if actual != expected:
            errors.append(f"{label} declares {actual}, expected {expected}.")
    if not re.search(rf"^## {re.escape(expected)}(?:\s+-|$)", changelog, flags=re.MULTILINE):
        errors.append(f"CHANGELOG.md has no release section for {expected}.")
    if "Development Status :: 3 - Alpha" not in pyproject:
        errors.append("pyproject.toml must retain the Alpha classifier.")
    if "Lifecycle: Alpha; not production-qualified." not in state:
        errors.append("docs/STATE.md must retain the Alpha/not-production-qualified status.")
    return errors


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def check_bundled_contract() -> list[str]:
    errors: list[str] = []
    try:
        body = SCHEMA_PATH.read_bytes()
        schema = json.loads(body)
        if not isinstance(schema, dict):
            return ["Bundled threat-scenario schema root is not an object."]
        Draft202012Validator.check_schema(schema)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, SchemaError) as exc:
        return [f"Bundled threat-scenario schema is invalid: {exc}"]
    expected_body = (json.dumps(schema, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if body != expected_body:
        errors.append("Bundled threat-scenario schema is not deterministically formatted.")
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        errors.append("Bundled threat-scenario schema is not JSON Schema 2020-12.")
    if schema.get("$id") != SCHEMA_ID:
        errors.append(f"Bundled threat-scenario schema ID must be {SCHEMA_ID}.")
    if schema.get("properties", {}).get("schema_version", {}).get("const") != 1:
        errors.append("Bundled threat-scenario schema must require schema_version 1.")
    try:
        golden = _load_json(GOLDEN_PATH)
        validation_errors = list(Draft202012Validator(schema).iter_errors(golden))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        errors.append(f"Golden v1 record is unavailable or invalid JSON: {exc}")
    else:
        if validation_errors:
            errors.append(f"Golden v1 record violates the bundled schema: {validation_errors[0]}")
    return errors


def check_package_data() -> list[str]:
    errors: list[str] = []
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    package_data = _match(
        r"(?s)\[tool\.setuptools\.package-data\]\s*(.*?)(?:\n\[|\Z)",
        pyproject,
        "setuptools package-data section",
    )
    if SCHEMA_NAME not in package_data:
        errors.append(f"pyproject.toml package data omits {SCHEMA_NAME}.")
    if "operations.json" not in package_data:
        errors.append("pyproject.toml package data omits operations.json.")
    if "schemas.json" in package_data:
        errors.append("pyproject.toml must not package a model catalog.")
    try:
        packaged = resources.files("anvilogic_cli").joinpath(SCHEMA_NAME).read_bytes()
        source = SCHEMA_PATH.read_bytes()
    except OSError as exc:
        errors.append(f"Installed package data is unavailable: {exc}")
    else:
        if packaged != source:
            errors.append("Installed and source threat-scenario schemas differ.")
    return errors


def check_public_boundary() -> list[str]:
    errors: list[str] = []
    forbidden = [ROOT / "models.md", ROOT / "src" / "anvilogic_cli" / "schemas.json"]
    for path in forbidden:
        if path.exists():
            errors.append(f"Forbidden public model artifact exists: {path.relative_to(ROOT)}.")
    return errors


CHECKS = {
    "version-alignment": check_version_alignment,
    "bundled-contract": check_bundled_contract,
    "package-data": check_package_data,
    "public-boundary": check_public_boundary,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("check", choices=CHECKS)
    arguments = parser.parse_args()
    try:
        errors = CHECKS[arguments.check]()
    except (OSError, ValueError) as exc:
        errors = [str(exc)]
    if errors:
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"{arguments.check} check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
