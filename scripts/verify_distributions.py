#!/usr/bin/env python3
"""Verify that built wheel and sdist archives contain the exact bundled contract."""

from __future__ import annotations

import argparse
import importlib
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # pragma: no cover - direct script execution fallback.
    sys.path.insert(0, str(ROOT))
check_public_safety = importlib.import_module("scripts.check_public_safety")
SCHEMA_NAME = "threat_scenario_record.schema.json"
SCHEMA_PATH = ROOT / "src" / "anvilogic_cli" / SCHEMA_NAME
FORBIDDEN_MODEL_NAMES = {
    "anvilogic-combined-apis.yaml",
    "models.md",
    "openapi.yaml",
    "openapi.yml",
    "schemas.json",
}


def _wheel_schema(path: Path) -> bytes:
    with zipfile.ZipFile(path) as archive:
        forbidden = [
            name
            for name in archive.namelist()
            if Path(name).name.casefold() in FORBIDDEN_MODEL_NAMES
        ]
        if forbidden:
            raise ValueError(f"{path.name} contains forbidden model catalogs: {forbidden}")
        names = [name for name in archive.namelist() if name.endswith(f"/{SCHEMA_NAME}")]
        if names != [f"anvilogic_cli/{SCHEMA_NAME}"]:
            raise ValueError(f"{path.name} has unexpected schema entries: {names}")
        return archive.read(names[0])


def _sdist_schema(path: Path) -> bytes:
    with tarfile.open(path, mode="r:gz") as archive:
        forbidden = [
            member.name
            for member in archive.getmembers()
            if member.isfile() and Path(member.name).name.casefold() in FORBIDDEN_MODEL_NAMES
        ]
        if forbidden:
            raise ValueError(f"{path.name} contains forbidden model catalogs: {forbidden}")
        members = [
            member
            for member in archive.getmembers()
            if member.isfile() and member.name.endswith(f"/src/anvilogic_cli/{SCHEMA_NAME}")
        ]
        if len(members) != 1:
            raise ValueError(
                f"{path.name} has {len(members)} schema entries; expected exactly one."
            )
        extracted = archive.extractfile(members[0])
        if extracted is None:
            raise ValueError(f"Could not read schema from {path.name}.")
        return extracted.read()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist_dir", nargs="?", type=Path, default=ROOT / "dist")
    arguments = parser.parse_args()
    wheels = sorted(arguments.dist_dir.glob("*.whl"))
    sdists = sorted(arguments.dist_dir.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        print(
            f"Expected one wheel and one sdist, found {len(wheels)} wheel(s) and "
            f"{len(sdists)} sdist(s).",
            file=sys.stderr,
        )
        return 1
    expected = SCHEMA_PATH.read_bytes()
    try:
        packaged = {
            wheels[0].name: _wheel_schema(wheels[0]),
            sdists[0].name: _sdist_schema(sdists[0]),
        }
        safety_errors = [
            *check_public_safety.scan_wheel(wheels[0]),
            *check_public_safety.scan_sdist(sdists[0]),
        ]
    except (OSError, tarfile.TarError, ValueError, zipfile.BadZipFile) as exc:
        print(f"Distribution verification failed: {exc}", file=sys.stderr)
        return 1
    mismatches = [name for name, body in packaged.items() if body != expected]
    if mismatches:
        print(
            "Distribution schema bytes differ from source: " + ", ".join(mismatches),
            file=sys.stderr,
        )
        return 1
    if safety_errors:
        print(
            "Distribution public-safety scan failed:\n- " + "\n- ".join(safety_errors),
            file=sys.stderr,
        )
        return 1
    print("Wheel and sdist passed exact-schema and full-content public-safety checks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
