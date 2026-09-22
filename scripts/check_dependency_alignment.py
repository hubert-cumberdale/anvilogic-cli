#!/usr/bin/env python3
"""Check that declared build/runtime/dev requirements align with exact constraints."""

from __future__ import annotations

import sys
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10 fallback.
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]


def _declared_requirements(root: Path) -> list[Requirement]:
    payload = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    values = [
        *payload["build-system"]["requires"],
        *payload["project"]["dependencies"],
        *payload["project"]["optional-dependencies"]["dev"],
    ]
    return [Requirement(value) for value in values]


def _active_constraints(root: Path) -> dict[str, Requirement]:
    constraints: dict[str, Requirement] = {}
    for line in (root / "constraints.txt").read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        requirement = Requirement(stripped)
        if requirement.marker is not None and not requirement.marker.evaluate():
            continue
        constraints[canonicalize_name(requirement.name)] = requirement
    return constraints


def check_alignment(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    constraints = _active_constraints(root)
    for declared in _declared_requirements(root):
        name = canonicalize_name(declared.name)
        constrained = constraints.get(name)
        if constrained is None:
            errors.append(f"{declared.name}: no active exact constraint")
            continue
        pins = [
            specifier.version
            for specifier in constrained.specifier
            if specifier.operator == "=="
        ]
        if len(pins) != 1 or len(tuple(constrained.specifier)) != 1:
            errors.append(f"{declared.name}: constraint must contain one exact == pin")
            continue
        if declared.specifier and not declared.specifier.contains(pins[0], prereleases=True):
            errors.append(
                f"{declared.name}: constrained {pins[0]} violates {declared.specifier}"
            )
    return errors


def main() -> int:
    try:
        errors = check_alignment()
    except (OSError, KeyError, ValueError) as exc:
        print(f"Dependency alignment check could not run: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("Dependency declarations align with exact constraints.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
