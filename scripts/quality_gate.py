#!/usr/bin/env python3
"""Run the deterministic local checks used by CI."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Check:
    name: str
    arguments: tuple[str, ...]


def checks() -> tuple[Check, ...]:
    python = sys.executable
    return (
        Check("dependency alignment", (python, "scripts/check_dependency_alignment.py")),
        Check(
            "version alignment",
            (python, "scripts/check_release_contract.py", "version-alignment"),
        ),
        Check(
            "bundled contract",
            (python, "scripts/check_release_contract.py", "bundled-contract"),
        ),
        Check(
            "package data",
            (python, "scripts/check_release_contract.py", "package-data"),
        ),
        Check(
            "public boundary",
            (python, "scripts/check_release_contract.py", "public-boundary"),
        ),
        Check("secret scan", (python, "scripts/check_secret_scan.py")),
        Check("public safety", (python, "scripts/check_public_safety.py")),
        Check("ruff", (python, "-m", "ruff", "check", "src", "tests", "scripts")),
        Check(
            "mypy",
            (python, "-m", "mypy", "src", "tests", "scripts", "--cache-dir", "/tmp/avl-cli-mypy"),
        ),
        Check("pytest", (python, "-m", "pytest", "-q")),
    )


def main() -> int:
    for check in checks():
        print(f"==> {check.name}", flush=True)
        completed = subprocess.run(check.arguments, cwd=ROOT, check=False)
        if completed.returncode:
            print(f"Quality gate failed at {check.name}.", file=sys.stderr)
            return completed.returncode
    print("Quality gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
