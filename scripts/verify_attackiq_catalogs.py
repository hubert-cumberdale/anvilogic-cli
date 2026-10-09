#!/usr/bin/env python3
"""Verify that two private AttackIQ scenario exports are stable for reconciliation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


class CatalogVerificationError(ValueError):
    """Raised when an AttackIQ export cannot support stable reconciliation."""


def _load_export(path: Path, label: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CatalogVerificationError(f"{label} AttackIQ export is not readable JSON.") from exc
    if isinstance(payload, dict):
        payload = payload.get("results")
    if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
        raise CatalogVerificationError(
            f"{label} AttackIQ export must be a JSON list of objects."
        )
    if not payload:
        raise CatalogVerificationError(f"{label} AttackIQ export contains no scenarios.")
    return payload


def _stable_projection(
    scenarios: list[dict[str, Any]],
    label: str,
) -> dict[str, dict[str, Any]]:
    projection: dict[str, dict[str, Any]] = {}
    for scenario in scenarios:
        scenario_id = scenario.get("id")
        if not isinstance(scenario_id, str) or not scenario_id.strip():
            raise CatalogVerificationError(
                f"{label} AttackIQ export contains an empty or non-string scenario ID."
            )
        scenario_id = scenario_id.strip()
        if scenario_id in projection:
            raise CatalogVerificationError(
                f"{label} AttackIQ export contains duplicate scenario IDs."
            )
        modified = scenario.get("modified")
        if not isinstance(modified, str) or not modified.strip():
            raise CatalogVerificationError(
                f"{label} AttackIQ export contains a scenario without a modification value."
            )
        tags = scenario.get("scenario_tags")
        if tags is None:
            tags = scenario.get("tags")
        stable_fields = {
            "modified": modified.strip(),
            "scenario_tags": tags,
            "supported_platforms": scenario.get("supported_platforms"),
        }
        try:
            json.dumps(stable_fields, sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise CatalogVerificationError(
                f"{label} AttackIQ export has non-JSON reconciliation fields."
            ) from exc
        projection[scenario_id] = stable_fields
    return projection


def verify_catalogs(first_path: Path, second_path: Path) -> dict[str, Any]:
    first = _stable_projection(_load_export(first_path, "First"), "First")
    second = _stable_projection(_load_export(second_path, "Second"), "Second")
    if first.keys() != second.keys():
        difference_count = len(first.keys() ^ second.keys())
        raise CatalogVerificationError(
            "AttackIQ scenario ID sets differ "
            f"({difference_count} scenario difference(s)); retry later."
        )
    changed_count = sum(first[scenario_id] != second[scenario_id] for scenario_id in first)
    if changed_count:
        raise CatalogVerificationError(
            "AttackIQ reconciliation fields drifted "
            f"for {changed_count} scenario(s); retry later."
        )
    return {"scenario_count": len(first), "stable": True}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Compare two private AttackIQ exports without printing scenario IDs or payloads."
        )
    )
    parser.add_argument("first", type=Path, help="First AttackIQ scenarios JSON export.")
    parser.add_argument("second", type=Path, help="Second AttackIQ scenarios JSON export.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = verify_catalogs(args.first, args.second)
    except CatalogVerificationError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
