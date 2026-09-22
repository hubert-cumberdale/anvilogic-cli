"""Strict JSON decoding shared by config, payload, and model inputs."""

from __future__ import annotations

import json
from typing import Any


def loads_json(value: str) -> Any:
    return json.loads(
        value,
        object_pairs_hook=_object_without_duplicates,
        parse_constant=_reject_constant,
    )


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate object key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite number {value}")
