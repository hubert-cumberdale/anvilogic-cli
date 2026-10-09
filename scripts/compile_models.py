#!/usr/bin/env python3
"""Compile a caller-supplied Markdown schema export into a deterministic local catalog."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

JSON_BLOCK_RE = re.compile(r"^```json\s*\n(.*?)\n```\s*$", re.MULTILINE | re.DOTALL)


def strict_json_loads(value: str) -> Any:
    def object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate object key {key!r}")
            result[key] = item
        return result

    def reject_constant(constant: str) -> None:
        raise ValueError(f"non-finite number {constant}")

    return json.loads(
        value,
        object_pairs_hook=object_without_duplicates,
        parse_constant=reject_constant,
    )


def compile_export(source: bytes, *, source_name: str) -> dict[str, Any]:
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("model export must be UTF-8") from exc
    blocks = JSON_BLOCK_RE.findall(text)
    if not blocks:
        raise ValueError("model export contains no fenced JSON blocks")
    schemas: dict[str, dict[str, Any]] = {}
    versions: set[str] = set()
    for block_number, block in enumerate(blocks, start=1):
        try:
            fragment = strict_json_loads(block)
            components = fragment["components"]["schemas"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ValueError(f"block {block_number} is not an OpenAPI schema fragment") from exc
        if not isinstance(components, dict) or not components:
            raise ValueError(f"block {block_number} contains no component schemas")
        version = fragment.get("info", {}).get("version")
        if isinstance(version, str):
            versions.add(version)
        for name, schema in components.items():
            if not isinstance(name, str) or not isinstance(schema, dict):
                raise ValueError(f"block {block_number} contains an invalid component schema")
            existing = schemas.get(name)
            if existing is not None and existing != schema:
                raise ValueError(f"conflicting definitions found for model {name!r}")
            schemas[name] = schema
    version_label = ", ".join(sorted(versions)) if versions else "unknown"
    return {
        "openapi": "3.0.0",
        "info": {"title": "Anvilogic exported models", "version": version_label},
        "components": {
            "schemas": dict(sorted(schemas.items(), key=lambda item: item[0].casefold()))
        },
        "x-anvilogic-source": {
            "file": source_name,
            "fragments": len(blocks),
            "sha256": hashlib.sha256(source).hexdigest(),
        },
    }


def render_catalog(catalog: dict[str, Any]) -> bytes:
    return (json.dumps(catalog, sort_keys=True, separators=(",", ":")) + "\n").encode()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--check", action="store_true", help="Fail if the compiled catalog is missing or stale."
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        source = args.input.read_bytes()
        catalog = compile_export(source, source_name=args.input.name)
        rendered = render_catalog(catalog)
    except (OSError, ValueError) as exc:
        print(f"Model compilation failed: {exc}", file=sys.stderr)
        return 2
    if args.check:
        try:
            current = args.output.read_bytes()
        except OSError:
            current = b""
        if current != rendered:
            print(
                f"Compiled model catalog is stale; run {Path(__file__).name}.", file=sys.stderr
            )
            return 1
        print(f"Model catalog is current ({len(catalog['components']['schemas'])} models).")
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(rendered)
    print(f"Wrote {len(catalog['components']['schemas'])} models to {args.output}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
