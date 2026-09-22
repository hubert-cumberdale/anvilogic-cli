from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts import generate_operations


def seed_registry() -> dict:
    return {
        "version": 2,
        "operations": [
            {
                "confidence": "confirmed",
                "evidence_class": "distilled-private-traffic",
                "id": "stable.get.thing",
                "last_verified": "2026-09-20",
                "method": "GET",
                "path": "/things/{thing_id}",
                "query_params": ["observed"],
                "request_body": False,
                "risk": "read",
            },
            {
                "confidence": "confirmed",
                "evidence_class": "distilled-private-traffic",
                "id": "private.only",
                "last_verified": "2026-09-20",
                "method": "POST",
                "path": "/private",
                "query_params": [],
                "request_body": True,
                "risk": "write",
            },
        ],
    }


def document() -> dict:
    return {
        "openapi": "3.0.0",
        "info": {
            "title": generate_operations.OPENAPI_TITLE,
            "version": generate_operations.OPENAPI_VERSION,
        },
        "paths": {
            "/things/{thing_id}": {
                "get": {
                    "parameters": [{"in": "query", "name": "documented"}],
                }
            },
            "/newItems/{item_id}": {"delete": {}},
        },
    }


def test_generation_is_deterministic_and_preserves_reviewed_ids() -> None:
    first = generate_operations.build_registry(document(), seed_registry())
    second = generate_operations.build_registry(document(), seed_registry())

    assert generate_operations.render_registry(first) == generate_operations.render_registry(second)
    operations = {item["id"]: item for item in first["operations"]}
    assert operations["stable.get.thing"]["query_params"] == ["documented", "observed"]
    assert operations["stable.get.thing"]["evidence"] == [
        "public-openapi",
        "distilled-private-traffic",
    ]
    assert operations["delete.new-items.by-item-id"]["risk"] == "destructive"
    assert operations["private.only"]["confidence"] == "confirmed"


def test_generation_rejects_derived_id_collisions() -> None:
    collision: dict = {
        "paths": {
            "/fooBar": {"get": {}},
            "/foo-bar": {"get": {}},
        }
    }

    with pytest.raises(ValueError, match="collision"):
        generate_operations.build_registry(collision, {"version": 2, "operations": []})


def test_pinned_source_verification_rejects_other_bytes() -> None:
    source = b"openapi: 3.0.0\n"
    assert hashlib.sha256(source).hexdigest() != generate_operations.OPENAPI_SHA256

    with pytest.raises(ValueError, match="SHA-256"):
        generate_operations.verify_pinned_source(source, document())


def test_private_seed_is_independently_checksum_pinned(monkeypatch) -> None:
    source = (json.dumps(seed_registry(), sort_keys=True) + "\n").encode()
    monkeypatch.setattr(
        generate_operations,
        "PRIVATE_SEED_SHA256",
        hashlib.sha256(source).hexdigest(),
    )

    assert generate_operations.load_private_seed(source) == seed_registry()
    with pytest.raises(ValueError, match="Private seed SHA-256"):
        generate_operations.load_private_seed(source.replace(b"private.only", b"private.edit"))


def test_generator_rejects_using_output_as_private_seed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "operations.json"

    result = generate_operations.main(
        [
            "--input",
            str(tmp_path / "openapi.yaml"),
            "--existing",
            str(output),
            "--output",
            str(output),
        ]
    )

    assert result == 2
    assert "must be different files" in capsys.readouterr().err
