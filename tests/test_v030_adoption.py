from __future__ import annotations

import copy
import hashlib
import json
from collections import Counter
from collections.abc import Callable, Iterator
from importlib import resources
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

FIXTURES = Path(__file__).parent / "fixtures" / "v0_3_0_adoption"
CORPUS_PATH = FIXTURES / "threat_scenarios.jsonl"
MANIFEST_PATH = FIXTURES / "manifest.json"
SCHEMA_ID = "urn:anvilogic-cli:threat-scenario-record:1"
SCHEMA_RESOURCE = "threat_scenario_record.schema.json"


def _schema_bytes() -> bytes:
    return resources.files("anvilogic_cli").joinpath(SCHEMA_RESOURCE).read_bytes()


def _stream_records(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("rb") as stream:
        for line_number, line in enumerate(stream, start=1):
            assert line.endswith(b"\n"), f"JSONL line {line_number} is not LF-terminated"
            assert line.strip(), f"JSONL line {line_number} is empty"
            record = json.loads(line)
            assert isinstance(record, dict), f"JSONL line {line_number} is not an object"
            yield record


def _deterministic_jsonl(records: list[dict[str, Any]]) -> bytes:
    return b"".join(
        (
            json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
        ).encode("utf-8")
        for record in records
    )


def _counts(records: list[dict[str, Any]]) -> dict[str, int]:
    stages = [stage for record in records for stage in record["stages"]]
    identifiers = [identifier for stage in stages for identifier in stage["identifiers"]]
    return {
        "attack_mappings": sum(len(identifier["attack_ids"]) for identifier in identifiers),
        "identifier_memberships": len(identifiers),
        "platform_mappings": sum(len(identifier["platforms"]) for identifier in identifiers),
        "scenarios": len(records),
        "stages": len(stages),
        "unique_identifiers": len({identifier["id"] for identifier in identifiers}),
    }


def _first_record() -> dict[str, Any]:
    return next(_stream_records(CORPUS_PATH))


def test_v030_corpus_validates_against_released_package_schema() -> None:
    manifest = json.loads(MANIFEST_PATH.read_bytes())
    schema_body = _schema_bytes()
    schema = json.loads(schema_body)
    records = list(_stream_records(CORPUS_PATH))
    validator = Draft202012Validator(schema)

    Draft202012Validator.check_schema(schema)
    assert schema["$id"] == manifest["record_schema"]["id"] == SCHEMA_ID
    assert schema["properties"]["schema_version"]["const"] == 1
    assert manifest["record_schema"]["version"] == manifest["schema_version"] == 1
    assert hashlib.sha256(schema_body).hexdigest() == manifest["record_schema"]["sha256"]
    for line_number, record in enumerate(records, start=1):
        assert record["schema_version"] == 1
        assert list(validator.iter_errors(record)) == [], f"invalid JSONL line {line_number}"


def test_v030_fixture_manifest_reconciles_bytes_and_counts() -> None:
    manifest = json.loads(MANIFEST_PATH.read_bytes())
    artifact = CORPUS_PATH.read_bytes()
    records = list(_stream_records(CORPUS_PATH))

    assert manifest["artifact"]["name"] == CORPUS_PATH.name
    assert hashlib.sha256(artifact).hexdigest() == manifest["artifact"]["sha256"]
    assert len(records) == manifest["artifact"]["records"]
    assert artifact == _deterministic_jsonl(records)
    assert _counts(records) == manifest["counts"]


def test_v030_corpus_covers_representative_record_shapes() -> None:
    records = list(_stream_records(CORPUS_PATH))
    populated = records[0]
    memberships = [
        identifier
        for stage in populated["stages"]
        for identifier in stage["identifiers"]
    ]
    attack_ids = {attack_id for item in memberships for attack_id in item["attack_ids"]}

    assert len(populated["stages"]) > 1
    assert any(not record["stages"] for record in records)
    assert any(not stage["identifiers"] for stage in populated["stages"])
    assert any(count > 1 for count in Counter(item["id"] for item in memberships).values())
    assert any(
        not item[field]
        for item in memberships
        for field in ("platforms", "references", "rule_ids", "tactics")
    )
    assert any("." in attack_id for attack_id in attack_ids)
    assert any("." not in attack_id for attack_id in attack_ids)


def _remove_required(record: dict[str, Any]) -> None:
    record.pop("title")


def _mistype_field(record: dict[str, Any]) -> None:
    record["platforms"] = "Windows"


def _add_field(record: dict[str, Any]) -> None:
    record["tenant"] = "must-not-be-accepted"


def _malform_nested_field(record: dict[str, Any]) -> None:
    record["stages"][0]["identifiers"] = {"id": "TI-SYNTHETIC-001"}


@pytest.mark.parametrize(
    "mutation",
    [_remove_required, _mistype_field, _add_field, _malform_nested_field],
)
def test_released_schema_rejects_incompatible_records(
    mutation: Callable[[dict[str, Any]], None],
) -> None:
    schema = json.loads(_schema_bytes())
    record = copy.deepcopy(_first_record())
    mutation(record)

    assert list(Draft202012Validator(schema).iter_errors(record))
