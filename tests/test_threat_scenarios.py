from __future__ import annotations

import copy
import hashlib
import json
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest

from anvilogic_cli.threat_scenarios import (
    SCENARIO_DETAIL_OPERATION,
    SCENARIO_GROUP_OPERATION,
    SCENARIO_LIST_OPERATION,
    SCHEMA_ID,
    CollectionResult,
    ThreatScenarioCollectionError,
    ThreatScenarioCollector,
    ThreatScenarioContractError,
    threat_scenario_schema_bytes,
    validate_threat_scenario_record,
    write_collection,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _summary(scenario_id: str, title: str) -> dict[str, str]:
    return {"use_case_id": scenario_id, "use_case_title": title}


def _observed_page(
    page: int,
    hits: list[tuple[str, int]],
    *,
    total: int = 2,
    page_size: int = 1,
) -> dict[str, Any]:
    payload = json.loads((FIXTURES / "scenario_list_page.json").read_text(encoding="utf-8"))
    payload["hits"] = {
        scenario_id: {
            "use_case_id": scenario_id,
            "use_case_title": f"Synthetic {scenario_id}",
            "modification_time": modification_time,
        }
        for scenario_id, modification_time in hits
    }
    metadata = payload["searchMetadata"]
    metadata.update(
        {
            "currPageResults": len(hits),
            "numPages": (total + page_size - 1) // page_size if total else 0,
            "pageNum": page,
            "paginationTotal": total,
            "reqDocsPerPage": page_size,
            "totalResults": total,
        }
    )
    return cast(dict[str, Any], payload)


def _fixture_request(
    list_pages: Iterator[dict[str, Any]],
    *,
    detail_overrides: dict[str, dict[str, Any]] | None = None,
):
    details = {
        "TS-1": {
            "use_case_id": "TS-1",
            "use_case_title": "Credential access",
            "victim_platform": ["Windows"],
            "threatScenario": {
                "stageOrder": [
                    {"id": "stage-a", "name": "Initial"},
                    {"id": "stage-b", "name": "Collect"},
                ]
            },
        },
        "TS-2": {
            "use_case_id": "TS-2",
            "use_case_title": "Persistence",
            "victim_platform": ["Linux"],
            "threatScenario": {"stageOrder": ["Persist"]},
        },
        "TI-1": {
            "use_case_title": "PowerShell",
            "mitre_subtechnique": ["T1059.001"],
            "mitre_tactic": ["Execution"],
            "references": ["https://example.com/reference"],
            "rules": [{"rule_id": "AVL_R1000", "rule_logic": "never-export"}],
            "authorization": "Bearer never-export",
        },
        "TI-2": {"use_case_title": "Metadata needed"},
    }
    details.update(detail_overrides or {})
    groups = {
        "TS-1": {
            "search_ui_scenario_result": [
                {
                    "id": "stage-a",
                    "name": "Initial",
                    "totalUseCases": 1,
                    "result_list": [{"use_case_id": "TI-1"}],
                },
                {
                    "id": "stage-b",
                    "name": "Collect",
                    "totalUseCases": 1,
                    "result_list": [{"use_case_id": "TI-2"}],
                },
            ]
        },
        "TS-2": {
            "search_ui_scenario_result": [
                {
                    "id": "Persist",
                    "totalUseCases": 1,
                    "result_list": [{"use_case_id": "TI-1"}],
                }
            ]
        },
    }

    def request(
        operation_id: str,
        body: dict[str, Any] | None,
        query: list[tuple[str, str]],
    ) -> Any:
        if operation_id == SCENARIO_LIST_OPERATION:
            return next(list_pages)
        if operation_id == SCENARIO_GROUP_OPERATION:
            assert body is not None
            assert body["listIdentifierUseCasesOnly"] is True
            return groups[body["use_case_id"]]
        assert operation_id == SCENARIO_DETAIL_OPERATION
        return details[dict(query)["usecaseid"]]

    return request


def test_collects_multiple_pages_and_ordered_stages() -> None:
    pages = iter(
        [
            _observed_page(1, [("TS-1", 200)]),
            _observed_page(2, [("TS-2", 100)]),
        ]
    )

    result = ThreatScenarioCollector(_fixture_request(pages), page_size=1).collect()

    assert [item["id"] for item in result.scenarios] == ["TS-1", "TS-2"]
    assert [stage["name"] for stage in result.scenarios[0]["stages"]] == [
        "Initial",
        "Collect",
    ]
    first_identifier = result.scenarios[0]["stages"][0]["identifiers"][0]
    assert first_identifier["attack_ids"] == ["T1059.001"]
    assert first_identifier["platforms"] == ["Windows"]
    assert first_identifier["rule_ids"] == ["AVL_R1000"]
    assert result.source["sort"] == {"field": "modification_time", "direction": "desc"}
    normalized = json.dumps(result.scenarios)
    assert "never-export" not in normalized
    assert "authorization" not in normalized.casefold()
    assert "rule_logic" not in normalized.casefold()


def test_collection_restarts_once_when_total_changes() -> None:
    pages = iter(
        [
            _observed_page(1, [("TS-1", 200)]),
            _observed_page(2, [("TS-2", 100)], total=3),
            _observed_page(1, [("TS-1", 200)], total=1),
        ]
    )

    result = ThreatScenarioCollector(_fixture_request(pages), page_size=1).collect()

    assert result.attempts == 2
    assert [item["id"] for item in result.scenarios] == ["TS-1"]


def test_observed_envelope_and_full_detail_group_requests_match_contract() -> None:
    calls: list[tuple[str, dict[str, Any] | None, list[tuple[str, str]]]] = []
    detail = {
        "use_case_id": "TS-1",
        "use_case_title": "One",
        "victim_platform": ["Windows"],
        "threatScenario": {"stageOrder": ["stage-a"]},
    }

    def request(
        operation_id: str,
        body: dict[str, Any] | None,
        query: list[tuple[str, str]],
    ) -> Any:
        calls.append((operation_id, body, query))
        if operation_id == SCENARIO_LIST_OPERATION:
            return _observed_page(1, [("TS-1", 200)], total=1, page_size=100)
        if operation_id == SCENARIO_GROUP_OPERATION:
            return {
                "search_ui_scenario_result": [
                    {
                        "id": "stage-a",
                        "totalUseCases": 2,
                        "result_list": [{"use_case_id": "TI-1"}, {"use_case_id": "TI-2"}],
                    }
                ]
            }
        requested_id = dict(query)["usecaseid"]
        if requested_id == "TS-1":
            return detail
        return {"use_case_title": requested_id, "mitre_technique": ["T1003"]}

    result = ThreatScenarioCollector(request, page_size=100).collect()

    identifiers = result.scenarios[0]["stages"][0]["identifiers"]
    assert [item["id"] for item in identifiers] == ["TI-1", "TI-2"]
    assert calls[0] == (
        SCENARIO_LIST_OPERATION,
        {
            "filter": {},
            "myOrg": False,
            "pageNum": 1,
            "query": "*",
            "reqDocsPerPage": 100,
            "sortCriteria": {"sortedBy": {"modification_time:latest": "DESC"}},
        },
        [],
    )
    assert calls[2] == (
        SCENARIO_GROUP_OPERATION,
        {**detail, "listIdentifierUseCasesOnly": True},
        [("summary", "true")],
    )
    assert sum(call[0] == SCENARIO_GROUP_OPERATION for call in calls) == 1


def test_only_verified_group_response_supplies_identifier_membership() -> None:
    pages = iter([_observed_page(1, [("TS-1", 200)], total=1)])
    detail = {
        "use_case_id": "TS-1",
        "use_case_title": "One",
        "threatScenario": {"stageOrder": ["stage-a", "stage-b"]},
        "stageMappings": {"stage-a": [{"use_case_id": "TI-extra"}]},
    }

    result = ThreatScenarioCollector(
        _fixture_request(pages, detail_overrides={"TS-1": detail}), page_size=1
    ).collect()

    assert [
        identifier["id"]
        for stage in result.scenarios[0]["stages"]
        for identifier in stage["identifiers"]
    ] == ["TI-1", "TI-2"]


def test_stage_order_disagreement_fails_closed() -> None:
    pages = iter(
        [
            _observed_page(1, [("TS-1", 200)], total=1),
            _observed_page(1, [("TS-1", 200)], total=1),
        ]
    )
    detail = {
        "use_case_id": "TS-1",
        "threatScenario": {"stageOrder": ["stage-a"]},
    }

    with pytest.raises(ThreatScenarioCollectionError, match="disagreed with stage membership"):
        ThreatScenarioCollector(
            _fixture_request(pages, detail_overrides={"TS-1": detail}), page_size=1
        ).collect()


def _collect_list_pages(
    pages: list[dict[str, Any]], *, page_size: int = 1
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    def request(
        operation_id: str,
        body: dict[str, Any] | None,
        query: list[tuple[str, str]],
    ) -> Any:
        assert operation_id == SCENARIO_LIST_OPERATION
        assert body is not None
        assert query == []
        return pages[body["pageNum"] - 1]

    return ThreatScenarioCollector(request, page_size=page_size)._collect_summaries()


def test_observed_pages_validate_and_preserve_descending_hit_order() -> None:
    summaries, source = _collect_list_pages(
        [_observed_page(1, [("TS-1", 200)]), _observed_page(2, [("TS-2", 100)])]
    )

    assert [summary["use_case_id"] for summary in summaries] == ["TS-1", "TS-2"]
    assert source == {
        "operation": SCENARIO_LIST_OPERATION,
        "page_size": 1,
        "pages": 2,
        "total_results": 2,
        "sort": {"field": "modification_time", "direction": "desc"},
    }


def test_observed_hit_mapping_is_ordered_by_modification_time_before_page_checks() -> None:
    summaries, _source = _collect_list_pages(
        [_observed_page(1, [("TS-1", 100), ("TS-2", 200)], total=2, page_size=2)],
        page_size=2,
    )

    assert [summary["use_case_id"] for summary in summaries] == ["TS-2", "TS-1"]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("pageNum", 1, "returned page"),
        ("reqDocsPerPage", 2, "page-size metadata"),
        ("currPageResults", 0, "current-page metadata"),
        ("numPages", 3, "page-count metadata"),
        ("paginationTotal", 3, "paginationTotal"),
    ],
)
def test_observed_list_rejects_metadata_drift(
    field: str, value: int, message: str
) -> None:
    pages = [_observed_page(1, [("TS-1", 200)]), _observed_page(2, [("TS-2", 100)])]
    pages[1]["searchMetadata"][field] = value

    with pytest.raises(ThreatScenarioCollectionError, match=message):
        _collect_list_pages(pages)


def test_observed_list_rejects_wrong_returned_sort() -> None:
    page = _observed_page(1, [("TS-1", 200)], total=1)
    page["searchMetadata"]["sortCriteria"]["sortedBy"] = {
        "modification_time:earliest": "ASC"
    }

    with pytest.raises(ThreatScenarioCollectionError, match="requested modification-time sort"):
        _collect_list_pages([page])


def test_observed_list_rejects_invalid_descending_order() -> None:
    pages = [_observed_page(1, [("TS-1", 100)]), _observed_page(2, [("TS-2", 200)])]

    with pytest.raises(ThreatScenarioCollectionError, match="not ordered"):
        _collect_list_pages(pages)


def test_observed_list_rejects_hit_key_id_mismatch() -> None:
    page = _observed_page(1, [("TS-1", 200)], total=1)
    page["hits"]["TS-1"]["use_case_id"] = "TS-2"

    with pytest.raises(ThreatScenarioCollectionError, match="hit key did not match"):
        _collect_list_pages([page])


@pytest.mark.parametrize(
    ("hits", "message"),
    [
        ([], "top-level hits mapping"),
        ({"TS-1": "not-an-object"}, "non-object hit"),
        ({"TS-1": {"use_case_id": "TS-1"}}, "modification_time"),
        ({"TS-1": {"modification_time": 200}}, "hit without an ID"),
    ],
)
def test_observed_list_rejects_malformed_hits(hits: Any, message: str) -> None:
    page = _observed_page(1, [("TS-1", 200)], total=1)
    page["hits"] = hits

    with pytest.raises(ThreatScenarioCollectionError, match=message):
        _collect_list_pages([page])


def test_observed_list_rejects_duplicate_hits_between_pages() -> None:
    pages = [_observed_page(1, [("TS-1", 200)]), _observed_page(2, [("TS-1", 100)])]

    with pytest.raises(ThreatScenarioCollectionError, match="duplicated between list pages"):
        _collect_list_pages(pages)


def test_observed_list_rejects_empty_page_before_total() -> None:
    pages = [_observed_page(1, [("TS-1", 200)]), _observed_page(2, [])]

    with pytest.raises(ThreatScenarioCollectionError, match="current-page count"):
        _collect_list_pages(pages)


def test_list_rejects_unverified_envelope() -> None:
    with pytest.raises(ThreatScenarioCollectionError, match="top-level hits mapping"):
        _collect_list_pages([{"totalResults": 1, "results": [_summary("TS-1", "One")]}])


def test_group_membership_accepts_populated_and_empty_stages_without_pagination() -> None:
    detail = {"use_case_id": "TS-1", "threatScenario": {"stageOrder": ["a", "b"]}}
    payload = {
        "search_ui_scenario_result": [
            {
                "id": "a",
                "totalUseCases": 1,
                "result_list": [{"use_case_id": "TI-1"}],
            },
            {"id": "b"},
        ]
    }
    calls: list[tuple[dict[str, Any] | None, list[tuple[str, str]]]] = []

    def request(
        operation_id: str,
        body: dict[str, Any] | None,
        query: list[tuple[str, str]],
    ) -> Any:
        assert operation_id == SCENARIO_GROUP_OPERATION
        calls.append((body, query))
        return payload

    result = ThreatScenarioCollector(request)._collect_group_membership(detail, "TS-1")

    assert result == payload
    assert calls == [({**detail, "listIdentifierUseCasesOnly": True}, [("summary", "true")])]


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        (
            [
                {
                    "id": "a",
                    "totalUseCases": 2,
                    "result_list": [{"use_case_id": "TI-1"}],
                }
            ],
            "did not match totalUseCases",
        ),
        (
            [{"id": "a", "result_list": [{"use_case_id": "TI-1"}]}],
            "valid totalUseCases",
        ),
        ([{"id": "a", "result_list": []}], "valid totalUseCases"),
        (
            [{"id": "a", "totalUseCases": 1, "result_list": [{"title": "missing"}]}],
            "malformed identifier membership",
        ),
        ([{"id": "a"}, {"id": "a"}], "duplicated stage"),
        (
            [
                {
                    "id": "a",
                    "totalUseCases": 2,
                    "result_list": [
                        {"use_case_id": "TI-1"},
                        {"use_case_id": "TI-1"},
                    ],
                }
            ],
            "duplicated identifier",
        ),
    ],
)
def test_group_membership_rejects_inconsistent_or_malformed_entries(
    entries: list[dict[str, Any]], message: str
) -> None:
    def request(
        operation_id: str,
        body: dict[str, Any] | None,
        query: list[tuple[str, str]],
    ) -> Any:
        del operation_id, body, query
        return {"search_ui_scenario_result": entries}

    with pytest.raises(ThreatScenarioCollectionError, match=message):
        ThreatScenarioCollector(request)._collect_group_membership(
            {"use_case_id": "TS-1"}, "TS-1"
        )


def test_collection_fails_after_second_incomplete_attempt() -> None:
    pages = iter(
        [
            _observed_page(1, [("TS-1", 200)]),
            _observed_page(2, [("TS-2", 100)], total=3),
            _observed_page(1, [("TS-1", 200)]),
            _observed_page(2, [("TS-2", 100)], total=3),
        ]
    )

    with pytest.raises(ThreatScenarioCollectionError, match="after one restart"):
        ThreatScenarioCollector(_fixture_request(pages), page_size=1).collect()


def test_collection_fails_closed_after_two_malformed_list_responses() -> None:
    responses: Iterator[Any] = iter([["not-an-object"], None])

    with pytest.raises(ThreatScenarioCollectionError, match="after one restart"):
        ThreatScenarioCollector(_fixture_request(responses), page_size=1).collect()


def test_write_collection_is_private_deterministic_and_excludes_secret_fields(
    tmp_path: Path,
) -> None:
    scenario = {
        "schema_version": 1,
        "id": "TS-1",
        "title": "Synthetic",
        "description": "Bounded behavior",
        "platforms": ["Windows"],
        "stages": [
            {
                "order": 1,
                "id": "stage-a",
                "name": "Initial",
                "identifiers": [
                    {
                        "id": "TI-1",
                        "title": "PowerShell",
                        "behavioral_intent": "Launch a benign process",
                        "attack_ids": ["T1059.001"],
                        "tactics": ["Execution"],
                        "platforms": ["Windows"],
                        "references": ["https://example.com/reference"],
                        "rule_ids": ["AVL_R1000"],
                    }
                ],
            }
        ],
    }
    result = CollectionResult(
        scenarios=[scenario],
        findings=[],
        source={"total_results": 1},
        attempts=1,
    )
    output_dir = tmp_path / "private"

    first_manifest = write_collection(output_dir, result)

    assert stat.S_IMODE(output_dir.stat().st_mode) == 0o700
    for path in output_dir.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    raw = (output_dir / "threat_scenarios.jsonl").read_text(encoding="utf-8")
    assert "authorization" not in raw.casefold()
    assert "rule_logic" not in raw.casefold()
    assert first_manifest["completeness"] == "complete"
    assert first_manifest["counts"]["platform_mappings"] == 1
    assert first_manifest["record_schema"] == {
        "id": SCHEMA_ID,
        "version": 1,
        "sha256": hashlib.sha256(threat_scenario_schema_bytes()).hexdigest(),
    }
    stored = json.loads((output_dir / "collection_manifest.json").read_text())
    assert stored == first_manifest
    with pytest.raises(ValueError, match="already exist"):
        write_collection(output_dir, result)


def _golden_record() -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads((FIXTURES / "threat_scenario_record_v1.json").read_text(encoding="utf-8")),
    )


def test_golden_v1_record_remains_compatible() -> None:
    validate_threat_scenario_record(_golden_record())


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda record: record.pop("title"), "required property"),
        (lambda record: record.update({"undeclared": True}), "Additional properties"),
        (
            lambda record: record["stages"][0]["identifiers"][0]["attack_ids"].append(
                "TA0001"
            ),
            "does not match",
        ),
        (
            lambda record: record["stages"][0].update({"identifiers": {"id": "TI-1"}}),
            "is not of type 'array'",
        ),
    ],
)
def test_v1_contract_rejects_missing_extra_invalid_attack_and_malformed_nesting(
    mutation, message: str
) -> None:
    record = copy.deepcopy(_golden_record())
    mutation(record)

    with pytest.raises(ThreatScenarioContractError, match=message):
        validate_threat_scenario_record(record)


def test_contract_violation_fails_before_output_directory_creation(tmp_path: Path) -> None:
    record = _golden_record()
    record["stages"][0]["identifiers"][0]["attack_ids"] = ["invalid"]
    result = CollectionResult(
        scenarios=[record],
        findings=[],
        source={"total_results": 1},
        attempts=1,
    )
    output_dir = tmp_path / "must-not-exist"

    with pytest.raises(ThreatScenarioContractError, match="Record 0"):
        write_collection(output_dir, result)

    assert not output_dir.exists()
