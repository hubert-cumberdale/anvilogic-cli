from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import os
import re
import stat
import tempfile
from collections.abc import Callable, Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from anvilogic_cli.errors import AnvilogicError

SCHEMA_VERSION = 1
SCHEMA_ID = "urn:anvilogic-cli:threat-scenario-record:1"
SCHEMA_RESOURCE = "threat_scenario_record.schema.json"
ATTACK_ID_RE = re.compile(r"(?<![A-Z0-9.])T\d{4}(?:\.\d{3})?(?![A-Z0-9.])", re.I)
SCENARIO_LIST_OPERATION = "post.api.search.scenario-list-view"
SCENARIO_DETAIL_OPERATION = "get.api.analytic.use-case"
SCENARIO_GROUP_OPERATION = "post.api.search.scenario-group-query"
SCENARIO_SORT_FIELD = "modification_time"
SCENARIO_SORT_DIRECTION = "DESC"

JsonRequest = Callable[[str, dict[str, Any] | None, list[tuple[str, str]]], Any]


class ThreatScenarioCollectionError(AnvilogicError):
    """Raised when a complete, internally consistent collection cannot be proved."""


class ThreatScenarioContractError(AnvilogicError):
    """Raised when a normalized record violates the bundled export contract."""


@dataclass(frozen=True)
class CollectionResult:
    scenarios: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    source: dict[str, Any]
    attempts: int


@dataclass
class _Stage:
    stage_id: str
    name: str
    identifier_ids: list[str]


class ThreatScenarioCollector:
    """Collect normalized threat-scenario data through the reviewed operation catalog."""

    def __init__(self, request: JsonRequest, *, page_size: int = 100) -> None:
        if page_size < 1 or page_size > 100:
            raise ValueError("page_size must be between 1 and 100.")
        self.request = request
        self.page_size = page_size

    def collect(self) -> CollectionResult:
        last_error: ThreatScenarioCollectionError | None = None
        for attempt in (1, 2):
            try:
                summaries, source = self._collect_summaries()
                scenarios, findings = self._collect_details(summaries)
                return CollectionResult(scenarios, findings, source, attempt)
            except ThreatScenarioCollectionError as exc:
                last_error = exc
        assert last_error is not None
        raise ThreatScenarioCollectionError(
            f"Collection changed or was incomplete after one restart: {last_error}"
        ) from last_error

    def _collect_summaries(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        unique: dict[str, dict[str, Any]] = {}
        expected_total: int | None = None
        page = 1
        expected_pages: int | None = None
        previous_modification_time: int | float | None = None
        while expected_pages is None or page <= expected_pages:
            body = {
                "filter": {},
                "myOrg": False,
                "pageNum": page,
                "query": "*",
                "reqDocsPerPage": self.page_size,
                "sortCriteria": {
                    "sortedBy": {
                        f"{SCENARIO_SORT_FIELD}:latest": SCENARIO_SORT_DIRECTION
                    }
                },
            }
            payload = self.request(SCENARIO_LIST_OPERATION, body, [])
            if not isinstance(payload, dict):
                raise ThreatScenarioCollectionError(
                    f"Scenario list page {page} was not a JSON object."
                )

            total, returned_pages, items, modification_times = _observed_list_page(
                payload, page, self.page_size
            )
            if expected_pages is not None and returned_pages != expected_pages:
                raise ThreatScenarioCollectionError(
                    "Scenario list page-count metadata changed during collection."
                )
            for modification_time in modification_times:
                if (
                    previous_modification_time is not None
                    and modification_time > previous_modification_time
                ):
                    raise ThreatScenarioCollectionError(
                        "Scenario list was not ordered by descending modification time."
                    )
                previous_modification_time = modification_time

            if expected_total is None:
                expected_total = total
                expected_pages = returned_pages
            elif total != expected_total:
                raise ThreatScenarioCollectionError(
                    f"Scenario total changed from {expected_total} to {total}."
                )
            if not items and expected_total:
                raise ThreatScenarioCollectionError(
                    f"Scenario list page {page} was empty before the advertised total."
                )
            for raw in items:
                if not isinstance(raw, dict):
                    raise ThreatScenarioCollectionError(
                        f"Scenario list page {page} contained a non-object item."
                    )
                scenario_id = _identifier(raw)
                if not scenario_id:
                    raise ThreatScenarioCollectionError(
                        f"Scenario list page {page} contained an item without an ID."
                    )
                prior = unique.get(scenario_id)
                if prior is not None:
                    raise ThreatScenarioCollectionError(
                        f"Scenario {scenario_id!r} was duplicated between list pages."
                    )
                unique[scenario_id] = raw
            page += 1
        expected_total = expected_total or 0
        if len(unique) != expected_total:
            raise ThreatScenarioCollectionError(
                f"Collected {len(unique)} unique scenarios but API advertised {expected_total}."
            )
        return list(unique.values()), {
            "operation": SCENARIO_LIST_OPERATION,
            "page_size": self.page_size,
            "pages": expected_pages or 0,
            "total_results": expected_total,
            "sort": {"field": SCENARIO_SORT_FIELD, "direction": "desc"},
        }

    def _collect_details(
        self, summaries: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        pending: list[tuple[str, dict[str, Any], dict[str, Any], list[_Stage]]] = []
        findings: list[dict[str, Any]] = []
        identifier_ids: set[str] = set()
        for summary in summaries:
            scenario_id = _identifier(summary)
            detail_payload = self.request(
                SCENARIO_DETAIL_OPERATION, None, [("usecaseid", scenario_id)]
            )
            if not isinstance(detail_payload, dict):
                raise ThreatScenarioCollectionError(
                    f"Threat scenario {scenario_id!r} detail was not a JSON object."
                )
            detail = _use_case_payload(detail_payload)
            groups = self._collect_group_membership(detail, scenario_id)
            stages = _resolve_stages(detail, groups, scenario_id, findings)
            for stage in stages:
                identifier_ids.update(stage.identifier_ids)
            pending.append((scenario_id, summary, detail, stages))

        identifier_details: dict[str, dict[str, Any]] = {}
        for identifier_id in sorted(identifier_ids):
            payload = self.request(
                SCENARIO_DETAIL_OPERATION, None, [("usecaseid", identifier_id)]
            )
            if not isinstance(payload, dict):
                findings.append(
                    {
                        "kind": "malformed_identifier",
                        "identifier_id": identifier_id,
                        "message": "Identifier detail was not a JSON object.",
                    }
                )
                payload = {}
            identifier_details[identifier_id] = _use_case_payload(payload)

        normalized = [
            _normalize_scenario(
                scenario_id,
                summary,
                detail,
                stages,
                identifier_details,
                findings,
            )
            for scenario_id, summary, detail, stages in pending
        ]
        normalized = sorted(normalized, key=lambda item: item["id"])
        validate_threat_scenario_records(normalized)
        return normalized, _sort_findings(findings)

    def _collect_group_membership(
        self, detail: dict[str, Any], scenario_id: str
    ) -> dict[str, Any]:
        group_body = {**detail, "listIdentifierUseCasesOnly": True}
        payload = self.request(
            SCENARIO_GROUP_OPERATION, group_body, [("summary", "true")]
        )
        if not isinstance(payload, dict):
            raise ThreatScenarioCollectionError(
                f"Threat scenario {scenario_id!r} stage membership had an invalid shape."
            )
        entries = payload.get("search_ui_scenario_result")
        if not isinstance(entries, list):
            raise ThreatScenarioCollectionError(
                f"Threat scenario {scenario_id!r} stage membership omitted its stage list."
            )

        stage_ids: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict):
                raise ThreatScenarioCollectionError(
                    f"Threat scenario {scenario_id!r} stage membership contained a "
                    "non-object stage."
                )
            raw_stage_id = entry.get("id")
            if not isinstance(raw_stage_id, str) or not raw_stage_id.strip():
                raise ThreatScenarioCollectionError(
                    f"Threat scenario {scenario_id!r} stage membership contained a stage "
                    "without an ID."
                )
            stage_id = raw_stage_id.strip()
            if stage_id in stage_ids:
                raise ThreatScenarioCollectionError(
                    f"Threat scenario {scenario_id!r} stage membership duplicated stage "
                    f"{stage_id!r}."
                )
            stage_ids.add(stage_id)

            has_members = "result_list" in entry
            raw_members = entry.get("result_list")
            if has_members and not isinstance(raw_members, list):
                raise ThreatScenarioCollectionError(
                    f"Threat scenario {scenario_id!r} stage {stage_id!r} returned a "
                    "malformed member list."
                )
            members = raw_members if isinstance(raw_members, list) else []

            has_total = "totalUseCases" in entry
            total = entry.get("totalUseCases")
            if not has_total and not has_members:
                total = 0
            elif (
                not isinstance(total, int)
                or isinstance(total, bool)
                or total < 0
            ):
                raise ThreatScenarioCollectionError(
                    f"Threat scenario {scenario_id!r} stage {stage_id!r} omitted a valid "
                    "totalUseCases value."
                )

            member_ids: set[str] = set()
            for member in members:
                raw_member_id = member.get("use_case_id") if isinstance(member, dict) else None
                if not isinstance(raw_member_id, str) or not raw_member_id.strip():
                    raise ThreatScenarioCollectionError(
                        f"Threat scenario {scenario_id!r} stage {stage_id!r} contained "
                        "malformed identifier membership."
                    )
                member_id = raw_member_id.strip()
                if member_id in member_ids:
                    raise ThreatScenarioCollectionError(
                        f"Threat scenario {scenario_id!r} stage {stage_id!r} duplicated "
                        f"identifier {member_id!r}."
                    )
                member_ids.add(member_id)

            if len(member_ids) != total:
                raise ThreatScenarioCollectionError(
                    f"Threat scenario {scenario_id!r} stage {stage_id!r} membership count "
                    "did not match totalUseCases."
                )
        return payload


def _resolve_stages(
    detail: dict[str, Any],
    groups: dict[str, Any],
    scenario_id: str,
    findings: list[dict[str, Any]],
) -> list[_Stage]:
    threat = _mapping(detail.get("threatScenario") or detail.get("threat_scenario"))
    ordered_raw = threat.get("stageOrder") or threat.get("stage_order") or []
    if not isinstance(ordered_raw, list):
        findings.append(
            {
                "kind": "missing_stages",
                "scenario_id": scenario_id,
                "message": "stageOrder was not a list.",
            }
        )
        ordered_raw = []

    stages: dict[str, _Stage] = {}
    order: list[str] = []
    for raw in ordered_raw:
        stage_id, name = _stage_identity(raw)
        if not stage_id:
            findings.append(
                {
                    "kind": "missing_stages",
                    "scenario_id": scenario_id,
                    "message": "stageOrder contained an entry without an ID or name.",
                }
            )
            continue
        if stage_id in stages:
            raise ThreatScenarioCollectionError(
                f"Threat scenario {scenario_id!r} stageOrder duplicated stage {stage_id!r}."
            )
        stages[stage_id] = _Stage(stage_id, name or stage_id, [])
        order.append(stage_id)

    entries = groups["search_ui_scenario_result"]
    group_ids = {entry["id"].strip() for entry in entries}
    if order and set(order) != group_ids:
        raise ThreatScenarioCollectionError(
            f"Threat scenario {scenario_id!r} stageOrder disagreed with stage membership."
        )
    for entry in entries:
        stage_id = entry["id"].strip()
        name = _text(entry, ("stage_name", "stageName", "name", "title"))
        members = entry.get("result_list") or []
        if stage_id not in stages:
            stages[stage_id] = _Stage(stage_id, name or stage_id, [])
        elif name and stages[stage_id].name == stage_id:
            stages[stage_id].name = name
        stages[stage_id].identifier_ids = [member["use_case_id"].strip() for member in members]

    for stage_id in sorted(stages):
        if stage_id not in order:
            order.append(stage_id)
    if not order:
        findings.append(
            {
                "kind": "missing_stages",
                "scenario_id": scenario_id,
                "message": "No stages were returned for the threat scenario.",
            }
        )
    for stage_id in order:
        if not stages[stage_id].identifier_ids:
            findings.append(
                {
                    "kind": "missing_stages",
                    "scenario_id": scenario_id,
                    "stage_id": stage_id,
                    "message": "Stage has no threat-identifier membership.",
                }
            )
    return [stages[stage_id] for stage_id in order]


def _stage_identity(value: Any) -> tuple[str, str]:
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned, cleaned
    if not isinstance(value, dict):
        return "", ""
    raw_id = _first_present(value, ("stage_id", "stageId", "id", "key", "name"))
    raw_name = _first_present(value, ("stage_name", "stageName", "name", "title"))
    stage_id = str(raw_id).strip() if raw_id is not None else ""
    name = str(raw_name).strip() if raw_name is not None else stage_id
    return stage_id, name


def _normalize_scenario(
    scenario_id: str,
    summary: dict[str, Any],
    detail: dict[str, Any],
    stages: list[_Stage],
    identifier_details: dict[str, dict[str, Any]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    title = _text(detail, ("use_case_title", "title", "name")) or _text(
        summary, ("use_case_title", "title", "name")
    )
    platforms = _string_list(
        _first_present(detail, ("victim_platform", "victimPlatform", "platforms"))
    )
    normalized_stages: list[dict[str, Any]] = []
    for position, stage in enumerate(stages, start=1):
        identifiers = []
        for identifier_id in stage.identifier_ids:
            raw = identifier_details.get(identifier_id, {})
            identifier = _normalize_identifier(identifier_id, raw, platforms)
            if not identifier["attack_ids"]:
                findings.append(
                    {
                        "kind": "malformed_identifier",
                        "scenario_id": scenario_id,
                        "stage_id": stage.stage_id,
                        "identifier_id": identifier_id,
                        "message": "Identifier has no canonical ATT&CK ID.",
                    }
                )
            identifiers.append(identifier)
        normalized_stages.append(
            {
                "order": position,
                "id": stage.stage_id,
                "name": stage.name,
                "identifiers": identifiers,
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "id": scenario_id,
        "title": title or scenario_id,
        "description": _text(detail, ("use_case_description", "description")),
        "platforms": platforms,
        "stages": normalized_stages,
    }


def _normalize_identifier(
    identifier_id: str, raw: dict[str, Any], inherited_platforms: list[str]
) -> dict[str, Any]:
    combined = _use_case_payload(raw)
    attacks = _attack_ids(
        combined.get("mitre_subtechnique"),
        combined.get("mitre_technique"),
        combined.get("mitre_techniques"),
        combined.get("techniques_fqn"),
        combined.get("attack_ids"),
    )
    platforms = _string_list(
        _first_present(combined, ("victim_platform", "victimPlatform", "platforms"))
    )
    rule_ids = _string_list(
        _first_present(combined, ("rule_ids", "ruleIds", "rules", "correlation_identifiers")),
        identifier_keys=("rule_id", "ruleId", "id"),
    )
    return {
        "id": identifier_id,
        "title": _text(combined, ("use_case_title", "title", "name")) or identifier_id,
        "behavioral_intent": _text(
            combined, ("use_case_description", "description", "details")
        ),
        "attack_ids": attacks,
        "tactics": _string_list(
            _first_present(combined, ("mitre_tactic", "mitre_tactics", "tactics"))
        ),
        "platforms": platforms or list(inherited_platforms),
        "references": _string_list(combined.get("references")),
        "rule_ids": rule_ids,
    }


def write_collection(output_dir: Path, result: CollectionResult) -> dict[str, Any]:
    validate_threat_scenario_records(result.scenarios)
    artifacts = {
        "threat_scenarios.jsonl": _jsonl(result.scenarios),
        "threat_scenario_identifiers.csv": _flatten_csv(result.scenarios),
        "collection_findings.json": _json_text(
            {"schema_version": SCHEMA_VERSION, "findings": _sort_findings(result.findings)}
        ),
    }
    _prepare_private_directory(output_dir, artifacts.keys())
    for name, body in artifacts.items():
        _write_private(output_dir / name, body)
    hashes = {name: _sha256(body) for name, body in artifacts.items()}
    manifest = _collection_manifest(result, hashes)
    _write_private(output_dir / "collection_manifest.json", _json_text(manifest))
    return manifest


def _collection_manifest(
    result: CollectionResult, artifact_hashes: dict[str, str]
) -> dict[str, Any]:
    stages = [stage for scenario in result.scenarios for stage in scenario["stages"]]
    identifiers = [identifier for stage in stages for identifier in stage["identifiers"]]
    unique_identifiers = {identifier["id"] for identifier in identifiers}
    attack_mappings = sum(len(identifier["attack_ids"]) for identifier in identifiers)
    platform_mappings = sum(len(identifier["platforms"]) for identifier in identifiers)
    return {
        "schema_version": SCHEMA_VERSION,
        "record_schema": {
            "id": SCHEMA_ID,
            "version": SCHEMA_VERSION,
            "sha256": threat_scenario_schema_sha256(),
        },
        "completeness": "complete",
        "attempts": result.attempts,
        "source": result.source,
        "counts": {
            "scenarios": len(result.scenarios),
            "stages": len(stages),
            "identifier_memberships": len(identifiers),
            "unique_identifiers": len(unique_identifiers),
            "attack_mappings": attack_mappings,
            "platform_mappings": platform_mappings,
            "findings": len(result.findings),
        },
        "artifacts": {
            name: {"sha256": digest, "mode": "0600"}
            for name, digest in sorted(artifact_hashes.items())
        },
    }


def _flatten_csv(scenarios: list[dict[str, Any]]) -> bytes:
    fields = [
        "scenario_id",
        "scenario_title",
        "stage_order",
        "stage_id",
        "stage_name",
        "identifier_id",
        "identifier_title",
        "attack_ids",
        "platforms",
        "tactics",
        "references",
        "rule_ids",
    ]
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for scenario in scenarios:
        for stage in scenario["stages"]:
            identifiers = stage["identifiers"] or [{}]
            for identifier in identifiers:
                writer.writerow(
                    {
                        "scenario_id": scenario["id"],
                        "scenario_title": scenario["title"],
                        "stage_order": stage["order"],
                        "stage_id": stage["id"],
                        "stage_name": stage["name"],
                        "identifier_id": identifier.get("id", ""),
                        "identifier_title": identifier.get("title", ""),
                        "attack_ids": json.dumps(identifier.get("attack_ids", [])),
                        "platforms": json.dumps(identifier.get("platforms", [])),
                        "tactics": json.dumps(identifier.get("tactics", [])),
                        "references": json.dumps(identifier.get("references", [])),
                        "rule_ids": json.dumps(identifier.get("rule_ids", [])),
                    }
                )
    return stream.getvalue().encode("utf-8")


def _prepare_private_directory(output_dir: Path, names: Iterable[str]) -> None:
    if output_dir.is_symlink():
        raise ValueError("Output directory must not be a symbolic link.")
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_dir.chmod(stat.S_IRWXU)
    reserved = [*names, "collection_manifest.json"]
    existing = [name for name in reserved if (output_dir / name).exists()]
    if existing:
        raise ValueError(
            "Output artifacts already exist; choose a new run directory: "
            + ", ".join(sorted(existing))
        )


def _write_private(path: Path, body: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(stat.S_IRUSR | stat.S_IWUSR)
        temporary.replace(path)
    except BaseException:
        with suppress(OSError):
            temporary.unlink(missing_ok=True)
        raise


def _observed_list_page(
    payload: dict[str, Any], requested_page: int, page_size: int
) -> tuple[int, int, list[dict[str, Any]], list[int | float]]:
    hits = payload.get("hits")
    metadata = payload.get("searchMetadata")
    if not isinstance(hits, dict):
        raise ThreatScenarioCollectionError(
            f"Scenario list page {requested_page} omitted its top-level hits mapping."
        )
    if not isinstance(metadata, dict):
        raise ThreatScenarioCollectionError(
            f"Scenario list page {requested_page} omitted its searchMetadata mapping."
        )

    returned_page = _required_metadata_int(metadata, "pageNum")
    returned_size = _required_metadata_int(metadata, "reqDocsPerPage")
    current_results = _required_metadata_int(metadata, "currPageResults")
    page_count = _required_metadata_int(metadata, "numPages")
    pagination_total = _required_metadata_int(metadata, "paginationTotal")
    total_results = _required_metadata_int(metadata, "totalResults")

    if returned_page != requested_page:
        raise ThreatScenarioCollectionError(
            f"Scenario list returned page {returned_page} while page {requested_page} "
            "was requested."
        )
    if returned_size != page_size:
        raise ThreatScenarioCollectionError(
            "Scenario list page-size metadata changed during collection."
        )
    expected_pages = math.ceil(total_results / page_size) if total_results else 0
    if page_count != expected_pages:
        raise ThreatScenarioCollectionError(
            "Scenario list page-count metadata was inconsistent with totalResults."
        )
    if pagination_total != total_results:
        raise ThreatScenarioCollectionError(
            "Scenario list paginationTotal did not match totalResults."
        )
    if current_results != len(hits):
        raise ThreatScenarioCollectionError(
            "Scenario list current-page metadata did not match the number of hits."
        )
    expected_current = min(
        page_size, max(total_results - ((requested_page - 1) * page_size), 0)
    )
    if current_results != expected_current:
        raise ThreatScenarioCollectionError(
            "Scenario list current-page count was inconsistent with its pagination metadata."
        )

    sort_criteria = metadata.get("sortCriteria")
    sorted_by = sort_criteria.get("sortedBy") if isinstance(sort_criteria, dict) else None
    expected_sort = {f"{SCENARIO_SORT_FIELD}:latest": SCENARIO_SORT_DIRECTION}
    if sorted_by != expected_sort:
        raise ThreatScenarioCollectionError(
            "Scenario list did not return the requested modification-time sort."
        )

    items: list[dict[str, Any]] = []
    modification_times: list[int | float] = []
    for raw_key, raw_hit in hits.items():
        if not isinstance(raw_key, str) or not raw_key.strip():
            raise ThreatScenarioCollectionError(
                f"Scenario list page {requested_page} contained an invalid hit key."
            )
        if not isinstance(raw_hit, dict):
            raise ThreatScenarioCollectionError(
                f"Scenario list page {requested_page} contained a non-object hit."
            )
        raw_scenario_id = raw_hit.get("use_case_id")
        if not isinstance(raw_scenario_id, str) or not raw_scenario_id.strip():
            raise ThreatScenarioCollectionError(
                f"Scenario list page {requested_page} contained a hit without an ID."
            )
        scenario_id = raw_scenario_id.strip()
        if raw_key.strip() != scenario_id:
            raise ThreatScenarioCollectionError(
                f"Scenario list page {requested_page} hit key did not match its ID."
            )
        modification_time = raw_hit.get(SCENARIO_SORT_FIELD)
        if (
            not isinstance(modification_time, int | float)
            or isinstance(modification_time, bool)
            or not math.isfinite(modification_time)
        ):
            raise ThreatScenarioCollectionError(
                f"Scenario list page {requested_page} hit omitted a valid "
                "modification_time."
            )
        items.append(raw_hit)
        modification_times.append(modification_time)
    ordered = sorted(
        zip(items, modification_times, strict=True),
        key=lambda item: item[1],
        reverse=True,
    )
    return (
        total_results,
        page_count,
        [item for item, _modification_time in ordered],
        [modification_time for _item, modification_time in ordered],
    )


def _required_metadata_int(metadata: Mapping[str, Any], key: str) -> int:
    value = metadata.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ThreatScenarioCollectionError(
            f"Scenario list searchMetadata omitted a valid {key} value."
        )
    return value


def _identifier(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if not isinstance(value, Mapping):
        return ""
    raw = _first_present(
        value,
        (
            "use_case_id",
            "useCaseId",
            "usecaseid",
            "identifier_id",
            "identifierId",
            "rule_id",
            "ruleId",
            "id",
        ),
    )
    return str(raw).strip() if raw is not None else ""


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _use_case_payload(value: dict[str, Any]) -> dict[str, Any]:
    nested = value.get("useCase") or value.get("use_case")
    if isinstance(nested, dict):
        return {**value, **nested}
    return value


def _first_present(value: Mapping[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in value and value[key] is not None:
            return value[key]
    return None


def _text(value: Mapping[str, Any], keys: tuple[str, ...]) -> str:
    raw = _first_present(value, keys)
    return str(raw).strip() if isinstance(raw, str | int | float) else ""


def _string_list(
    value: Any,
    *,
    combine: bool = False,
    sources: list[Any] | None = None,
    identifier_keys: tuple[str, ...] = ("id", "name", "value"),
) -> list[str]:
    raw_values = sources if combine and sources is not None else [value]
    result: list[str] = []
    for raw_value in raw_values:
        if isinstance(raw_value, str | int | float):
            candidates: list[Any] = [raw_value]
        elif isinstance(raw_value, list | tuple | set):
            candidates = list(raw_value)
        else:
            candidates = []
        for candidate in candidates:
            if isinstance(candidate, Mapping):
                candidate = _first_present(candidate, identifier_keys)
            if candidate is None:
                continue
            text = str(candidate).strip()
            if text and text not in result:
                result.append(text)
    return result


def _attack_ids(*sources: Any) -> list[str]:
    result: set[str] = set()
    for raw in _string_list(None, combine=True, sources=list(sources)):
        result.update(match.group(0).upper() for match in ATTACK_ID_RE.finditer(raw))
    return sorted(result)


def _sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(findings, key=lambda item: json.dumps(item, sort_keys=True))


def _jsonl(values: list[dict[str, Any]]) -> bytes:
    return "".join(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n" for value in values
    ).encode("utf-8")


def _json_text(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


@lru_cache(maxsize=1)
def _schema_bundle() -> tuple[bytes, dict[str, Any]]:
    try:
        body = resources.files("anvilogic_cli").joinpath(SCHEMA_RESOURCE).read_bytes()
        document = json.loads(body)
        if not isinstance(document, dict):
            raise TypeError("schema root is not an object")
        Draft202012Validator.check_schema(document)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, SchemaError, TypeError) as exc:
        raise ThreatScenarioContractError(
            f"Bundled threat-scenario schema is unavailable or invalid: {exc}"
        ) from exc
    if document.get("$id") != SCHEMA_ID or document.get("$schema") != (
        "https://json-schema.org/draft/2020-12/schema"
    ):
        raise ThreatScenarioContractError("Bundled threat-scenario schema identity is invalid.")
    return body, document


def threat_scenario_schema_bytes() -> bytes:
    """Return the exact immutable bytes of the bundled v1 record schema."""

    return _schema_bundle()[0]


def threat_scenario_schema_sha256() -> str:
    """Return the SHA-256 digest of the exact bundled v1 schema bytes."""

    return _sha256(threat_scenario_schema_bytes())


@lru_cache(maxsize=1)
def _record_validator() -> Draft202012Validator:
    return Draft202012Validator(_schema_bundle()[1])


def validate_threat_scenario_record(record: Any) -> None:
    """Validate one normalized JSONL record against the bundled v1 contract."""

    errors = sorted(
        _record_validator().iter_errors(record),
        key=lambda error: ("/".join(str(part) for part in error.absolute_path), error.message),
    )
    if not errors:
        return
    error = errors[0]
    path = "$" + "".join(
        f"[{part}]" if isinstance(part, int) else f".{part}" for part in error.absolute_path
    )
    raise ThreatScenarioContractError(
        f"Threat-scenario record violates schema {SCHEMA_ID} at {path}: {error.message}"
    )


def validate_threat_scenario_records(records: list[dict[str, Any]]) -> None:
    """Validate every normalized record before collection artifacts are written."""

    for index, record in enumerate(records):
        try:
            validate_threat_scenario_record(record)
        except ThreatScenarioContractError as exc:
            raise ThreatScenarioContractError(f"Record {index}: {exc}") from exc
