#!/usr/bin/env python3
"""Prepare a private, offline Daybreak matching-calibration pilot."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from scripts.verify_attackiq_catalogs import (
        CatalogVerificationError,
        verify_catalogs,
    )
except ModuleNotFoundError:  # pragma: no cover - direct script execution fallback.
    from verify_attackiq_catalogs import (  # type: ignore[no-redef]
        CatalogVerificationError,
        verify_catalogs,
    )


PILOT_SCHEMA_VERSION = 1
REQUESTED_MODEL = "gpt-daybreak-blue-latest"
ATTACK_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PLATFORM_QUOTAS: tuple[tuple[str, int], ...] = (
    ("windows", 2),
    ("linux", 2),
    ("macos", 2),
    ("containers", 2),
    ("iaas", 2),
    ("network_devices", 1),
    ("saas", 1),
)
ALLOWED_MAPPING_STATES = {"covered", "gap", "needs_metadata"}
ALLOWED_SCENARIO_STATES = {"covered", "gap", "deferred"}
ALLOWED_COVERED_REVIEWS = {"semantically_equivalent", "not_equivalent"}
ALLOWED_GAP_REVIEWS = {"confirmed_missing", "satisfied_by_existing_candidate"}
CROSSWALK_FIELDS = (
    "scenario_id",
    "scenario_title",
    "stage_order",
    "stage_name",
    "identifier_id",
    "identifier_title",
    "platform",
    "platform_raw",
    "attack_id",
    "status",
    "reason",
    "matching_scenario_ids",
    "review_only_scenario_ids",
)


class PilotPreparationError(ValueError):
    """Raised when private inputs cannot safely produce a pilot package."""


@dataclass(frozen=True)
class WorkItem:
    work_item_id: str
    identifier_id: str
    identifier_title: str
    platform: str | None
    platform_source: str
    attack_ids: tuple[str, ...]
    behavioral_intent: str
    occurrence_count: int
    occurrences: tuple[dict[str, Any], ...]
    prompt_path: PurePosixPath
    prompt_bytes: bytes

    @property
    def ranking_key(self) -> tuple[int, int, str]:
        return (-self.occurrence_count, -len(self.attack_ids), self.work_item_id)


@dataclass(frozen=True)
class Control:
    identifier_id: str
    identifier_title: str
    platform: str
    attack_ids: tuple[str, ...]
    behavioral_intent: str
    occurrence_count: int
    occurrences: tuple[dict[str, Any], ...]
    matching_candidate_ids: tuple[str, ...]

    @property
    def ranking_key(self) -> tuple[int, int, str]:
        return (-self.occurrence_count, -len(self.attack_ids), self.identifier_id)


@dataclass(frozen=True)
class GapEvidence:
    identifier_id: str
    platform: str
    attack_ids: tuple[str, ...]
    occurrence_keys: frozenset[tuple[str, int]]
    review_candidate_ids: tuple[str, ...]


@dataclass(frozen=True)
class Pairing:
    gap: WorkItem
    control: Control
    match_basis: str


@dataclass(frozen=True)
class ReviewValue:
    classification: str
    notes: str | None
    satisfied_by_candidate_id: str | None = None


@dataclass(frozen=True)
class ReviewDecisions:
    gap: Mapping[str, ReviewValue]
    controls: Mapping[tuple[str, str], ReviewValue]


@dataclass(frozen=True)
class ValidatedInputs:
    fingerprints: Mapping[str, str]
    work_items: tuple[WorkItem, ...]
    controls: tuple[Control, ...]
    gap_evidence: Mapping[tuple[str, str], GapEvidence]
    catalog: Mapping[str, dict[str, Any]]
    aggregate_counts: Mapping[str, int]


def _sha256_bytes(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise PilotPreparationError("A required private input could not be read.") from exc
    return digest.hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _require_private_file(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise PilotPreparationError(f"The required {label} file is missing.") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise PilotPreparationError(f"The required {label} input must be a regular file.")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise PilotPreparationError(f"The required {label} input must use mode 0600.")


def _require_private_directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise PilotPreparationError(f"The required {label} directory is missing.") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise PilotPreparationError(f"The required {label} input must be a directory.")
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise PilotPreparationError(f"The required {label} directory must use mode 0700.")


def _load_json(path: Path, label: str) -> dict[str, Any]:
    _require_private_file(path, label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PilotPreparationError(f"The required {label} file is not readable JSON.") from exc
    if not isinstance(value, dict):
        raise PilotPreparationError(f"The required {label} file must contain a JSON object.")
    return value


def _safe_relative_path(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise PilotPreparationError(f"A {label} path is invalid.")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise PilotPreparationError(f"A {label} path is invalid.")
    return path


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise PilotPreparationError(f"The {label} SHA-256 value is invalid.")
    return value


def _validate_manifest_artifacts(
    *,
    directory: Path,
    artifacts: Any,
    label: str,
) -> dict[str, str]:
    if not isinstance(artifacts, dict) or not artifacts:
        raise PilotPreparationError(f"The {label} artifact manifest is empty or invalid.")
    hashes: dict[str, str] = {}
    checked_directories: set[Path] = set()
    for name, facts in artifacts.items():
        relative = _safe_relative_path(name, label)
        if not isinstance(facts, dict) or facts.get("mode") != "0600":
            raise PilotPreparationError(f"A {label} artifact does not declare mode 0600.")
        expected = _require_sha256(facts.get("sha256"), label)
        path = directory.joinpath(*relative.parts)
        _require_private_file(path, label)
        parent = path.parent
        while parent != directory:
            if parent not in checked_directories:
                _require_private_directory(parent, label)
                checked_directories.add(parent)
            parent = parent.parent
        if _sha256_path(path) != expected:
            raise PilotPreparationError(f"A {label} artifact hash does not match its manifest.")
        hashes[relative.as_posix()] = expected
    return hashes


def _validate_collection_manifest(path: Path) -> tuple[Path, dict[str, str], str]:
    directory = path.parent
    _require_private_directory(directory, "Anvilogic collection")
    manifest = _load_json(path, "Anvilogic collection manifest")
    if manifest.get("schema_version") != 1 or manifest.get("completeness") != "complete":
        raise PilotPreparationError("The Anvilogic collection is not complete schema version 1.")
    hashes = _validate_manifest_artifacts(
        directory=directory,
        artifacts=manifest.get("artifacts"),
        label="Anvilogic collection",
    )
    required = "threat_scenarios.jsonl"
    if required not in hashes:
        raise PilotPreparationError("The Anvilogic collection lacks its normalized JSONL artifact.")
    return directory / required, hashes, _sha256_path(path)


def _validate_plan_manifest(plan_dir: Path) -> tuple[dict[str, Any], dict[str, str], str]:
    _require_private_directory(plan_dir, "reconciliation plan")
    manifest_path = plan_dir / "manifest.json"
    manifest = _load_json(manifest_path, "reconciliation manifest")
    if manifest.get("schema_version") != 1:
        raise PilotPreparationError("The reconciliation manifest schema version is invalid.")
    hashes = _validate_manifest_artifacts(
        directory=plan_dir,
        artifacts=manifest.get("outputs"),
        label="reconciliation output",
    )
    required = {"crosswalk.csv", "coverage_summary.json", "daybreak_work_items.jsonl"}
    if not required.issubset(hashes):
        raise PilotPreparationError("The reconciliation manifest lacks required pilot inputs.")
    return manifest, hashes, _sha256_path(manifest_path)


def _required_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise PilotPreparationError(f"A required aggregate {label} count is invalid.")
    return int(value)


def _validate_terminal_states(
    manifest: Mapping[str, Any],
    plan_dir: Path,
) -> dict[str, int]:
    counts = manifest.get("counts")
    records = manifest.get("terminal_records")
    state_counts = manifest.get("terminal_state_counts")
    if (
        not isinstance(counts, dict)
        or not isinstance(records, list)
        or not isinstance(state_counts, dict)
    ):
        raise PilotPreparationError("The reconciliation terminal-state ledger is invalid.")
    mapping_counts: Counter[str] = Counter()
    scenario_counts: Counter[str] = Counter()
    for record in records:
        if not isinstance(record, dict):
            raise PilotPreparationError("The reconciliation terminal-state ledger is invalid.")
        kind = record.get("kind")
        status = record.get("status")
        if kind == "mapping" and status in ALLOWED_MAPPING_STATES:
            mapping_counts[status] += 1
        elif kind == "scenario" and status in ALLOWED_SCENARIO_STATES:
            scenario_counts[status] += 1
        else:
            raise PilotPreparationError("The reconciliation contains an invalid terminal state.")
    expected_mapping = {
        "covered": _required_int(counts.get("covered_rows"), "covered"),
        "gap": _required_int(counts.get("gap_rows"), "gap"),
        "needs_metadata": _required_int(counts.get("needs_metadata_rows"), "needs-metadata"),
    }
    if mapping_counts != Counter(expected_mapping):
        raise PilotPreparationError("Reconciliation mapping terminal counts do not match.")
    scenario_total = _required_int(counts.get("anvilogic_scenarios"), "scenario")
    if sum(scenario_counts.values()) != scenario_total:
        raise PilotPreparationError("Reconciliation scenario terminal counts do not match.")
    executable = _required_int(counts.get("executable_assessments"), "executable")
    deferred = _required_int(counts.get("deferred_assessments"), "deferred")
    if scenario_counts["covered"] + scenario_counts["gap"] != executable:
        raise PilotPreparationError("Reconciliation executable scenario counts do not match.")
    if scenario_counts["deferred"] != deferred:
        raise PilotPreparationError("Reconciliation deferred scenario counts do not match.")
    expected_terminal = dict(expected_mapping)
    expected_terminal["deferred"] = deferred
    if state_counts != expected_terminal:
        raise PilotPreparationError("Reconciliation terminal-state aggregates do not match.")

    summary = _load_json(plan_dir / "coverage_summary.json", "coverage summary")
    if summary.get("schema_version") != 1:
        raise PilotPreparationError("The coverage summary schema version is invalid.")
    if summary.get("counts") != counts or summary.get("terminal_state_counts") != state_counts:
        raise PilotPreparationError("The coverage summary and manifest aggregates differ.")
    scenario_states = summary.get("scenario_states")
    if not isinstance(scenario_states, list) or len(scenario_states) != scenario_total:
        raise PilotPreparationError("The coverage summary scenario ledger is invalid.")
    observed: Counter[str] = Counter()
    scenario_ids: set[str] = set()
    for record in scenario_states:
        if not isinstance(record, dict) or record.get("status") not in ALLOWED_SCENARIO_STATES:
            raise PilotPreparationError("The coverage summary contains an invalid scenario state.")
        scenario_id = record.get("scenario_id")
        if not isinstance(scenario_id, str) or not scenario_id or scenario_id in scenario_ids:
            raise PilotPreparationError("The coverage summary contains duplicate scenario records.")
        scenario_ids.add(scenario_id)
        observed[record["status"]] += 1
    if observed != scenario_counts:
        raise PilotPreparationError("The coverage summary scenario states do not reconcile.")
    return {
        "anvilogic_scenarios": scenario_total,
        "attackiq_scenarios": _required_int(counts.get("attackiq_scenarios"), "AttackIQ"),
        "crosswalk_rows": _required_int(counts.get("crosswalk_rows"), "crosswalk"),
        "daybreak_work_items": _required_int(
            counts.get("daybreak_work_items"), "Daybreak work-item"
        ),
    }


def _parse_id_list(value: str, label: str) -> tuple[str, ...]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise PilotPreparationError(f"A {label} candidate list is invalid.") from exc
    if (
        not isinstance(parsed, list)
        or not all(isinstance(item, str) and item for item in parsed)
        or len(parsed) != len(set(parsed))
    ):
        raise PilotPreparationError(f"A {label} candidate list is invalid.")
    return tuple(sorted(parsed))


@dataclass
class _ControlBuilder:
    title: str
    attack_ids: set[str]
    occurrence_records: dict[tuple[str, int], dict[str, Any]]
    candidate_ids: set[str]


@dataclass
class _GapBuilder:
    attack_ids: set[str]
    occurrence_keys: set[tuple[str, int]]
    review_candidate_ids: set[str]


def _load_crosswalk(
    path: Path,
    expected_count: int,
) -> tuple[
    dict[tuple[str, str], _ControlBuilder],
    dict[tuple[str, str], GapEvidence],
    set[str],
    Counter[str],
]:
    _require_private_file(path, "crosswalk")
    controls: dict[tuple[str, str], _ControlBuilder] = {}
    gaps: dict[tuple[str, str], _GapBuilder] = {}
    all_candidate_ids: set[str] = set()
    states: Counter[str] = Counter()
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            if tuple(reader.fieldnames or ()) != CROSSWALK_FIELDS:
                raise PilotPreparationError(
                    "The crosswalk columns do not match the reviewed format."
                )
            for row in reader:
                status = row["status"]
                if status not in ALLOWED_MAPPING_STATES:
                    raise PilotPreparationError("The crosswalk contains an invalid mapping state.")
                states[status] += 1
                try:
                    stage_order = int(row["stage_order"])
                except ValueError as exc:
                    raise PilotPreparationError("A crosswalk stage order is invalid.") from exc
                if stage_order < 0:
                    raise PilotPreparationError("A crosswalk stage order is invalid.")
                required_text = (
                    row["scenario_id"],
                    row["scenario_title"],
                    row["stage_name"],
                )
                if not all(required_text):
                    raise PilotPreparationError("A crosswalk record lacks required review context.")
                matching = _parse_id_list(row["matching_scenario_ids"], "matching")
                review = _parse_id_list(row["review_only_scenario_ids"], "review-only")
                all_candidate_ids.update(matching)
                all_candidate_ids.update(review)
                attack_id = row["attack_id"]
                platform = row["platform"]
                key = (row["identifier_id"], platform)
                occurrence_key = (row["scenario_id"], stage_order)
                if status == "needs_metadata":
                    if attack_id or platform or matching or review:
                        raise PilotPreparationError(
                            "A needs-metadata crosswalk record contains mapping evidence."
                        )
                    continue
                if ATTACK_ID_RE.fullmatch(attack_id) is None:
                    if status == "gap" and not attack_id:
                        continue
                    raise PilotPreparationError(
                        "A mapped crosswalk record lacks canonical metadata."
                    )
                if not platform:
                    if status != "gap":
                        raise PilotPreparationError(
                            "A mapped crosswalk record lacks a canonical platform."
                        )
                    continue
                if not row["identifier_id"] or not row["identifier_title"]:
                    if status != "gap" or row["identifier_id"] or row["identifier_title"]:
                        raise PilotPreparationError(
                            "A crosswalk identifier lacks required review context."
                        )
                    continue
                if status == "covered":
                    if not matching:
                        raise PilotPreparationError(
                            "A covered crosswalk record has invalid candidates."
                        )
                    builder = controls.setdefault(
                        key,
                        _ControlBuilder(row["identifier_title"], set(), {}, set()),
                    )
                    if builder.title != row["identifier_title"]:
                        raise PilotPreparationError("A covered identifier title is inconsistent.")
                    builder.attack_ids.add(attack_id)
                    builder.occurrence_records[occurrence_key] = {
                        "scenario_id": row["scenario_id"],
                        "scenario_title": row["scenario_title"],
                        "stage_name": row["stage_name"],
                        "stage_order": stage_order,
                    }
                    builder.candidate_ids.update(matching)
                else:
                    if matching:
                        raise PilotPreparationError(
                            "A gap crosswalk record has a matching candidate."
                        )
                    gap = gaps.setdefault(key, _GapBuilder(set(), set(), set()))
                    gap.attack_ids.add(attack_id)
                    gap.occurrence_keys.add(occurrence_key)
                    gap.review_candidate_ids.update(review)
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise PilotPreparationError("The crosswalk could not be read safely.") from exc
    if sum(states.values()) != expected_count:
        raise PilotPreparationError("The crosswalk row count does not match its manifest.")
    return (
        controls,
        {
            key: GapEvidence(
                identifier_id=key[0],
                platform=key[1],
                attack_ids=tuple(sorted(value.attack_ids)),
                occurrence_keys=frozenset(value.occurrence_keys),
                review_candidate_ids=tuple(sorted(value.review_candidate_ids)),
            )
            for key, value in gaps.items()
        },
        all_candidate_ids,
        states,
    )


def _load_source_intents(path: Path) -> dict[str, tuple[str, str]]:
    _require_private_file(path, "normalized Anvilogic export")
    identifiers: dict[str, tuple[str, str]] = {}
    try:
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    raise PilotPreparationError(
                        "The normalized Anvilogic export has a blank record."
                    )
                record = json.loads(line)
                if not isinstance(record, dict) or not isinstance(record.get("stages"), list):
                    raise PilotPreparationError("The normalized Anvilogic export is malformed.")
                for stage in record["stages"]:
                    if not isinstance(stage, dict) or not isinstance(
                        stage.get("identifiers"), list
                    ):
                        raise PilotPreparationError("The normalized Anvilogic export is malformed.")
                    for item in stage["identifiers"]:
                        if not isinstance(item, dict):
                            raise PilotPreparationError(
                                "The normalized Anvilogic export is malformed."
                            )
                        identifier_id = item.get("id")
                        title = item.get("title")
                        intent = item.get("behavioral_intent")
                        if (
                            not isinstance(identifier_id, str)
                            or not identifier_id
                            or not isinstance(title, str)
                            or not title
                            or not isinstance(intent, str)
                        ):
                            raise PilotPreparationError(
                                "The normalized Anvilogic export lacks review context."
                            )
                        facts = (title, intent)
                        existing = identifiers.setdefault(identifier_id, facts)
                        if existing != facts:
                            raise PilotPreparationError(
                                "The normalized Anvilogic identifier context is inconsistent."
                            )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PilotPreparationError("The normalized Anvilogic export could not be read.") from exc
    if not identifiers:
        raise PilotPreparationError("The normalized Anvilogic export contains no identifiers.")
    return identifiers


def _required_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise PilotPreparationError(f"A Daybreak {label} value is invalid.")
    return value


def _required_attack_ids(value: Any) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and ATTACK_ID_RE.fullmatch(item) for item in value)
        or len(value) != len(set(value))
    ):
        raise PilotPreparationError("A Daybreak work item has invalid ATT&CK IDs.")
    return tuple(sorted(value))


def _load_work_items(
    path: Path,
    plan_dir: Path,
    manifest_outputs: Mapping[str, str],
    gap_evidence: Mapping[tuple[str, str], GapEvidence],
    expected_count: int,
) -> tuple[WorkItem, ...]:
    _require_private_file(path, "Daybreak work-item")
    items: list[WorkItem] = []
    work_ids: set[str] = set()
    identity_platforms: set[tuple[str, str | None]] = set()
    packet_paths: set[str] = set()
    try:
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    raise PilotPreparationError("The Daybreak work-item file has a blank record.")
                value = json.loads(line)
                if not isinstance(value, dict) or value.get("schema_version") != 1:
                    raise PilotPreparationError("A Daybreak work item is malformed.")
                work_id = _required_text(value.get("work_item_id"), "work-item ID")
                identifier = value.get("identifier")
                platform_value = value.get("platform")
                if not isinstance(identifier, dict) or not isinstance(platform_value, dict):
                    raise PilotPreparationError("A Daybreak work item is malformed.")
                identifier_id = _required_text(identifier.get("id"), "identifier ID")
                identifier_title = _required_text(identifier.get("title"), "identifier title")
                platform = platform_value.get("canonical")
                if platform is not None and (not isinstance(platform, str) or not platform):
                    raise PilotPreparationError("A Daybreak work item has an invalid platform.")
                platform_source = _required_text(platform_value.get("source"), "source platform")
                if work_id in work_ids or (
                    platform is not None and (identifier_id, platform) in identity_platforms
                ):
                    raise PilotPreparationError(
                        "The Daybreak work items contain duplicate identifiers."
                    )
                work_ids.add(work_id)
                if platform is not None:
                    identity_platforms.add((identifier_id, platform))
                attack_ids = _required_attack_ids(value.get("attack_ids"))
                if (
                    value.get("review_status") != "pending"
                    or value.get("automatic_upload") is not False
                ):
                    raise PilotPreparationError(
                        "A Daybreak work item is not in the required pending state."
                    )
                if value.get("model") != REQUESTED_MODEL or value.get("max_parallel_agents") != 3:
                    raise PilotPreparationError("A Daybreak work item has invalid model controls.")
                occurrences = value.get("occurrences")
                if not isinstance(occurrences, list) or not occurrences:
                    raise PilotPreparationError("A Daybreak work item has no occurrences.")
                normalized_occurrences: list[dict[str, Any]] = []
                occurrence_keys: set[tuple[str, int]] = set()
                for occurrence in occurrences:
                    if not isinstance(occurrence, dict):
                        raise PilotPreparationError("A Daybreak occurrence is malformed.")
                    scenario_id = _required_text(occurrence.get("scenario_id"), "scenario ID")
                    stage_name = _required_text(occurrence.get("stage_name"), "stage name")
                    stage_order = occurrence.get("stage_order")
                    if (
                        isinstance(stage_order, bool)
                        or not isinstance(stage_order, int)
                        or stage_order < 0
                    ):
                        raise PilotPreparationError(
                            "A Daybreak occurrence has an invalid stage order."
                        )
                    key = (scenario_id, stage_order)
                    if key in occurrence_keys:
                        raise PilotPreparationError(
                            "A Daybreak work item has duplicate occurrences."
                        )
                    occurrence_keys.add(key)
                    normalized_occurrences.append(
                        {
                            "scenario_id": scenario_id,
                            "stage_name": stage_name,
                            "stage_order": stage_order,
                        }
                    )
                prompt_path = _safe_relative_path(value.get("prompt_packet_path"), "prompt packet")
                draft_path = _safe_relative_path(value.get("draft_output_path"), "draft output")
                promotion_path = _safe_relative_path(value.get("promotion_path"), "promotion")
                if (
                    len(prompt_path.parts) != 3
                    or len(draft_path.parts) != 3
                    or len(promotion_path.parts) != 3
                    or prompt_path.parts[0] != "daybreak_packets"
                    or draft_path.parts[0] != "daybreak_drafts"
                    or promotion_path.parts[:2] != ("custom-scenarios", "anvilogic-coverage")
                    or prompt_path.parts[1] != draft_path.parts[1]
                    or prompt_path.parts[1] != promotion_path.parts[2]
                    or prompt_path.name != "prompt.json"
                    or draft_path.name != "draft.json"
                ):
                    raise PilotPreparationError("A Daybreak packet relationship is invalid.")
                prompt_key = prompt_path.as_posix()
                if prompt_key in packet_paths or prompt_key not in manifest_outputs:
                    raise PilotPreparationError("A Daybreak prompt packet relationship is invalid.")
                packet_paths.add(prompt_key)
                prompt_file = plan_dir.joinpath(*prompt_path.parts)
                prompt = _load_json(prompt_file, "Daybreak prompt packet")
                shared_fields = (
                    ("work_item_id", work_id),
                    ("identifier", identifier),
                    ("platform", platform_value),
                    ("attack_ids", value.get("attack_ids")),
                    ("behavioral_intent", value.get("behavioral_intent")),
                    ("prerequisites", value.get("prerequisites")),
                    ("references", value.get("references")),
                    ("tactics", value.get("tactics")),
                )
                if prompt.get("schema_version") != 1 or any(
                    prompt.get(field) != expected for field, expected in shared_fields
                ):
                    raise PilotPreparationError(
                        "A Daybreak prompt packet does not match its work item."
                    )
                constraints = prompt.get("constraints")
                if not isinstance(constraints, dict) or any(
                    constraints.get(field) is not True
                    for field in (
                        "bounded_behavior",
                        "defensive_only",
                        "no_credentials_or_tenant_data",
                        "no_upload",
                    )
                ):
                    raise PilotPreparationError(
                        "A Daybreak prompt packet has invalid safety controls."
                    )
                if platform is not None:
                    evidence = gap_evidence.get((identifier_id, platform))
                    if (
                        evidence is None
                        or evidence.attack_ids != attack_ids
                        or evidence.occurrence_keys != frozenset(occurrence_keys)
                    ):
                        raise PilotPreparationError(
                            "A Daybreak work item does not match the gap crosswalk."
                        )
                items.append(
                    WorkItem(
                        work_item_id=work_id,
                        identifier_id=identifier_id,
                        identifier_title=identifier_title,
                        platform=platform,
                        platform_source=platform_source,
                        attack_ids=attack_ids,
                        behavioral_intent=_required_text(
                            value.get("behavioral_intent"), "behavioral intent"
                        ),
                        occurrence_count=len(normalized_occurrences),
                        occurrences=tuple(normalized_occurrences),
                        prompt_path=prompt_path,
                        prompt_bytes=prompt_file.read_bytes(),
                    )
                )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PilotPreparationError("The Daybreak work-item file could not be read.") from exc
    if len(items) != expected_count:
        raise PilotPreparationError("The Daybreak work-item count does not match its manifest.")
    manifested_packets = {
        name
        for name in manifest_outputs
        if name.startswith("daybreak_packets/") and name.endswith("/prompt.json")
    }
    if packet_paths != manifested_packets:
        raise PilotPreparationError("The Daybreak prompt-packet inventory is incomplete.")
    return tuple(items)


def _load_catalog(
    path: Path, expected_count: int, referenced_ids: set[str]
) -> dict[str, dict[str, Any]]:
    _require_private_file(path, "AttackIQ catalog")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PilotPreparationError("The AttackIQ catalog could not be read.") from exc
    if isinstance(value, dict):
        value = value.get("results")
    if not isinstance(value, list) or len(value) != expected_count:
        raise PilotPreparationError("The AttackIQ catalog count does not match the reconciliation.")
    catalog: dict[str, dict[str, Any]] = {}
    for item in value:
        if not isinstance(item, dict):
            raise PilotPreparationError("The AttackIQ catalog is malformed.")
        scenario_id = item.get("id")
        if not isinstance(scenario_id, str) or not scenario_id or scenario_id in catalog:
            raise PilotPreparationError("The AttackIQ catalog has invalid or duplicate IDs.")
        if scenario_id in referenced_ids:
            name = item.get("name")
            description = item.get("description")
            platforms = item.get("supported_platforms")
            if (
                not isinstance(name, str)
                or not name
                or (description is not None and not isinstance(description, str))
                or not isinstance(platforms, dict)
            ):
                raise PilotPreparationError("An AttackIQ review candidate lacks required context.")
            if not all(isinstance(key, str) and key for key in platforms):
                raise PilotPreparationError("An AttackIQ review candidate has invalid platforms.")
            catalog[scenario_id] = {
                "id": scenario_id,
                "name": name,
                "description": description or "",
                "supported_platforms": sorted(platforms),
            }
    if catalog.keys() != referenced_ids:
        raise PilotPreparationError("The crosswalk references missing AttackIQ candidates.")
    return catalog


def _build_controls(
    builders: Mapping[tuple[str, str], _ControlBuilder],
    source_intents: Mapping[str, tuple[str, str]],
) -> tuple[Control, ...]:
    controls: list[Control] = []
    for (identifier_id, platform), builder in builders.items():
        source = source_intents.get(identifier_id)
        if source is None or source[0] != builder.title:
            raise PilotPreparationError("A covered control lacks consistent source context.")
        if not source[1]:
            continue
        controls.append(
            Control(
                identifier_id=identifier_id,
                identifier_title=builder.title,
                platform=platform,
                attack_ids=tuple(sorted(builder.attack_ids)),
                behavioral_intent=source[1],
                occurrence_count=len(builder.occurrence_records),
                occurrences=tuple(
                    builder.occurrence_records[key] for key in sorted(builder.occurrence_records)
                ),
                matching_candidate_ids=tuple(sorted(builder.candidate_ids)),
            )
        )
    return tuple(controls)


def _validate_inputs(
    *,
    collection_manifest: Path,
    plan_dir: Path,
    attackiq_catalog: Path,
    attackiq_verification_catalog: Path,
) -> ValidatedInputs:
    source_path, collection_hashes, collection_manifest_hash = _validate_collection_manifest(
        collection_manifest
    )
    plan_manifest, plan_outputs, plan_manifest_hash = _validate_plan_manifest(plan_dir)
    inputs = plan_manifest.get("inputs")
    if not isinstance(inputs, dict):
        raise PilotPreparationError("The reconciliation input manifest is invalid.")
    anvilogic_input = inputs.get("anvilogic_export")
    attackiq_input = inputs.get("attackiq_scenarios_export")
    if not isinstance(anvilogic_input, dict) or not isinstance(attackiq_input, dict):
        raise PilotPreparationError("The reconciliation input manifest is invalid.")
    source_hash = _require_sha256(anvilogic_input.get("sha256"), "Anvilogic input")
    catalog_hash = _require_sha256(attackiq_input.get("sha256"), "AttackIQ input")
    if source_hash != collection_hashes["threat_scenarios.jsonl"]:
        raise PilotPreparationError("The reconciliation used a different Anvilogic export.")
    _require_private_directory(attackiq_catalog.parent, "AttackIQ catalog")
    _require_private_directory(attackiq_verification_catalog.parent, "AttackIQ catalog")
    _require_private_file(attackiq_catalog, "AttackIQ catalog")
    _require_private_file(attackiq_verification_catalog, "AttackIQ verification catalog")
    if _sha256_path(attackiq_catalog) != catalog_hash:
        raise PilotPreparationError("The reconciliation used a different AttackIQ catalog.")
    try:
        catalog_result = verify_catalogs(attackiq_catalog, attackiq_verification_catalog)
    except CatalogVerificationError as exc:
        raise PilotPreparationError(str(exc)) from exc
    aggregates = _validate_terminal_states(plan_manifest, plan_dir)
    if catalog_result.get("scenario_count") != aggregates["attackiq_scenarios"]:
        raise PilotPreparationError("The stable AttackIQ count does not match the reconciliation.")
    builders, gap_evidence, candidate_ids, crosswalk_states = _load_crosswalk(
        plan_dir / "crosswalk.csv", aggregates["crosswalk_rows"]
    )
    counts = plan_manifest["counts"]
    expected_states = Counter(
        {
            "covered": counts["covered_rows"],
            "gap": counts["gap_rows"],
            "needs_metadata": counts["needs_metadata_rows"],
        }
    )
    if crosswalk_states != expected_states:
        raise PilotPreparationError(
            "The crosswalk states do not match the reconciliation manifest."
        )
    source_intents = _load_source_intents(source_path)
    work_items = _load_work_items(
        plan_dir / "daybreak_work_items.jsonl",
        plan_dir,
        plan_outputs,
        gap_evidence,
        aggregates["daybreak_work_items"],
    )
    catalog = _load_catalog(attackiq_catalog, aggregates["attackiq_scenarios"], candidate_ids)
    controls = _build_controls(builders, source_intents)
    fingerprints = {
        "anvilogic_collection_manifest": collection_manifest_hash,
        "anvilogic_export": source_hash,
        "attackiq_catalog": catalog_hash,
        "attackiq_verification_catalog": _sha256_path(attackiq_verification_catalog),
        "reconciliation_manifest": plan_manifest_hash,
        "crosswalk": plan_outputs["crosswalk.csv"],
        "daybreak_work_items": plan_outputs["daybreak_work_items.jsonl"],
    }
    aggregate_counts = {
        **aggregates,
        "covered_controls_available": len(controls),
        "eligible_gap_work_items": sum(
            item.platform in dict(PLATFORM_QUOTAS) and bool(item.attack_ids) for item in work_items
        ),
    }
    return ValidatedInputs(
        fingerprints=fingerprints,
        work_items=work_items,
        controls=controls,
        gap_evidence=gap_evidence,
        catalog=catalog,
        aggregate_counts=aggregate_counts,
    )


def select_gap_work_items(
    items: Sequence[WorkItem],
    *,
    quotas: Sequence[tuple[str, int]] = PLATFORM_QUOTAS,
    excluded_work_item_ids: Iterable[str] = (),
) -> tuple[WorkItem, ...]:
    excluded = set(excluded_work_item_ids)
    quota_map = dict(quotas)
    if len(quota_map) != len(quotas) or any(
        not platform or quota <= 0 for platform, quota in quotas
    ):
        raise PilotPreparationError("The pilot platform quotas are invalid.")
    pools: dict[str, list[WorkItem]] = {platform: [] for platform in quota_map}
    identities: set[tuple[str, str]] = set()
    work_ids: set[str] = set()
    for item in items:
        if item.work_item_id in work_ids:
            raise PilotPreparationError("The Daybreak work items contain duplicate work-item IDs.")
        work_ids.add(item.work_item_id)
        if item.platform not in quota_map or not item.attack_ids or item.work_item_id in excluded:
            continue
        assert item.platform is not None
        identity = (item.identifier_id, item.platform)
        if identity in identities:
            raise PilotPreparationError("The eligible gap pool contains duplicate identifiers.")
        identities.add(identity)
        pools[item.platform].append(item)
    for pool in pools.values():
        pool.sort(key=lambda item: item.ranking_key)
    order_index = {platform: index for index, (platform, _) in enumerate(quotas)}
    platform_order = sorted(
        quota_map,
        key=lambda platform: (
            len({item.identifier_id for item in pools[platform]}) / quota_map[platform],
            len(pools[platform]),
            order_index[platform],
        ),
    )
    selected: list[WorkItem] = []
    selected_ids: set[str] = set()
    unfilled = 0
    for platform in platform_order:
        chosen = 0
        for item in pools[platform]:
            if item.identifier_id in selected_ids:
                continue
            selected.append(item)
            selected_ids.add(item.identifier_id)
            chosen += 1
            if chosen == quota_map[platform]:
                break
        if chosen != quota_map[platform]:
            unfilled += 1
    if unfilled:
        raise PilotPreparationError(
            f"Gap quotas cannot be filled for {unfilled} platform group(s)."
        )
    return tuple(selected)


def _attack_parents(attack_ids: Sequence[str]) -> set[str]:
    return {attack_id.split(".", 1)[0] for attack_id in attack_ids}


def pair_covered_controls(
    gaps: Sequence[WorkItem],
    controls: Sequence[Control],
) -> tuple[Pairing, ...]:
    controls_by_platform: dict[str, list[Control]] = defaultdict(list)
    gap_ids = {gap.identifier_id for gap in gaps}
    for control in controls:
        if control.identifier_id not in gap_ids:
            controls_by_platform[control.platform].append(control)
    used_controls: set[str] = set()
    pairings: list[Pairing] = []
    missing_platforms: set[str] = set()
    for gap in gaps:
        assert gap.platform is not None
        exact_ids = set(gap.attack_ids)
        parents = _attack_parents(gap.attack_ids)

        def candidate_key(
            control: Control,
            exact_ids: set[str] = exact_ids,
            parents: set[str] = parents,
        ) -> tuple[int, int, int, str]:
            if exact_ids.intersection(control.attack_ids):
                preference = 0
            elif parents.intersection(_attack_parents(control.attack_ids)):
                preference = 1
            else:
                preference = 2
            return (preference, *control.ranking_key)

        candidates = [
            control
            for control in controls_by_platform.get(gap.platform, [])
            if control.identifier_id not in used_controls
        ]
        if not candidates:
            missing_platforms.add(gap.platform)
            continue
        control = min(candidates, key=candidate_key)
        preference = candidate_key(control)[0]
        basis = ("same_attack_id", "same_attack_parent", "platform_only")[preference]
        pairings.append(Pairing(gap=gap, control=control, match_basis=basis))
        used_controls.add(control.identifier_id)
    if len(pairings) != len(gaps):
        raise PilotPreparationError(
            "Covered-control pairing cannot be completed for "
            f"{len(missing_platforms)} platform group(s)."
        )
    return tuple(pairings)


def _candidate_set_hash(candidate_ids: Sequence[str]) -> str:
    return _sha256_bytes(_json_bytes(sorted(candidate_ids)))


def _load_review_decisions(
    path: Path | None,
    fingerprints: Mapping[str, str],
) -> ReviewDecisions:
    if path is None:
        return ReviewDecisions(gap={}, controls={})
    _require_private_directory(path.parent, "review decision")
    worksheet = _load_json(path, "review decision")
    if worksheet.get("schema_version") != PILOT_SCHEMA_VERSION:
        raise PilotPreparationError("The review decision schema version is invalid.")
    if worksheet.get("source_fingerprints") != fingerprints:
        raise PilotPreparationError("The review decisions refer to different source inputs.")
    pairs = worksheet.get("pairs")
    if not isinstance(pairs, list) or not pairs:
        raise PilotPreparationError("The review decision worksheet contains no pairs.")
    gap_decisions: dict[str, ReviewValue] = {}
    control_decisions: dict[tuple[str, str], ReviewValue] = {}
    for pair in pairs:
        if not isinstance(pair, dict):
            raise PilotPreparationError("The review decision worksheet is malformed.")
        gap = pair.get("gap")
        control = pair.get("covered_control")
        platform = pair.get("platform")
        if (
            not isinstance(gap, dict)
            or not isinstance(control, dict)
            or not isinstance(platform, str)
        ):
            raise PilotPreparationError("The review decision worksheet is malformed.")
        gap_review = gap.get("review")
        control_review = control.get("review")
        gap_id = gap.get("work_item_id")
        control_identifier = control.get("identifier")
        if (
            not isinstance(gap_review, dict)
            or not isinstance(control_review, dict)
            or not isinstance(gap_id, str)
            or not isinstance(control_identifier, dict)
            or not isinstance(control_identifier.get("id"), str)
        ):
            raise PilotPreparationError("The review decision worksheet is malformed.")
        gap_classification = gap_review.get("classification")
        if gap_classification is not None:
            if gap_classification not in ALLOWED_GAP_REVIEWS or gap_id in gap_decisions:
                raise PilotPreparationError("A gap review classification is invalid or duplicated.")
            candidate_id = gap_review.get("satisfied_by_candidate_id")
            if gap_classification == "satisfied_by_existing_candidate":
                candidates = gap.get("review_only_candidates")
                if not isinstance(candidates, list) or not isinstance(candidate_id, str):
                    raise PilotPreparationError("A satisfied gap review lacks its candidate.")
                valid_ids = {
                    candidate.get("id") for candidate in candidates if isinstance(candidate, dict)
                }
                if candidate_id not in valid_ids:
                    raise PilotPreparationError(
                        "A satisfied gap review names an invalid candidate."
                    )
            elif candidate_id is not None:
                raise PilotPreparationError("A confirmed gap review names an existing candidate.")
            notes = gap_review.get("notes")
            if notes is not None and not isinstance(notes, str):
                raise PilotPreparationError("A gap review note is invalid.")
            gap_decisions[gap_id] = ReviewValue(gap_classification, notes, candidate_id)
        control_classification = control_review.get("classification")
        if control_classification is not None:
            key = (control_identifier["id"], platform)
            if control_classification not in ALLOWED_COVERED_REVIEWS or key in control_decisions:
                raise PilotPreparationError(
                    "A covered-control review classification is invalid or duplicated."
                )
            notes = control_review.get("notes")
            if notes is not None and not isinstance(notes, str):
                raise PilotPreparationError("A covered-control review note is invalid.")
            control_decisions[key] = ReviewValue(control_classification, notes)
    excluded_reviews = worksheet.get("excluded_gap_reviews", [])
    if not isinstance(excluded_reviews, list):
        raise PilotPreparationError("The excluded gap-review ledger is malformed.")
    for review in excluded_reviews:
        if not isinstance(review, dict):
            raise PilotPreparationError("The excluded gap-review ledger is malformed.")
        work_id = review.get("work_item_id")
        candidate_id = review.get("satisfied_by_candidate_id")
        notes = review.get("notes")
        if (
            not isinstance(work_id, str)
            or not work_id
            or not isinstance(candidate_id, str)
            or not candidate_id
            or (notes is not None and not isinstance(notes, str))
            or work_id in gap_decisions
        ):
            raise PilotPreparationError("The excluded gap-review ledger is malformed.")
        gap_decisions[work_id] = ReviewValue("satisfied_by_existing_candidate", notes, candidate_id)
    if any(value.classification == "not_equivalent" for value in control_decisions.values()):
        raise PilotPreparationError(
            "A covered control was not equivalent; revise the matching policy before continuing."
        )
    return ReviewDecisions(gap=gap_decisions, controls=control_decisions)


def _review_candidate(candidate_id: str, catalog: Mapping[str, dict[str, Any]]) -> dict[str, Any]:
    candidate = catalog.get(candidate_id)
    if candidate is None:
        raise PilotPreparationError("A selected review candidate is absent from the catalog.")
    return dict(candidate)


def _worksheet(
    pairings: Sequence[Pairing],
    validated: ValidatedInputs,
    reviews: ReviewDecisions,
) -> tuple[dict[str, Any], str]:
    pairs: list[dict[str, Any]] = []
    accepted_controls = 0
    confirmed_gaps = 0
    for number, pairing in enumerate(pairings, start=1):
        gap = pairing.gap
        control = pairing.control
        assert gap.platform is not None
        evidence = validated.gap_evidence[(gap.identifier_id, gap.platform)]
        gap_review = reviews.gap.get(gap.work_item_id)
        control_review = reviews.controls.get((control.identifier_id, control.platform))
        if gap_review and gap_review.classification == "confirmed_missing":
            confirmed_gaps += 1
        if control_review and control_review.classification == "semantically_equivalent":
            accepted_controls += 1
        pairs.append(
            {
                "pair_number": number,
                "platform": gap.platform,
                "gap": {
                    "work_item_id": gap.work_item_id,
                    "identifier": {"id": gap.identifier_id, "title": gap.identifier_title},
                    "attack_ids": list(gap.attack_ids),
                    "behavioral_intent": gap.behavioral_intent,
                    "occurrence_count": gap.occurrence_count,
                    "occurrences": list(gap.occurrences),
                    "prompt_path": f"gap_packets/{number:02d}.json",
                    "review_only_candidate_set_sha256": _candidate_set_hash(
                        evidence.review_candidate_ids
                    ),
                    "review_only_candidates": [
                        _review_candidate(candidate_id, validated.catalog)
                        for candidate_id in evidence.review_candidate_ids
                    ],
                    "review": {
                        "allowed_classifications": sorted(ALLOWED_GAP_REVIEWS),
                        "classification": gap_review.classification if gap_review else None,
                        "notes": gap_review.notes if gap_review else None,
                        "satisfied_by_candidate_id": (
                            gap_review.satisfied_by_candidate_id if gap_review else None
                        ),
                    },
                },
                "covered_control": {
                    "identifier": {
                        "id": control.identifier_id,
                        "title": control.identifier_title,
                    },
                    "attack_ids": list(control.attack_ids),
                    "behavioral_intent": control.behavioral_intent,
                    "occurrence_count": control.occurrence_count,
                    "occurrences": list(control.occurrences),
                    "pairing_basis": pairing.match_basis,
                    "matching_candidate_set_sha256": _candidate_set_hash(
                        control.matching_candidate_ids
                    ),
                    "matching_candidates": [
                        _review_candidate(candidate_id, validated.catalog)
                        for candidate_id in control.matching_candidate_ids
                    ],
                    "review": {
                        "allowed_classifications": sorted(ALLOWED_COVERED_REVIEWS),
                        "classification": (
                            control_review.classification if control_review else None
                        ),
                        "notes": control_review.notes if control_review else None,
                    },
                },
            }
        )
    calibration_status = (
        "accepted"
        if accepted_controls == len(pairings) and confirmed_gaps == len(pairings)
        else "pending_human_review"
    )
    selected_work_ids = {pairing.gap.work_item_id for pairing in pairings}
    excluded_gap_reviews = [
        {
            "work_item_id": work_id,
            "classification": value.classification,
            "notes": value.notes,
            "satisfied_by_candidate_id": value.satisfied_by_candidate_id,
        }
        for work_id, value in sorted(reviews.gap.items())
        if value.classification == "satisfied_by_existing_candidate"
        and work_id not in selected_work_ids
    ]
    return (
        {
            "schema_version": PILOT_SCHEMA_VERSION,
            "calibration_status": calibration_status,
            "submission_authorized": False,
            "source_fingerprints": dict(validated.fingerprints),
            "excluded_gap_reviews": excluded_gap_reviews,
            "instructions": {
                "covered_control": (
                    "Classify every control as semantically equivalent or not equivalent."
                ),
                "gap": (
                    "Classify every gap as confirmed missing or satisfied by an existing "
                    "review-only candidate."
                ),
                "stop_condition": (
                    "Any not-equivalent covered control requires matching-policy revision."
                ),
            },
            "pairs": pairs,
        },
        calibration_status,
    )


def _selection_summary(
    pairings: Sequence[Pairing],
    validated: ValidatedInputs,
    reviews: ReviewDecisions,
    calibration_status: str,
) -> dict[str, Any]:
    platforms = Counter(pairing.gap.platform for pairing in pairings)
    bases = Counter(pairing.match_basis for pairing in pairings)
    selected_gap_ids = {pairing.gap.work_item_id for pairing in pairings}
    selected_control_keys = {
        (pairing.control.identifier_id, pairing.control.platform) for pairing in pairings
    }
    return {
        "schema_version": PILOT_SCHEMA_VERSION,
        "calibration_status": calibration_status,
        "submission_authorized": False,
        "requested_model": REQUESTED_MODEL,
        "selected_gap_count": len(pairings),
        "covered_control_count": len(pairings),
        "platform_counts": dict(sorted(platforms.items())),
        "pairing_basis_counts": dict(sorted(bases.items())),
        "review_counts": {
            "confirmed_gaps": sum(
                reviews.gap.get(work_id, ReviewValue("", None)).classification
                == "confirmed_missing"
                for work_id in selected_gap_ids
            ),
            "accepted_covered_controls": sum(
                reviews.controls.get(key, ReviewValue("", None)).classification
                == "semantically_equivalent"
                for key in selected_control_keys
            ),
            "excluded_satisfied_gaps": sum(
                value.classification == "satisfied_by_existing_candidate"
                for value in reviews.gap.values()
            ),
        },
        "source_aggregate_counts": dict(validated.aggregate_counts),
        "prohibited_actions_performed": {
            "model_requests": 0,
            "scenario_uploads": 0,
            "assessment_applications": 0,
            "target_changes": 0,
            "schedule_changes": 0,
            "executions": 0,
        },
    }


def _data_inventory(pairings: Sequence[Pairing]) -> dict[str, Any]:
    return {
        "schema_version": PILOT_SCHEMA_VERSION,
        "classification": "private_security_content",
        "submission_authorized": False,
        "retained_artifacts": [
            {
                "path": "review_worksheet.json",
                "records": len(pairings),
                "contains": [
                    "Anvilogic identifiers, titles, behavioral intent, and occurrences",
                    "AttackIQ candidate IDs, names, descriptions, and supported-platform labels",
                    "human-review classifications and notes",
                ],
            },
            {
                "path": "selection_summary.json",
                "records": 1,
                "contains": ["aggregate counts and authorization state"],
            },
            {
                "path": "gap_packets/*.json",
                "records": len(pairings),
                "contains": ["selected existing Daybreak prompt packets"],
            },
            {
                "path": "manifest.json",
                "records": 1,
                "contains": ["input and output SHA-256 values and file modes"],
            },
        ],
        "excluded_data": [
            "credentials and authorization headers",
            "raw API envelopes",
            "assessment apply plans",
            "targets, schedules, and execution results",
            "model responses and promoted scenarios",
        ],
    }


def _write_private_file(path: Path, body: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        with suppress(OSError):
            os.close(descriptor)
        raise


def _write_package(
    output_dir: Path,
    *,
    pairings: Sequence[Pairing],
    worksheet: Mapping[str, Any],
    summary: Mapping[str, Any],
    inventory: Mapping[str, Any],
    fingerprints: Mapping[str, str],
    review_decisions_path: Path | None,
) -> None:
    if output_dir.exists() or output_dir.is_symlink():
        raise PilotPreparationError("The pilot output directory already exists.")
    parent = output_dir.parent
    _require_private_directory(parent, "pilot output parent")
    previous_umask = os.umask(0o077)
    temporary: Path | None = None
    try:
        temporary = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.", dir=parent))
        os.chmod(temporary, 0o700)
        packet_dir = temporary / "gap_packets"
        packet_dir.mkdir(mode=0o700)
        outputs: dict[str, dict[str, str]] = {}
        content = {
            "review_worksheet.json": _json_bytes(worksheet),
            "selection_summary.json": _json_bytes(summary),
            "data_inventory.json": _json_bytes(inventory),
        }
        for name, body in content.items():
            _write_private_file(temporary / name, body)
            outputs[name] = {"mode": "0600", "sha256": _sha256_bytes(body)}
        for number, pairing in enumerate(pairings, start=1):
            relative = f"gap_packets/{number:02d}.json"
            _write_private_file(temporary / relative, pairing.gap.prompt_bytes)
            outputs[relative] = {
                "mode": "0600",
                "sha256": _sha256_bytes(pairing.gap.prompt_bytes),
            }
        manifest_inputs = {
            name: {"sha256": digest} for name, digest in sorted(fingerprints.items())
        }
        if review_decisions_path is not None:
            manifest_inputs["review_decisions"] = {"sha256": _sha256_path(review_decisions_path)}
        manifest = {
            "schema_version": PILOT_SCHEMA_VERSION,
            "submission_authorized": False,
            "inputs": manifest_inputs,
            "outputs": dict(sorted(outputs.items())),
        }
        _write_private_file(temporary / "manifest.json", _json_bytes(manifest))
        os.replace(temporary, output_dir)
        temporary = None
    except PilotPreparationError:
        raise
    except OSError as exc:
        raise PilotPreparationError(
            "The private pilot package could not be written atomically."
        ) from exc
    finally:
        os.umask(previous_umask)
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)


def prepare_pilot(
    *,
    collection_manifest: Path,
    plan_dir: Path,
    attackiq_catalog: Path,
    attackiq_verification_catalog: Path,
    output_dir: Path,
    review_decisions_path: Path | None = None,
) -> dict[str, Any]:
    validated = _validate_inputs(
        collection_manifest=collection_manifest,
        plan_dir=plan_dir,
        attackiq_catalog=attackiq_catalog,
        attackiq_verification_catalog=attackiq_verification_catalog,
    )
    reviews = _load_review_decisions(review_decisions_path, validated.fingerprints)
    work_index = {item.work_item_id: item for item in validated.work_items}
    control_keys = {(control.identifier_id, control.platform) for control in validated.controls}
    for work_id, review in reviews.gap.items():
        item = work_index.get(work_id)
        if item is None or item.platform is None:
            raise PilotPreparationError("A gap review does not match the current work items.")
        evidence = validated.gap_evidence.get((item.identifier_id, item.platform))
        if evidence is None or (
            review.classification == "satisfied_by_existing_candidate"
            and review.satisfied_by_candidate_id not in evidence.review_candidate_ids
        ):
            raise PilotPreparationError("A gap review does not match current candidate evidence.")
    if not set(reviews.controls).issubset(control_keys):
        raise PilotPreparationError("A control review does not match the current crosswalk.")
    excluded = {
        work_id
        for work_id, value in reviews.gap.items()
        if value.classification == "satisfied_by_existing_candidate"
    }
    gaps = select_gap_work_items(
        validated.work_items,
        excluded_work_item_ids=excluded,
    )
    pairings = pair_covered_controls(gaps, validated.controls)
    worksheet, calibration_status = _worksheet(pairings, validated, reviews)
    summary = _selection_summary(pairings, validated, reviews, calibration_status)
    inventory = _data_inventory(pairings)
    _write_package(
        output_dir,
        pairings=pairings,
        worksheet=worksheet,
        summary=summary,
        inventory=inventory,
        fingerprints=validated.fingerprints,
        review_decisions_path=review_decisions_path,
    )
    return {
        "calibration_status": calibration_status,
        "submission_authorized": False,
        "selected_gap_count": len(pairings),
        "covered_control_count": len(pairings),
        "platform_counts": summary["platform_counts"],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare a deterministic private Daybreak calibration pilot without network or "
            "mutation operations."
        )
    )
    parser.add_argument(
        "--collection-manifest",
        required=True,
        type=Path,
        help="Complete Anvilogic collection_manifest.json.",
    )
    parser.add_argument(
        "--plan-dir",
        required=True,
        type=Path,
        help="Existing private reconciliation plan directory.",
    )
    parser.add_argument(
        "--attackiq-catalog",
        required=True,
        type=Path,
        help="Primary AttackIQ scenario export used by the reconciliation.",
    )
    parser.add_argument(
        "--attackiq-verification-catalog",
        required=True,
        type=Path,
        help="Second stable AttackIQ scenario export.",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="New private output directory; it must not already exist.",
    )
    parser.add_argument(
        "--review-decisions",
        type=Path,
        help="Optional reviewer-completed worksheet from a prior pilot iteration.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = prepare_pilot(
            collection_manifest=args.collection_manifest,
            plan_dir=args.plan_dir,
            attackiq_catalog=args.attackiq_catalog,
            attackiq_verification_catalog=args.attackiq_verification_catalog,
            output_dir=args.output_dir,
            review_decisions_path=args.review_decisions,
        )
    except PilotPreparationError as exc:
        print(f"Pilot preparation failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
