from __future__ import annotations

import csv
import hashlib
import json
import stat
from pathlib import Path
from typing import Any

import pytest

from scripts import prepare_daybreak_pilot as pilot
from scripts.prepare_daybreak_pilot import (
    Control,
    PilotPreparationError,
    WorkItem,
    pair_covered_controls,
    prepare_pilot,
    select_gap_work_items,
)


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _write(path: Path, body: bytes | str) -> None:
    missing: list[Path] = []
    parent = path.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    for directory in missing:
        directory.chmod(0o700)
    path.write_bytes(body.encode() if isinstance(body, str) else body)
    path.chmod(0o600)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _work_item(
    work_id: str,
    identifier_id: str,
    platform: str,
    attack_ids: tuple[str, ...],
    occurrence_count: int,
) -> WorkItem:
    occurrences = tuple(
        {
            "scenario_id": f"scenario-{index}",
            "stage_name": "Stage",
            "stage_order": index,
        }
        for index in range(occurrence_count)
    )
    return WorkItem(
        work_item_id=work_id,
        identifier_id=identifier_id,
        identifier_title="Sanitized gap",
        platform=platform,
        platform_source=platform,
        attack_ids=attack_ids,
        behavioral_intent="Sanitized defensive behavior.",
        occurrence_count=occurrence_count,
        occurrences=occurrences,
        prompt_path=pilot.PurePosixPath(f"daybreak_packets/{work_id}/prompt.json"),
        prompt_bytes=b"{}\n",
    )


def _control(
    identifier_id: str,
    platform: str,
    attack_ids: tuple[str, ...],
    *,
    occurrences: int = 1,
) -> Control:
    return Control(
        identifier_id=identifier_id,
        identifier_title="Sanitized control",
        platform=platform,
        attack_ids=attack_ids,
        behavioral_intent="Sanitized defensive behavior.",
        occurrence_count=occurrences,
        occurrences=(),
        matching_candidate_ids=(f"candidate-{identifier_id}",),
    )


def test_gap_selection_uses_scarcity_ranking_and_distinct_identifiers() -> None:
    items = (
        _work_item("shared-saas", "shared", "saas", ("T1000",), 1),
        _work_item("shared-windows", "shared", "windows", ("T1000",), 9),
        _work_item("windows-b", "windows-b", "windows", ("T1001",), 2),
        _work_item("windows-c", "windows-c", "windows", ("T1002", "T1003"), 1),
        _work_item("unknown", "unknown", "unknown", ("T1004",), 99),
        _work_item("missing-attack", "missing-attack", "windows", (), 99),
    )

    selected = select_gap_work_items(items, quotas=(("windows", 1), ("saas", 1)))

    assert [(item.platform, item.identifier_id) for item in selected] == [
        ("saas", "shared"),
        ("windows", "windows-b"),
    ]


def test_gap_selection_ranks_occurrences_then_attack_breadth_then_work_id() -> None:
    items = (
        _work_item("z", "id-z", "windows", ("T1000",), 3),
        _work_item("b", "id-b", "windows", ("T1000", "T1001"), 3),
        _work_item("a", "id-a", "windows", ("T1000", "T1001"), 3),
        _work_item("many", "id-many", "windows", ("T1000",), 4),
    )

    selected = select_gap_work_items(items, quotas=(("windows", 3),))

    assert [item.work_item_id for item in selected] == ["many", "a", "b"]


def test_gap_selection_fails_closed_on_shortfall_and_duplicates() -> None:
    one = _work_item("one", "same", "windows", ("T1000",), 1)
    duplicate = _work_item("two", "same", "windows", ("T1001",), 1)

    with pytest.raises(PilotPreparationError, match="duplicate identifiers"):
        select_gap_work_items((one, duplicate), quotas=(("windows", 1),))
    with pytest.raises(PilotPreparationError, match="cannot be filled"):
        select_gap_work_items((one,), quotas=(("windows", 2),))


def test_control_pairing_prefers_exact_then_parent_then_platform() -> None:
    gaps = (
        _work_item("gap-a", "gap-a", "windows", ("T1000.001",), 1),
        _work_item("gap-b", "gap-b", "linux", ("T2000.001",), 1),
        _work_item("gap-c", "gap-c", "macos", ("T3000",), 1),
    )
    controls = (
        _control("exact", "windows", ("T1000.001",)),
        _control("parent", "linux", ("T2000.002",)),
        _control("fallback", "macos", ("T9999",)),
    )

    pairs = pair_covered_controls(gaps, controls)

    assert [pair.match_basis for pair in pairs] == [
        "same_attack_id",
        "same_attack_parent",
        "platform_only",
    ]


def _catalog_record(candidate_id: str, platform: str, attack_id: str) -> dict[str, Any]:
    return {
        "id": candidate_id,
        "modified": "2026-09-25T00:00:00Z",
        "scenario_tags": [{"tag": {"display_name": attack_id}}],
        "supported_platforms": {platform: ">=0.0"},
        "name": f"Candidate {candidate_id}",
        "description": "Sanitized candidate behavior.",
    }


def _prompt(work: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "work_item_id": work["work_item_id"],
        "identifier": work["identifier"],
        "platform": work["platform"],
        "attack_ids": work["attack_ids"],
        "behavioral_intent": work["behavioral_intent"],
        "prerequisites": work["prerequisites"],
        "references": work["references"],
        "tactics": work["tactics"],
        "constraints": {
            "bounded_behavior": True,
            "defensive_only": True,
            "no_credentials_or_tenant_data": True,
            "no_upload": True,
        },
        "required_response": ["implementation"],
        "task": "Draft a bounded validation scenario.",
    }


def _manifest_entry(path: Path) -> dict[str, str]:
    return {"mode": "0600", "sha256": _sha(path)}


def _build_fixture(root: Path, *, extra_saas_gap: bool = False) -> dict[str, Path]:
    root.mkdir(mode=0o700)
    collection = root / "collection"
    attackiq = root / "attackiq"
    plan = root / "plan"
    for directory in (collection, attackiq, plan):
        directory.mkdir(mode=0o700)

    slots = [platform for platform, quota in pilot.PLATFORM_QUOTAS for _ in range(quota)]
    if extra_saas_gap:
        slots.append("saas")
    identifiers: list[dict[str, Any]] = []
    rows: list[dict[str, str]] = []
    terminal: list[dict[str, Any]] = []
    work_items: list[dict[str, Any]] = []
    catalog: list[dict[str, Any]] = []
    outputs: dict[str, dict[str, str]] = {}

    for index, platform in enumerate(slots, start=1):
        attack_id = f"T{1000 + index:04d}"
        candidate_id = f"private-candidate-{index:02d}"
        control_id = f"control-{index:02d}"
        gap_id = f"gap-{index:02d}"
        catalog.append(_catalog_record(candidate_id, platform, attack_id))
        for identifier_id, title, intent in (
            (control_id, f"Control {index}", f"Control behavior {index}"),
            (gap_id, f"Gap {index}", f"Gap behavior {index}"),
        ):
            identifiers.append(
                {
                    "id": identifier_id,
                    "title": title,
                    "behavioral_intent": intent,
                    "attack_ids": [attack_id],
                    "platforms": [platform],
                    "references": ["https://example.com/reference"],
                    "rule_ids": [],
                    "tactics": ["discovery"],
                }
            )
        common = {
            "scenario_id": "tenant-scenario-private",
            "scenario_title": "Tenant scenario private title",
            "stage_order": "1",
            "stage_name": "Sanitized stage",
            "platform": platform,
            "platform_raw": platform,
            "attack_id": attack_id,
        }
        rows.append(
            {
                **common,
                "identifier_id": control_id,
                "identifier_title": f"Control {index}",
                "status": "covered",
                "reason": "exact",
                "matching_scenario_ids": json.dumps([candidate_id]),
                "review_only_scenario_ids": "[]",
            }
        )
        rows.append(
            {
                **common,
                "identifier_id": gap_id,
                "identifier_title": f"Gap {index}",
                "status": "gap",
                "reason": "no exact match",
                "matching_scenario_ids": "[]",
                "review_only_scenario_ids": json.dumps([candidate_id]),
            }
        )
        terminal.extend(
            {
                "kind": "mapping",
                "status": status,
                "scenario_id": "tenant-scenario-private",
                "stage_order": 1,
                "identifier_id": identifier_id,
                "platform": platform,
                "platform_raw": platform,
                "attack_id": attack_id,
            }
            for status, identifier_id in (("covered", control_id), ("gap", gap_id))
        )
        work_id = f"work-{index:02d}"
        packet_root = f"daybreak_packets/{work_id}"
        work = {
            "schema_version": 1,
            "work_item_id": work_id,
            "identifier": {"id": gap_id, "title": f"Gap {index}"},
            "platform": {"canonical": platform, "source": platform},
            "attack_ids": [attack_id],
            "behavioral_intent": f"Gap behavior {index}",
            "occurrences": [
                {
                    "scenario_id": "tenant-scenario-private",
                    "stage_name": "Sanitized stage",
                    "stage_order": 1,
                }
            ],
            "prerequisites": [],
            "references": ["https://example.com/reference"],
            "tactics": ["discovery"],
            "review_status": "pending",
            "automatic_upload": False,
            "model": pilot.REQUESTED_MODEL,
            "max_parallel_agents": 3,
            "prompt_packet_path": f"{packet_root}/prompt.json",
            "draft_output_path": f"daybreak_drafts/{work_id}/draft.json",
            "promotion_path": f"custom-scenarios/anvilogic-coverage/{work_id}",
            "required_review": ["behavior"],
        }
        work_items.append(work)
        packet_path = plan / packet_root / "prompt.json"
        _write(packet_path, _json_bytes(_prompt(work)))
        outputs[f"{packet_root}/prompt.json"] = _manifest_entry(packet_path)

    source_record = {
        "schema_version": 1,
        "id": "tenant-scenario-private",
        "title": "Tenant scenario private title",
        "description": "Sanitized scenario.",
        "platforms": sorted(set(slots)),
        "stages": [
            {
                "id": "stage-1",
                "name": "Sanitized stage",
                "order": 1,
                "identifiers": identifiers,
            }
        ],
    }
    source_path = collection / "threat_scenarios.jsonl"
    _write(source_path, json.dumps(source_record, sort_keys=True) + "\n")
    identifiers_path = collection / "threat_scenario_identifiers.csv"
    findings_path = collection / "collection_findings.json"
    _write(identifiers_path, "identifier_id\n")
    _write(findings_path, _json_bytes({"findings": []}))
    collection_manifest = collection / "collection_manifest.json"
    _write(
        collection_manifest,
        _json_bytes(
            {
                "schema_version": 1,
                "completeness": "complete",
                "artifacts": {
                    path.name: _manifest_entry(path)
                    for path in (source_path, identifiers_path, findings_path)
                },
            }
        ),
    )

    primary_catalog = attackiq / "scenarios.json"
    verification_catalog = attackiq / "scenarios.verify.json"
    _write(primary_catalog, _json_bytes(catalog))
    _write(verification_catalog, _json_bytes(list(reversed(catalog))))

    crosswalk = plan / "crosswalk.csv"
    with crosswalk.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=pilot.CROSSWALK_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    crosswalk.chmod(0o600)
    work_path = plan / "daybreak_work_items.jsonl"
    _write(
        work_path,
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in work_items),
    )
    coverage_summary = plan / "coverage_summary.json"
    counts = {
        "anvilogic_scenarios": 1,
        "anvilogic_stages": 1,
        "attackiq_scenarios": len(catalog),
        "covered_rows": len(slots),
        "crosswalk_rows": len(rows),
        "daybreak_work_items": len(work_items),
        "deferred_assessments": 0,
        "executable_assessments": 1,
        "gap_rows": len(slots),
        "needs_metadata_rows": 0,
    }
    terminal_counts = {
        "covered": len(slots),
        "deferred": 0,
        "gap": len(slots),
        "needs_metadata": 0,
    }
    _write(
        coverage_summary,
        _json_bytes(
            {
                "schema_version": 1,
                "counts": counts,
                "terminal_state_counts": terminal_counts,
                "scenario_states": [
                    {
                        "scenario_id": "tenant-scenario-private",
                        "status": "gap",
                        "covered_tests": len(slots),
                        "total_tests": len(rows),
                    }
                ],
            }
        ),
    )
    for path in (crosswalk, coverage_summary, work_path):
        outputs[path.name] = _manifest_entry(path)
    plan_manifest = plan / "manifest.json"
    _write(
        plan_manifest,
        _json_bytes(
            {
                "schema_version": 1,
                "inputs": {
                    "anvilogic_export": {"sha256": _sha(source_path)},
                    "attackiq_scenarios_export": {"sha256": _sha(primary_catalog)},
                },
                "outputs": outputs,
                "counts": counts,
                "terminal_records": [
                    *terminal,
                    {
                        "kind": "scenario",
                        "scenario_id": "tenant-scenario-private",
                        "status": "gap",
                    },
                ],
                "terminal_state_counts": terminal_counts,
            }
        ),
    )
    return {
        "collection_manifest": collection_manifest,
        "plan": plan,
        "primary": primary_catalog,
        "verification": verification_catalog,
        "root": root,
    }


def _prepare(paths: dict[str, Path], output_name: str = "pilot") -> dict[str, Any]:
    return prepare_pilot(
        collection_manifest=paths["collection_manifest"],
        plan_dir=paths["plan"],
        attackiq_catalog=paths["primary"],
        attackiq_verification_catalog=paths["verification"],
        output_dir=paths["root"] / output_name,
    )


def _rehash_plan_output(paths: dict[str, Path], relative: str) -> None:
    manifest_path = paths["plan"] / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["outputs"][relative]["sha256"] = _sha(paths["plan"] / relative)
    _write(manifest_path, _json_bytes(manifest))


def test_prepare_pilot_end_to_end_is_deterministic_private_and_aggregate_only(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    paths = _build_fixture(tmp_path / "run")
    first = _prepare(paths, "pilot-a")
    second = _prepare(paths, "pilot-b")

    assert first == second
    assert first["selected_gap_count"] == 12
    assert first["covered_control_count"] == 12
    assert first["submission_authorized"] is False
    first_dir = paths["root"] / "pilot-a"
    second_dir = paths["root"] / "pilot-b"
    first_files = sorted(
        path.relative_to(first_dir) for path in first_dir.rglob("*") if path.is_file()
    )
    second_files = sorted(
        path.relative_to(second_dir) for path in second_dir.rglob("*") if path.is_file()
    )
    assert first_files == second_files
    assert all(
        (first_dir / name).read_bytes() == (second_dir / name).read_bytes() for name in first_files
    )
    assert stat.S_IMODE(first_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((first_dir / "gap_packets").stat().st_mode) == 0o700
    assert all(stat.S_IMODE((first_dir / name).stat().st_mode) == 0o600 for name in first_files)
    output_manifest = json.loads((first_dir / "manifest.json").read_text())
    for name, facts in output_manifest["outputs"].items():
        assert _sha(first_dir / name) == facts["sha256"]
        assert facts["mode"] == "0600"
    assert output_manifest["submission_authorized"] is False

    cli_output = paths["root"] / "pilot-cli"
    assert (
        pilot.main(
            [
                "--collection-manifest",
                str(paths["collection_manifest"]),
                "--plan-dir",
                str(paths["plan"]),
                "--attackiq-catalog",
                str(paths["primary"]),
                "--attackiq-verification-catalog",
                str(paths["verification"]),
                "--output-dir",
                str(cli_output),
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert json.loads(captured.out)["selected_gap_count"] == 12
    for private_value in (
        "tenant-scenario-private",
        "Tenant scenario private title",
        "private-candidate",
        "Gap behavior",
    ):
        assert private_value not in captured.out
        assert private_value not in captured.err


def test_prepare_pilot_fails_closed_for_catalog_and_manifest_drift(tmp_path: Path) -> None:
    catalog_paths = _build_fixture(tmp_path / "catalog-run")
    verification = json.loads(catalog_paths["verification"].read_text())
    verification[0]["modified"] = "2026-09-26T00:00:00Z"
    _write(catalog_paths["verification"], _json_bytes(verification))
    with pytest.raises(PilotPreparationError, match="drifted"):
        _prepare(catalog_paths)

    manifest_paths = _build_fixture(tmp_path / "manifest-run")
    with (manifest_paths["plan"] / "crosswalk.csv").open("a", encoding="utf-8") as handle:
        handle.write("changed\n")
    with pytest.raises(PilotPreparationError, match="hash"):
        _prepare(manifest_paths)


def test_prepare_pilot_fails_closed_for_missing_packet_and_invalid_state(
    tmp_path: Path,
) -> None:
    missing_paths = _build_fixture(tmp_path / "missing-run")
    packet = next((missing_paths["plan"] / "daybreak_packets").glob("*/prompt.json"))
    packet.unlink()
    with pytest.raises(PilotPreparationError, match="missing"):
        _prepare(missing_paths)

    state_paths = _build_fixture(tmp_path / "state-run")
    work_path = state_paths["plan"] / "daybreak_work_items.jsonl"
    items = [json.loads(line) for line in work_path.read_text().splitlines()]
    items[0]["review_status"] = "approved"
    _write(work_path, "".join(json.dumps(item, sort_keys=True) + "\n" for item in items))
    _rehash_plan_output(state_paths, "daybreak_work_items.jsonl")
    with pytest.raises(PilotPreparationError, match="pending state"):
        _prepare(state_paths)


def test_prepare_pilot_cleans_partial_output_on_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _build_fixture(tmp_path / "run")
    output = paths["root"] / "pilot"
    real_write = pilot._write_private_file
    calls = 0

    def fail_after_first(path: Path, body: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("sanitized write failure")
        real_write(path, body)

    monkeypatch.setattr(pilot, "_write_private_file", fail_after_first)

    with pytest.raises(PilotPreparationError, match="atomically"):
        _prepare(paths)
    assert not output.exists()
    assert not list(paths["root"].glob(".pilot.*"))


def test_reviewed_false_gap_is_replenished_and_non_equivalent_control_stops(
    tmp_path: Path,
) -> None:
    paths = _build_fixture(tmp_path / "run", extra_saas_gap=True)
    _prepare(paths, "pilot-first")
    worksheet_path = paths["root"] / "pilot-first" / "review_worksheet.json"
    worksheet = json.loads(worksheet_path.read_text())
    first_saas = next(pair for pair in worksheet["pairs"] if pair["platform"] == "saas")
    for pair in worksheet["pairs"]:
        pair["covered_control"]["review"]["classification"] = "semantically_equivalent"
        pair["gap"]["review"]["classification"] = "confirmed_missing"
    first_saas["gap"]["review"]["classification"] = "satisfied_by_existing_candidate"
    first_saas["gap"]["review"]["satisfied_by_candidate_id"] = first_saas["gap"][
        "review_only_candidates"
    ][0]["id"]
    decisions = paths["root"] / "decisions.json"
    _write(decisions, _json_bytes(worksheet))

    result = prepare_pilot(
        collection_manifest=paths["collection_manifest"],
        plan_dir=paths["plan"],
        attackiq_catalog=paths["primary"],
        attackiq_verification_catalog=paths["verification"],
        output_dir=paths["root"] / "pilot-replenished",
        review_decisions_path=decisions,
    )
    assert result["calibration_status"] == "pending_human_review"
    replenished = json.loads(
        (paths["root"] / "pilot-replenished" / "review_worksheet.json").read_text()
    )
    new_saas = next(pair for pair in replenished["pairs"] if pair["platform"] == "saas")
    assert new_saas["gap"]["work_item_id"] != first_saas["gap"]["work_item_id"]
    assert (
        replenished["excluded_gap_reviews"][0]["work_item_id"] == first_saas["gap"]["work_item_id"]
    )
    for pair in replenished["pairs"]:
        pair["covered_control"]["review"]["classification"] = "semantically_equivalent"
        pair["gap"]["review"]["classification"] = "confirmed_missing"
    final_decisions = paths["root"] / "final-decisions.json"
    _write(final_decisions, _json_bytes(replenished))
    final_result = prepare_pilot(
        collection_manifest=paths["collection_manifest"],
        plan_dir=paths["plan"],
        attackiq_catalog=paths["primary"],
        attackiq_verification_catalog=paths["verification"],
        output_dir=paths["root"] / "pilot-accepted",
        review_decisions_path=final_decisions,
    )
    assert final_result["calibration_status"] == "accepted"

    stopped = json.loads(worksheet_path.read_text())
    stopped["pairs"][0]["covered_control"]["review"]["classification"] = "not_equivalent"
    stopped_path = paths["root"] / "stopped.json"
    _write(stopped_path, _json_bytes(stopped))
    with pytest.raises(PilotPreparationError, match="revise the matching policy"):
        prepare_pilot(
            collection_manifest=paths["collection_manifest"],
            plan_dir=paths["plan"],
            attackiq_catalog=paths["primary"],
            attackiq_verification_catalog=paths["verification"],
            output_dir=paths["root"] / "pilot-stopped",
            review_decisions_path=stopped_path,
        )
