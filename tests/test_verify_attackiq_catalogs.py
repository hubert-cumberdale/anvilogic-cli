from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.verify_attackiq_catalogs import CatalogVerificationError, main, verify_catalogs


def _scenario(
    scenario_id: str,
    *,
    modified: str = "2026-09-25T00:00:00Z",
    attack_id: str = "T1059.001",
    platform: str = "windows",
    ignored: str = "first",
) -> dict:
    return {
        "id": scenario_id,
        "modified": modified,
        "last_updated": ignored,
        "scenario_tags": [{"tag": {"display_name": attack_id}}],
        "supported_platforms": {platform: ">=0.0"},
    }


def _write(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_verify_catalogs_accepts_order_and_ignored_field_changes(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    _write(first, [_scenario("scenario-a"), _scenario("scenario-b")])
    _write(
        second,
        [
            _scenario("scenario-b", ignored="second"),
            _scenario("scenario-a", ignored="second"),
        ],
    )

    assert verify_catalogs(first, second) == {"scenario_count": 2, "stable": True}


@pytest.mark.parametrize("field", ["modified", "attack_id", "platform"])
def test_verify_catalogs_rejects_reconciliation_drift_without_ids(
    tmp_path: Path,
    field: str,
) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    _write(first, [_scenario("private-scenario-id")])
    changed = {
        "modified": "2026-09-26T00:00:00Z",
        "attack_id": "T1003",
        "platform": "linux",
    }
    _write(second, [_scenario("private-scenario-id", **{field: changed[field]})])

    with pytest.raises(CatalogVerificationError) as exc_info:
        verify_catalogs(first, second)

    assert "private-scenario-id" not in str(exc_info.value)
    assert "1 scenario(s)" in str(exc_info.value)


def test_verify_catalogs_rejects_id_set_drift_without_ids(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    _write(first, [_scenario("private-a")])
    _write(second, [_scenario("private-b")])

    with pytest.raises(CatalogVerificationError) as exc_info:
        verify_catalogs(first, second)

    assert "private-a" not in str(exc_info.value)
    assert "private-b" not in str(exc_info.value)
    assert "2 scenario difference(s)" in str(exc_info.value)


@pytest.mark.parametrize(
    "payload, message",
    [
        ([{"id": "scenario-a", "modified": ""}], "without a modification value"),
        (
            [_scenario("scenario-a"), _scenario("scenario-a")],
            "duplicate scenario IDs",
        ),
        ({"not_results": []}, "must be a JSON list"),
        ([], "contains no scenarios"),
    ],
)
def test_verify_catalogs_rejects_malformed_exports(
    tmp_path: Path,
    payload: object,
    message: str,
) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    _write(first, payload)
    _write(second, [])

    with pytest.raises(CatalogVerificationError, match=message):
        verify_catalogs(first, second)


def test_main_emits_only_aggregate_result(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    payload = {"results": [_scenario("private-scenario-id")]}
    _write(first, payload)
    _write(second, payload)

    assert main([str(first), str(second)]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"scenario_count": 1, "stable": True}
    assert "private-scenario-id" not in captured.out
    assert captured.err == ""
