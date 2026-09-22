from __future__ import annotations

import zipfile
from pathlib import Path

from scripts import check_public_safety


def test_public_safety_source_tree_passes() -> None:
    assert check_public_safety.check_public_safety(scan_package=False) == []


def test_forbidden_public_model_files_are_detected() -> None:
    assert check_public_safety._path_findings(Path("models.md")) == [
        "models.md: forbidden model-catalog artifact"
    ]
    assert check_public_safety._path_findings(Path("nested/models.md")) == [
        "nested/models.md: forbidden model-catalog artifact"
    ]
    assert check_public_safety._path_findings(
        Path("src/anvilogic_cli/schemas.json")
    ) == ["src/anvilogic_cli/schemas.json: forbidden model-catalog artifact"]


def test_private_paths_and_raw_captures_are_detected() -> None:
    private_path = "/" + "home" + "/operator/private/evidence.json"

    assert check_public_safety._scan_text("notes.md", private_path) == [
        "notes.md:1: blocked private Unix user path"
    ]
    assert check_public_safety._path_findings(Path("evidence/session.har")) == [
        "evidence/session.har: forbidden raw-capture artifact"
    ]


def test_wheel_inspection_rejects_model_catalog(tmp_path: Path) -> None:
    wheel_path = tmp_path / "example.whl"
    with zipfile.ZipFile(wheel_path, "w") as wheel:
        wheel.writestr("anvilogic_cli/schemas.json", "{}\n")

    errors = check_public_safety.scan_wheel(wheel_path)

    assert errors == [
        "wheel contains forbidden model catalog: anvilogic_cli/schemas.json"
    ]
