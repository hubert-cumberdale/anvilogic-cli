from __future__ import annotations

import hashlib
import io
import tarfile
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
    assert check_public_safety._path_findings(
        Path("downloads/anvilogic-combined-apis.yaml")
    ) == ["downloads/anvilogic-combined-apis.yaml: forbidden model-catalog artifact"]


def test_complete_openapi_content_is_rejected_even_when_renamed(
    monkeypatch,
) -> None:
    body = b"openapi: 3.0.0\npaths: {}\ncomponents:\n  schemas: {}\n"
    monkeypatch.setattr(
        check_public_safety,
        "UPSTREAM_OPENAPI_SHA256",
        hashlib.sha256(body).hexdigest(),
    )

    assert check_public_safety._content_findings("renamed.txt", body) == [
        "renamed.txt: forbidden complete upstream OpenAPI document"
    ]


def test_small_openapi_corpus_is_rejected() -> None:
    body = b"openapi: 3.0.0\npaths: {}\ncomponents:\n  schemas: {}\n" + b" " * 100_000

    assert check_public_safety._content_findings("renamed.data", body) == [
        "renamed.data: forbidden complete OpenAPI/model corpus"
    ]


def test_flow_style_openapi_corpus_is_rejected() -> None:
    body = (
        b"{'info': {title: test}, 'paths': {}, 'openapi': 3.0.0, "
        b"'components': {'schemas': {}}}"
    )

    assert check_public_safety._content_findings("renamed.data", body) == [
        "renamed.data: forbidden complete OpenAPI/model corpus"
    ]


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


def test_wheel_scans_small_unknown_extension_members(tmp_path: Path) -> None:
    wheel_path = tmp_path / "example.whl"
    body = (
        b"%YAML 1.2\n---\ninfo: {title: test}\npaths: {}\nopenapi: 3.0.0\n"
        b"components:\n  schemas: {}\n"
        + b" " * 100_000
    )
    with zipfile.ZipFile(wheel_path, "w") as wheel:
        wheel.writestr("anvilogic_cli/renamed.data", body)

    assert check_public_safety.scan_wheel(wheel_path) == [
        "anvilogic_cli/renamed.data: forbidden complete OpenAPI/model corpus"
    ]


def test_sdist_scans_unknown_extension_members(tmp_path: Path) -> None:
    sdist_path = tmp_path / "example.tar.gz"
    body = (
        b"  'info' : {title: test}\r\n  'components' :\r\n    'schemas' : {}\r\n"
        b"  'paths' : {}\r\n  'openapi' : 3.0.0\r\n" + b" " * 100_000
    )
    member = tarfile.TarInfo("example-1.0/renamed.data")
    member.size = len(body)
    with tarfile.open(sdist_path, "w:gz") as archive:
        archive.addfile(member, io.BytesIO(body))

    assert check_public_safety.scan_sdist(sdist_path) == [
        "example-1.0/renamed.data: forbidden complete OpenAPI/model corpus"
    ]


def test_sdist_rejects_non_regular_members(tmp_path: Path) -> None:
    sdist_path = tmp_path / "example.tar.gz"
    member = tarfile.TarInfo("example-1.0/catalog-link")
    member.type = tarfile.SYMTYPE
    member.linkname = "openapi.yaml"
    with tarfile.open(sdist_path, "w:gz") as archive:
        archive.addfile(member)

    assert check_public_safety.scan_sdist(sdist_path) == [
        "sdist contains unsupported archive member: example-1.0/catalog-link"
    ]
