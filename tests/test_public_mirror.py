from __future__ import annotations

import json
import subprocess
from pathlib import Path

from scripts import create_public_mirror


def _git(arguments: list[str], root: Path) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _source_repository(tmp_path: Path) -> Path:
    root = tmp_path / "private-source"
    root.mkdir()
    (root / "security").mkdir()
    (root / "security" / "secret-scan-allowlist.json").write_text(
        '{"allowlist": [], "version": 1}\n', encoding="utf-8"
    )
    (root / "pyproject.toml").write_text(
        '[project]\nname = "example"\nversion = "1.2.3"\n', encoding="utf-8"
    )
    (root / "README.md").write_text("# Public source\n", encoding="utf-8")
    _git(["init"], root)
    _git(["add", "-A"], root)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "source",
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    _git(["tag", "v1.2.3"], root)
    return root


def test_manifest_builder_is_deterministic() -> None:
    arguments = {
        "public_repo": "owner/public",
        "source_ref": "v1.2.3",
        "source_commit": "abc123",
        "source_commit_time": "2026-09-22T00:00:00+00:00",
        "version": "1.2.3",
        "tree_sha256": "digest",
        "source_snapshot": "git-archive",
    }

    first = create_public_mirror.build_publication_manifest(**arguments)
    second = create_public_mirror.build_publication_manifest(**arguments)

    assert first == second
    assert first["history_policy"] == "single sanitized source snapshot; no private git history"


def test_public_mirror_has_one_commit_main_and_lightweight_tag(tmp_path: Path) -> None:
    source = _source_repository(tmp_path)
    output = tmp_path / "public"

    summary = create_public_mirror.prepare_public_mirror(
        ref="v1.2.3",
        output_dir=output,
        public_repo="owner/public",
        scan_package=False,
        root=source,
    )

    manifest = json.loads((output / create_public_mirror.MANIFEST_NAME).read_text())
    assert summary["version"] == "1.2.3"
    assert manifest["tree_sha256"] == create_public_mirror.calculate_tree_sha256(output)
    assert _git(["rev-list", "--count", "HEAD"], output) == "1"
    assert _git(["branch", "--show-current"], output) == "main"
    assert _git(["cat-file", "-t", "v1.2.3"], output) == "commit"


def test_public_mirror_rejects_forbidden_model_file(tmp_path: Path) -> None:
    source = _source_repository(tmp_path)
    (source / "models.md").write_text("private model export\n", encoding="utf-8")
    _git(["add", "models.md"], source)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "forbidden",
        ],
        cwd=source,
        check=True,
        capture_output=True,
        text=True,
    )
    _git(["tag", "-f", "v1.2.3"], source)

    try:
        create_public_mirror.prepare_public_mirror(
            ref="v1.2.3",
            output_dir=tmp_path / "public",
            scan_package=False,
            root=source,
        )
    except RuntimeError as exc:
        assert "forbidden model files" in str(exc)
    else:  # pragma: no cover - assertion clarity.
        raise AssertionError("forbidden model file was exported")
