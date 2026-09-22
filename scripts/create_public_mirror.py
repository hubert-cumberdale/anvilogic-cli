#!/usr/bin/env python3
"""Create and validate a deterministic, one-commit public source mirror."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10 fallback.
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # pragma: no cover - direct script execution fallback.
    sys.path.insert(0, str(ROOT))
check_public_safety = importlib.import_module("scripts.check_public_safety")
DEFAULT_PUBLIC_REPO = "hubert-cumberdale/anvilogic-cli"
MANIFEST_NAME = "PUBLICATION_MANIFEST.json"


def _run(
    arguments: list[str], *, cwd: Path, capture_output: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=cwd,
        check=True,
        capture_output=capture_output,
        text=True,
    )


def _git_output(arguments: list[str], *, root: Path) -> str:
    return _run(arguments, cwd=root).stdout.strip()


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def ensure_output_dir(path: Path, *, root: Path = ROOT) -> Path:
    output_dir = path.expanduser().resolve()
    source_root = root.resolve()
    if output_dir == source_root or is_relative_to(output_dir, source_root):
        raise RuntimeError("public mirror export directory must be outside the source repository")
    if output_dir.exists() and not output_dir.is_dir():
        raise RuntimeError(f"public mirror export path is not a directory: {output_dir}")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise RuntimeError(f"public mirror export directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def ensure_clean_worktree(*, root: Path = ROOT) -> None:
    if _git_output(["git", "status", "--porcelain"], root=root):
        raise RuntimeError("source worktree is dirty; commit changes before strict export")


def resolve_commit(ref: str, *, root: Path = ROOT) -> str:
    return _git_output(["git", "rev-parse", "--verify", f"{ref}^{{commit}}"], root=root)


def resolve_commit_time(ref: str, *, root: Path = ROOT) -> str:
    return _git_output(["git", "show", "-s", "--format=%cI", ref], root=root)


def safe_extract_tar(archive_path: Path, output_dir: Path) -> None:
    output_root = output_dir.resolve()
    with tarfile.open(archive_path) as archive:
        for member in archive.getmembers():
            target = (output_root / member.name).resolve()
            if target != output_root and not is_relative_to(target, output_root):
                raise RuntimeError(f"archive member escapes export directory: {member.name}")
            if member.issym() or member.islnk():
                raise RuntimeError(f"public snapshot may not contain links: {member.name}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise RuntimeError(f"unsupported archive member: {member.name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = archive.extractfile(member)
            if extracted is None:
                raise RuntimeError(f"could not read archive member: {member.name}")
            target.write_bytes(extracted.read())
            target.chmod(member.mode & 0o777)


def export_ref(ref: str, output_dir: Path, *, root: Path = ROOT) -> None:
    with tempfile.TemporaryDirectory(prefix="avl-cli-public-archive-") as temporary:
        archive_path = Path(temporary) / "source.tar"
        _run(
            ["git", "archive", "--format=tar", "--output", str(archive_path), ref],
            cwd=root,
        )
        safe_extract_tar(archive_path, output_dir)


def export_working_tree(output_dir: Path, *, root: Path = ROOT) -> None:
    files = _git_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        root=root,
    ).splitlines()
    for value in files:
        relative_path = Path(value)
        source_path = root / relative_path
        if not source_path.is_file():
            continue
        target_path = output_dir / relative_path
        target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, target_path, follow_symlinks=False)


def load_package_version(root: Path) -> str:
    payload = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    return str(payload["project"]["version"])


def snapshot_files(root: Path, *, exclude_manifest: bool = False) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        relative_path = path.relative_to(root)
        if ".git" in relative_path.parts or not path.is_file():
            continue
        if exclude_manifest and relative_path.as_posix() == MANIFEST_NAME:
            continue
        files.append(relative_path)
    return sorted(files, key=lambda item: item.as_posix())


def calculate_tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for relative_path in snapshot_files(root, exclude_manifest=True):
        file_digest = hashlib.sha256((root / relative_path).read_bytes()).hexdigest()
        digest.update(relative_path.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def build_publication_manifest(
    *,
    public_repo: str,
    source_ref: str,
    source_commit: str,
    source_commit_time: str,
    version: str,
    tree_sha256: str,
    source_snapshot: str,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "public_repo": public_repo,
        "source_ref": source_ref,
        "source_commit": source_commit,
        "source_commit_time": source_commit_time,
        "source_snapshot": source_snapshot,
        "version": version,
        "tree_sha256": tree_sha256,
        "tree_sha256_excludes": [MANIFEST_NAME, ".git/"],
        "history_policy": "single sanitized source snapshot; no private git history",
        "distribution_policy": "source-only GitHub prerelease; no package assets or PyPI",
        "validation_commands": [
            "python3 scripts/check_secret_scan.py",
            "python3 scripts/check_public_safety.py",
            "python3 scripts/quality_gate.py",
            "git rev-list --count HEAD",
        ],
    }


def write_manifest(export_dir: Path, manifest: dict[str, Any]) -> Path:
    path = export_dir / MANIFEST_NAME
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def initialize_repository(export_dir: Path, *, version: str) -> None:
    _run(["git", "init"], cwd=export_dir)
    _run(["git", "symbolic-ref", "HEAD", "refs/heads/main"], cwd=export_dir)
    _run(["git", "add", "-A"], cwd=export_dir)
    _run(
        [
            "git",
            "-c",
            "user.name=Anvilogic CLI Release Bot",
            "-c",
            "user.email=release@example.invalid",
            "commit",
            "-m",
            f"Initial public release v{version}",
        ],
        cwd=export_dir,
    )
    _run(["git", "tag", f"v{version}"], cwd=export_dir)
    if _git_output(["git", "rev-list", "--count", "HEAD"], root=export_dir) != "1":
        raise RuntimeError("public mirror repository does not contain exactly one commit")
    if _git_output(["git", "status", "--porcelain"], root=export_dir):
        raise RuntimeError("public mirror repository is dirty after initialization")


def prepare_public_mirror(
    *,
    ref: str,
    output_dir: Path,
    public_repo: str = DEFAULT_PUBLIC_REPO,
    scan_package: bool = True,
    allow_dirty: bool = False,
    root: Path = ROOT,
) -> dict[str, Any]:
    if allow_dirty and ref != "HEAD":
        raise RuntimeError("--allow-dirty can only export HEAD")
    if not allow_dirty:
        ensure_clean_worktree(root=root)
    source_commit = resolve_commit(ref, root=root)
    source_commit_time = resolve_commit_time(ref, root=root)
    export_dir = ensure_output_dir(output_dir, root=root)
    if allow_dirty:
        export_working_tree(export_dir, root=root)
        source_snapshot = "working-tree"
    else:
        export_ref(ref, export_dir, root=root)
        source_snapshot = "git-archive"

    version = load_package_version(export_dir)
    if not allow_dirty and ref != f"v{version}":
        raise RuntimeError(f"strict export ref must be v{version}, got {ref}")
    forbidden = [
        relative_path.as_posix()
        for relative_path in snapshot_files(export_dir)
        if relative_path.name in check_public_safety.FORBIDDEN_MODEL_NAMES
    ]
    if forbidden:
        raise RuntimeError("forbidden model files in public snapshot: " + ", ".join(forbidden))

    manifest = build_publication_manifest(
        public_repo=public_repo,
        source_ref=ref,
        source_commit=source_commit,
        source_commit_time=source_commit_time,
        version=version,
        tree_sha256=calculate_tree_sha256(export_dir),
        source_snapshot=source_snapshot,
    )
    manifest_path = write_manifest(export_dir, manifest)
    errors = check_public_safety.scan_snapshot_tree(export_dir)
    if scan_package:
        with tempfile.TemporaryDirectory(prefix="avl-cli-mirror-wheel-") as temporary:
            wheel = check_public_safety.build_wheel(Path(temporary), root=export_dir)
            errors.extend(check_public_safety.scan_wheel(wheel))
    if errors:
        raise RuntimeError("public mirror safety scan failed:\n- " + "\n- ".join(errors))
    initialize_repository(export_dir, version=version)
    return {
        "export_dir": export_dir,
        "manifest_path": manifest_path,
        "public_repo": public_repo,
        "source_commit": source_commit,
        "source_ref": ref,
        "version": version,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", default="HEAD")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--public-repo", default=DEFAULT_PUBLIC_REPO)
    parser.add_argument("--skip-wheel", action="store_true")
    parser.add_argument("--allow-dirty", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        summary = prepare_public_mirror(
            ref=args.ref,
            output_dir=args.output_dir,
            public_repo=args.public_repo,
            scan_package=not args.skip_wheel,
            allow_dirty=args.allow_dirty,
        )
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Public mirror creation failed: {exc}", file=sys.stderr)
        return 1
    print("Public mirror created.")
    for key, value in summary.items():
        print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
