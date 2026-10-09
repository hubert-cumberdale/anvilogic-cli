#!/usr/bin/env python3
"""Check tracked source and a built wheel against the public release boundary."""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

try:
    from scripts import check_secret_scan
except ModuleNotFoundError:  # pragma: no cover - direct script execution fallback.
    import check_secret_scan  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_OPENAPI_FILENAME = "anvilogic-combined-apis.yaml"
UPSTREAM_OPENAPI_SHA256 = "0e96b604ed12ef29007b38f209855f9a5577ae198ee330fa06692ddf876f884c"
FORBIDDEN_MODEL_NAMES = {
    "models.md",
    "openapi.yaml",
    "openapi.yml",
    "schemas.json",
    UPSTREAM_OPENAPI_FILENAME,
}
FORBIDDEN_CAPTURE_SUFFIXES = {".burp", ".har", ".pcap", ".pcapng", ".saz"}
FORBIDDEN_WHEEL_NAMES = FORBIDDEN_MODEL_NAMES
SKIPPED_PREFIXES = (
    ".git/",
    ".mypy_cache/",
    ".pytest_cache/",
    ".ruff_cache/",
    ".venv/",
    "build/",
    "dist/",
)


@dataclass(frozen=True)
class BlockedPattern:
    label: str
    regex: re.Pattern[str]


BLOCKED_PATTERNS = (
    BlockedPattern(
        "private Unix user path",
        re.compile(r"/(?:home|Users)/[A-Za-z0-9._-]+/"),
    ),
    BlockedPattern(
        "private Windows user path",
        re.compile(r"[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s]+[\\/]", re.IGNORECASE),
    ),
    BlockedPattern(
        "private hostname",
        re.compile(r"\b[A-Za-z0-9-]+\.(?:internal|lan|local)\b", re.IGNORECASE),
    ),
)
TOP_LEVEL_OPENAPI_RE = re.compile(
    rb"(?m)^[ \t]*(?:openapi|['\"]openapi['\"])[ \t]*:(?=[ \t\r\n]|$)"
)
TOP_LEVEL_PATHS_RE = re.compile(
    rb"(?m)^[ \t]*(?:paths|['\"]paths['\"])[ \t]*:(?=[ \t\r\n]|$)"
)
TOP_LEVEL_COMPONENTS_RE = re.compile(
    rb"(?m)^[ \t]*(?:components|['\"]components['\"])[ \t]*:(?=[ \t\r\n]|$)"
)
YAML_SCHEMAS_RE = re.compile(
    rb"(?m)^[ \t]+(?:schemas|['\"]schemas['\"])[ \t]*:(?=[ \t\r\n]|$)"
)
OPENAPI_KEY_RE = re.compile(rb"(?:openapi|['\"]openapi['\"])[ \t]*:")
PATHS_KEY_RE = re.compile(rb"(?:paths|['\"]paths['\"])[ \t]*:")
COMPONENTS_KEY_RE = re.compile(rb"(?:components|['\"]components['\"])[ \t]*:")
SCHEMAS_KEY_RE = re.compile(rb"(?:schemas|['\"]schemas['\"])[ \t]*:")


def _git_tracked_files(root: Path = ROOT) -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return [Path(line) for line in completed.stdout.splitlines() if line.strip()]


def _should_scan_file(relative_path: Path, absolute_path: Path) -> bool:
    label = relative_path.as_posix()
    if any(label.startswith(prefix) for prefix in SKIPPED_PREFIXES):
        return False
    return absolute_path.is_file()


def _path_findings(relative_path: Path) -> list[str]:
    label = relative_path.as_posix()
    errors: list[str] = []
    if relative_path.name.casefold() in FORBIDDEN_MODEL_NAMES:
        errors.append(f"{label}: forbidden model-catalog artifact")
    if relative_path.suffix.casefold() in FORBIDDEN_CAPTURE_SUFFIXES:
        errors.append(f"{label}: forbidden raw-capture artifact")
    return errors


def _content_findings(path_label: str, body: bytes) -> list[str]:
    errors: list[str] = []
    if hashlib.sha256(body).hexdigest() == UPSTREAM_OPENAPI_SHA256:
        return [f"{path_label}: forbidden complete upstream OpenAPI document"]
    lowered = body.lower()
    has_openapi = OPENAPI_KEY_RE.search(lowered) is not None
    has_components = COMPONENTS_KEY_RE.search(lowered) is not None
    has_schemas = SCHEMAS_KEY_RE.search(lowered) is not None
    has_paths = PATHS_KEY_RE.search(lowered) is not None
    yaml_openapi = bool(
        TOP_LEVEL_OPENAPI_RE.search(lowered)
        and TOP_LEVEL_PATHS_RE.search(lowered)
        and TOP_LEVEL_COMPONENTS_RE.search(lowered)
    )
    json_document = lowered.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"{")
    json_openapi = json_document and has_openapi and has_components and has_paths
    yaml_schemas = YAML_SCHEMAS_RE.search(lowered) is not None
    complete_openapi = (yaml_openapi and yaml_schemas) or (json_openapi and has_schemas)
    large_model_corpus = len(body) >= 250_000 and (
        (TOP_LEVEL_COMPONENTS_RE.search(lowered) is not None and yaml_schemas)
        or (json_document and has_components and has_schemas)
    )
    if complete_openapi or large_model_corpus:
        errors.append(f"{path_label}: forbidden complete OpenAPI/model corpus")
    return errors


def _scan_text(
    path_label: str,
    text: str,
    *,
    allowlist: tuple[check_secret_scan.AllowlistEntry, ...] = (),
) -> list[str]:
    errors: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for pattern in BLOCKED_PATTERNS:
            if pattern.regex.search(line):
                errors.append(f"{path_label}:{line_number}: blocked {pattern.label}")
    errors.extend(check_secret_scan.scan_text(path_label, text, allowlist=allowlist))
    return errors


def scan_paths(
    paths: list[Path],
    *,
    root: Path,
    allowlist: tuple[check_secret_scan.AllowlistEntry, ...] = (),
) -> list[str]:
    errors: list[str] = []
    for relative_path in paths:
        absolute_path = root / relative_path
        if not absolute_path.exists():
            continue
        errors.extend(_path_findings(relative_path))
        if not _should_scan_file(relative_path, absolute_path):
            continue
        body = absolute_path.read_bytes()
        errors.extend(_content_findings(relative_path.as_posix(), body))
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            continue
        errors.extend(_scan_text(relative_path.as_posix(), text, allowlist=allowlist))
    return errors


def scan_tracked_files(root: Path = ROOT) -> list[str]:
    allowlist = check_secret_scan.load_allowlist(
        root / "security" / "secret-scan-allowlist.json"
    )
    return scan_paths(_git_tracked_files(root), root=root, allowlist=allowlist)


def scan_snapshot_tree(root: Path) -> list[str]:
    paths = sorted(
        (
            path.relative_to(root)
            for path in root.rglob("*")
            if path.is_file() and ".git" not in path.relative_to(root).parts
        ),
        key=lambda path: path.as_posix(),
    )
    allowlist = check_secret_scan.load_allowlist(
        root / "security" / "secret-scan-allowlist.json"
    )
    return scan_paths(paths, root=root, allowlist=allowlist)


def validate_wheel_entries(entries: list[str]) -> list[str]:
    errors: list[str] = []
    for entry in entries:
        path = Path(entry)
        if path.name.casefold() in FORBIDDEN_WHEEL_NAMES:
            errors.append(f"wheel contains forbidden model catalog: {entry}")
        if path.suffix.casefold() in FORBIDDEN_CAPTURE_SUFFIXES:
            errors.append(f"wheel contains forbidden raw capture: {entry}")
    return errors


def build_wheel(output_dir: Path, *, root: Path = ROOT) -> Path:
    with tempfile.TemporaryDirectory(prefix="avl-cli-wheel-source-") as temporary:
        source = Path(temporary) / "source"
        shutil.copytree(
            root,
            source,
            ignore=shutil.ignore_patterns(
                ".git",
                ".mypy_cache",
                ".pytest_cache",
                ".ruff_cache",
                ".venv",
                "build",
                "dist",
                "*.egg-info",
                "__pycache__",
            ),
        )
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "-c",
                "constraints.txt",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                str(output_dir),
                ".",
            ],
            cwd=source,
            check=True,
        )
    wheels = sorted(output_dir.glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected exactly one wheel, found {len(wheels)}")
    return wheels[0]


def scan_wheel(
    wheel_path: Path,
    *,
    allowlist: tuple[check_secret_scan.AllowlistEntry, ...] = (),
) -> list[str]:
    errors: list[str] = []
    with zipfile.ZipFile(wheel_path) as wheel:
        entries = [info.filename for info in wheel.infolist()]
        errors.extend(validate_wheel_entries(entries))
        for info in wheel.infolist():
            if info.is_dir():
                continue
            body = wheel.read(info)
            errors.extend(_content_findings(info.filename, body))
            try:
                text = body.decode("utf-8")
            except UnicodeDecodeError:
                continue
            errors.extend(
                _scan_text(
                    f"{wheel_path.name}!{info.filename}", text, allowlist=allowlist
                )
            )
    return errors


def scan_sdist(
    sdist_path: Path,
    *,
    allowlist: tuple[check_secret_scan.AllowlistEntry, ...] = (),
) -> list[str]:
    """Inspect every regular sdist member regardless of name, extension, or size."""
    errors: list[str] = []
    with tarfile.open(sdist_path, mode="r:gz") as archive:
        all_members = archive.getmembers()
        members = [member for member in all_members if member.isfile()]
        entries = [member.name for member in all_members]
        for finding in validate_wheel_entries(entries):
            errors.append(finding.replace("wheel contains", "sdist contains", 1))
        for member in all_members:
            if not member.isfile() and not member.isdir():
                errors.append(f"sdist contains unsupported archive member: {member.name}")
        for member in members:
            extracted = archive.extractfile(member)
            if extracted is None:
                errors.append(f"could not inspect sdist member: {member.name}")
                continue
            body = extracted.read()
            errors.extend(_content_findings(member.name, body))
            try:
                text = body.decode("utf-8")
            except UnicodeDecodeError:
                continue
            errors.extend(
                _scan_text(
                    f"{sdist_path.name}!{member.name}", text, allowlist=allowlist
                )
            )
    return errors


def check_public_safety(*, root: Path = ROOT, scan_package: bool = True) -> list[str]:
    errors = scan_tracked_files(root)
    if scan_package:
        try:
            with tempfile.TemporaryDirectory(prefix="avl-cli-public-wheel-") as tmpdir:
                wheel = build_wheel(Path(tmpdir), root=root)
                errors.extend(scan_wheel(wheel))
        except (OSError, RuntimeError, subprocess.CalledProcessError, zipfile.BadZipFile) as exc:
            errors.append(f"wheel build or inspection failed: {exc}")
    return errors


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-wheel",
        action="store_true",
        help="Scan tracked source only; skip wheel build and inspection.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        errors = check_public_safety(scan_package=not args.skip_wheel)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Public-safety scan could not run: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("Public-safety scan failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("Public-safety scan passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
