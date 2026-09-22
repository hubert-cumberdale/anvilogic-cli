#!/usr/bin/env python3
"""Scan repository text for likely secrets without printing candidate values."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ALLOWLIST = ROOT / "security" / "secret-scan-allowlist.json"
MAX_SCAN_BYTES = 2_000_000
SKIPPED_PREFIXES = (
    ".git/",
    ".mypy_cache/",
    ".pytest_cache/",
    ".ruff_cache/",
    ".venv/",
    "build/",
    "dist/",
)
TEXT_SUFFIXES = {
    ".cfg",
    ".ini",
    ".json",
    ".md",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
TEXT_NAMES = {".gitignore", "Dockerfile", "LICENSE"}
SAFE_MARKERS = (
    "dummy",
    "env-",
    "example",
    "placeholder",
    "redacted",
    "sample",
    "stored-",
    "synthetic",
)
SAFE_VALUES = {
    "api-key",
    "do-not-print",
    "header.payload.signature",
    "not-configured",
    "secret-value",
}
SAFE_VARIABLES = {"api_key", "password", "secret", "token"}

SECRET_ASSIGNMENT_RE = re.compile(
    r"""
    \b(?P<key>
        api[_-]?key|api[_-]?token|access[_-]?token|auth[_-]?token|bearer[_-]?token|
        client[_-]?secret|jwt|password|passwd|private[_-]?key|refresh[_-]?token|secret|token
    )\b\s*(?::|=)\s*(?P<quote>['"]?)(?P<value>[A-Za-z0-9_./+~:@%=-]{8,})(?P=quote)
    """,
    re.IGNORECASE | re.VERBOSE,
)


@dataclass(frozen=True)
class SecretPattern:
    label: str
    regex: re.Pattern[str]


PATTERNS = (
    SecretPattern(
        "private key block", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----")
    ),
    SecretPattern("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b")),
    SecretPattern("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    SecretPattern("AWS access key", re.compile(r"\bA(?:KIA|SIA)[0-9A-Z]{16}\b")),
    SecretPattern(
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    SecretPattern(
        "credential-bearing URL",
        re.compile(r"https?://[^\s/:]+:[^\s/@]+@", re.IGNORECASE),
    ),
)


@dataclass(frozen=True)
class SecretFinding:
    path: str
    line_number: int
    label: str

    def message(self) -> str:
        return f"{self.path}:{self.line_number}: possible {self.label}"


@dataclass(frozen=True)
class AllowlistEntry:
    path: str
    labels: frozenset[str]
    line_contains: str
    reason: str

    def allows(self, finding: SecretFinding, line: str) -> bool:
        return (
            finding.path == self.path
            and finding.label in self.labels
            and self.line_contains in line
        )


def _safe_assignment(path: str, value: str, *, quoted: bool) -> bool:
    normalized = value.strip().strip("'\"").casefold()
    if normalized.startswith("<") and normalized.endswith(">"):
        return True
    if normalized.startswith("${") and normalized.endswith("}"):
        return True
    if normalized.startswith("$"):
        return True
    if normalized in SAFE_VALUES or any(marker in normalized for marker in SAFE_MARKERS):
        return True
    if not quoted and normalized in SAFE_VARIABLES:
        return True
    return bool(
        path.endswith(".py")
        and not quoted
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", value)
    )


def _findings_for_line(path: str, line_number: int, line: str) -> list[SecretFinding]:
    findings = [
        SecretFinding(path, line_number, pattern.label)
        for pattern in PATTERNS
        if pattern.regex.search(line)
    ]
    for match in SECRET_ASSIGNMENT_RE.finditer(line):
        if not _safe_assignment(
            path, match.group("value"), quoted=bool(match.group("quote"))
        ):
            findings.append(SecretFinding(path, line_number, "secret assignment"))
    return findings


def scan_text(
    path: str,
    text: str,
    *,
    allowlist: tuple[AllowlistEntry, ...] = (),
) -> list[str]:
    errors: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for finding in _findings_for_line(path, line_number, line):
            if not any(entry.allows(finding, line) for entry in allowlist):
                errors.append(finding.message())
    return errors


def _required_string(raw: Any, *, field: str, entry_number: int) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"allowlist entry {entry_number} {field} must be a non-empty string")
    return raw


def load_allowlist(path: Path = DEFAULT_ALLOWLIST) -> tuple[AllowlistEntry, ...]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise ValueError(f"{path}: version must be 1")
    raw_entries = payload.get("allowlist")
    if not isinstance(raw_entries, list):
        raise ValueError(f"{path}: allowlist must be a list")
    entries: list[AllowlistEntry] = []
    for entry_number, raw in enumerate(raw_entries, start=1):
        if not isinstance(raw, dict) or set(raw) != {"path", "labels", "line_contains", "reason"}:
            raise ValueError(f"{path}: allowlist entry {entry_number} has invalid fields")
        labels = raw["labels"]
        if not isinstance(labels, list) or not labels or not all(
            isinstance(label, str) and label for label in labels
        ):
            raise ValueError(f"{path}: allowlist entry {entry_number} labels must be strings")
        entries.append(
            AllowlistEntry(
                path=_required_string(raw["path"], field="path", entry_number=entry_number),
                labels=frozenset(labels),
                line_contains=_required_string(
                    raw["line_contains"], field="line_contains", entry_number=entry_number
                ),
                reason=_required_string(raw["reason"], field="reason", entry_number=entry_number),
            )
        )
    return tuple(entries)


def _git_scan_files(root: Path) -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return [Path(value) for value in completed.stdout.split("\0") if value]


def scan_files(
    *, root: Path = ROOT, allowlist: tuple[AllowlistEntry, ...] = ()
) -> list[str]:
    errors: list[str] = []
    for relative_path in _git_scan_files(root):
        label = relative_path.as_posix()
        absolute_path = root / relative_path
        if any(label.startswith(prefix) for prefix in SKIPPED_PREFIXES):
            continue
        if not absolute_path.is_file() or absolute_path.stat().st_size > MAX_SCAN_BYTES:
            continue
        if (
            relative_path.suffix.lower() not in TEXT_SUFFIXES
            and relative_path.name not in TEXT_NAMES
        ):
            continue
        try:
            text = absolute_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        errors.extend(scan_text(label, text, allowlist=allowlist))
    return errors


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        allowlist = load_allowlist(args.allowlist)
        errors = scan_files(allowlist=allowlist)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Secret scan setup failed: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("Secret scan failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("Secret scan passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
