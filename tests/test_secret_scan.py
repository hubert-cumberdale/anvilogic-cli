from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import check_secret_scan


def test_secret_finding_does_not_echo_candidate() -> None:
    candidate = "sk_live_" + "1234567890abcdef"

    errors = check_secret_scan.scan_text("fixture.env", f"api_token={candidate}\n")

    assert errors == ["fixture.env:1: possible secret assignment"]
    assert candidate not in errors[0]


def test_placeholder_assignments_are_allowed() -> None:
    assert check_secret_scan.scan_text("README.md", "api_key=<api-key>\n") == []
    assert check_secret_scan.scan_text("README.md", "password=${PASSWORD}\n") == []


def test_reviewed_allowlist_entry_is_narrow() -> None:
    candidate = "sk_live_" + "1234567890abcdef"
    entry = check_secret_scan.AllowlistEntry(
        path="tests/fixture.txt",
        labels=frozenset({"secret assignment"}),
        line_contains="api_token",
        reason="synthetic scanner fixture",
    )

    assert check_secret_scan.scan_text(
        "tests/fixture.txt",
        f"api_token={candidate}\n",
        allowlist=(entry,),
    ) == []
    assert check_secret_scan.scan_text(
        "other.txt",
        f"api_token={candidate}\n",
        allowlist=(entry,),
    )


def test_allowlist_requires_a_review_reason(tmp_path: Path) -> None:
    allowlist = tmp_path / "allowlist.json"
    allowlist.write_text(
        json.dumps(
            {
                "version": 1,
                "allowlist": [
                    {
                        "path": "tests/fixture.txt",
                        "labels": ["secret assignment"],
                        "line_contains": "api_token",
                        "reason": "",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="reason must be a non-empty string"):
        check_secret_scan.load_allowlist(allowlist)
