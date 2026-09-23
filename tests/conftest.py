from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("ANVILOGIC_CONFIG_DIR", str(tmp_path / "config"))
    for name in (
        "ANVILOGIC_API_KEY",
        "ANVILOGIC_AUTH_SCHEME",
        "ANVILOGIC_BASE_URL",
        "ANVILOGIC_MODELS_PATH",
    ):
        monkeypatch.delenv(name, raising=False)
