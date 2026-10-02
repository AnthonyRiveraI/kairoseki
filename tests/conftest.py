from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent
SDK_SERVER = str(ROOT / "servers" / "sdk_server.py")


@pytest.fixture(autouse=True)
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Every test gets its own KAIROSEKI_HOME and session, never touching ~/.kairoseki."""
    home = tmp_path / "kairoseki-home"
    monkeypatch.setenv("KAIROSEKI_HOME", str(home))
    monkeypatch.setenv("KAIROSEKI_SESSION", f"test-{tmp_path.name}")
    monkeypatch.delenv("KAIROSEKI_POLICY", raising=False)
    return home


def kairoseki_argv(*args: str) -> list[str]:
    return [sys.executable, "-m", "kairoseki", *args]
