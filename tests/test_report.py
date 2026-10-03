from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from kairoseki.labels import PRIVATE, SINK, UNTRUSTED
from kairoseki.report import ScanResult, render_card

from .conftest import SDK_SERVER, kairoseki_argv


def result(unprotected: list[str], poisoned: list[str] | None = None, legs: bool = True) -> ScanResult:
    r = ScanResult(servers=3, unprotected=unprotected, poisoned=poisoned or [])
    if legs:
        r.legs = {PRIVATE: ["files.read_file"], UNTRUSTED: ["fetch.fetch"], SINK: ["fetch.fetch"]}
    return r


def test_grades() -> None:
    assert result(["fetch"], poisoned=["evil.add"]).grade == "F"
    assert result(["fetch"]).grade == "D"  # trifecta through an unprotected server
    assert result(["codegraph"]).grade == "B"  # trifecta servers are wrapped, another one isn't
    assert result(["fetch"], legs=False).grade == "B"
    assert result([]).grade == "A"


def test_card_is_valid_svg_without_private_details() -> None:
    card = render_card(result(["fetch"]))
    assert card.startswith("<svg") and card.rstrip().endswith("</svg>")
    assert ">D<" in card and "uvx kairoseki scan" in card
    assert "fetch" not in card and "files" not in card  # server and tool names stay private


def test_scan_share_and_json(tmp_path: Path) -> None:
    card = tmp_path / "card.svg"
    argv = kairoseki_argv("scan", "--json", "--share", str(card), "--", sys.executable, SDK_SERVER)
    out = subprocess.run(argv, capture_output=True, encoding="utf-8")
    data = json.loads(out.stdout)
    assert data["grade"] in {"A", "B", "D", "F"} and data["servers"] == 1
    assert card.read_text(encoding="utf-8").startswith("<svg")
