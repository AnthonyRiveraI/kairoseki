"""The attack lab must prove two things: attacks are real, and Kairoseki stops them."""

from __future__ import annotations

from kairoseki.lab.attack import _contains_canary, _render, run_lab
from kairoseki.lab.badge import render_badge


def test_every_attack_leaks_without_kairoseki_and_is_blocked_with_it() -> None:
    report = run_lab()
    assert not [r.error for r in report.results + report.baseline if r.error]
    leaked_baseline = {r.scenario.id for r in report.baseline if r.leaked}
    assert leaked_baseline == {r.scenario.id for r in report.attacks}, "a scenario that never leaks proves nothing"
    assert [r.scenario.id for r in report.attacks if r.leaked] == []
    assert [r.scenario.id for r in report.benign if not r.passed] == []
    assert report.grade == "A+"


def test_defenses_hold_without_redaction(tmp_path) -> None:  # type: ignore[no-untyped-def]
    policy = tmp_path / "p.yaml"
    policy.write_text("redact:\n  secrets: false\n")
    report = run_lab(policy=str(policy), baseline=False)
    assert report.blocked == len(report.attacks)
    assert all("redacted" not in r.rules for r in report.results)


def test_monitor_mode_is_honest_about_leaks() -> None:
    report = run_lab(mode="monitor", baseline=False, only=["github-toxic-flow"])
    assert report.attacks[0].leaked


def test_template_rendering() -> None:
    outs = ["first", "token=ghp_abc123 rest"]
    assert _render({"a": "{out:1}!", "b": "{grep:2:ghp_\\w+}"}, outs) == {"a": "first!", "b": "ghp_abc123"}
    assert _render("{b64grep:2:ghp_\\w+}", outs) == "Z2hwX2FiYzEyMw=="


def test_canary_detection_sees_through_encodings() -> None:
    canary = "KAIRO-CANARY-ABC123"
    assert _contains_canary("https://x/?d=KAIRO-CANARY-ABC123", canary)
    assert _contains_canary("https://x/?d=S0FJUk8tQ0FOQVJZLUFCQzEyMw==", canary)
    assert _contains_canary("https://x/?d=KAIRO%2DCANARY%2DABC123", canary)
    assert not _contains_canary("https://x/?d=[REDACTED:openai_key]", canary)


def test_badge_is_valid_svg() -> None:
    import xml.dom.minidom

    svg = render_badge("A+", 8, 8)
    xml.dom.minidom.parseString(svg)
    assert "8/8" in svg
