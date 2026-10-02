"""Run the attack lab: replay every scenario with and without Kairoseki and score the result."""

from __future__ import annotations

import base64
import contextlib
import json
import re
import sys
import tempfile
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..client import StdioClient, result_text
from .scenarios import Scenario, build_scenarios

_REF = re.compile(r"\{(out|grep|b64grep):(\d+)(?::([^}]*))?\}")


@dataclass
class ScenarioResult:
    scenario: Scenario
    protected: bool
    leaked: bool = False
    blocked_steps: list[int] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def passed(self) -> bool:
        if self.error:
            return False
        if self.scenario.kind == "attack":
            return not self.leaked
        return not self.blocked_steps


@dataclass
class Report:
    mode: str
    results: list[ScenarioResult]
    baseline: list[ScenarioResult]
    seconds: float

    @property
    def attacks(self) -> list[ScenarioResult]:
        return [r for r in self.results if r.scenario.kind == "attack"]

    @property
    def benign(self) -> list[ScenarioResult]:
        return [r for r in self.results if r.scenario.kind == "benign"]

    @property
    def blocked(self) -> int:
        return sum(r.passed for r in self.attacks)

    @property
    def benign_ok(self) -> int:
        return sum(r.passed for r in self.benign)

    @property
    def grade(self) -> str:
        a = self.blocked / max(len(self.attacks), 1)
        b = self.benign_ok / max(len(self.benign), 1)
        if a == 1 and b == 1:
            return "A+"
        if a == 1 and b >= 0.8:
            return "A"
        if a >= 0.75:
            return "B"
        if a >= 0.5:
            return "C"
        if a > 0:
            return "D"
        return "F"

    def to_json(self) -> dict[str, Any]:
        def row(r: ScenarioResult) -> dict[str, Any]:
            return {
                "id": r.scenario.id,
                "kind": r.scenario.kind,
                "passed": r.passed,
                "leaked": r.leaked,
                "blocked_steps": r.blocked_steps,
                "rules": r.rules,
                "error": r.error,
                "reference": r.scenario.reference,
            }

        return {
            "grade": self.grade,
            "mode": self.mode,
            "attacks_blocked": self.blocked,
            "attacks_total": len(self.attacks),
            "benign_passed": self.benign_ok,
            "benign_total": len(self.benign),
            "baseline_leaked": sum(r.leaked for r in self.baseline if r.scenario.kind == "attack"),
            "scenarios": [row(r) for r in self.results],
            "seconds": round(self.seconds, 2),
        }


def _render(template: Any, outputs: list[str]) -> Any:
    if isinstance(template, dict):
        return {k: _render(v, outputs) for k, v in template.items()}
    if not isinstance(template, str):
        return template

    def repl(m: re.Match[str]) -> str:
        kind, n, pattern = m.group(1), int(m.group(2)), m.group(3)
        text = outputs[n - 1] if 0 < n <= len(outputs) else ""
        if kind == "out":
            return text
        found = re.search(pattern or ".+", text)
        value = found.group(0) if found else text
        return base64.b64encode(value.encode()).decode() if kind == "b64grep" else value

    return _REF.sub(repl, template)


def _contains_canary(payload: str, canary: str) -> bool:
    if not canary:
        return False
    candidates = {payload, urllib.parse.unquote(payload), urllib.parse.unquote_plus(payload)}
    for token in re.findall(r"[A-Za-z0-9+/_-]{12,}={0,2}", payload):
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            with contextlib.suppress(ValueError, TypeError):
                candidates.add(decoder(token + "=" * (-len(token) % 4)).decode("utf-8", "ignore"))
    return any(canary in c for c in candidates)


def run_scenario(
    scenario: Scenario, protected: bool, policy: str | None = None, mode: str | None = None, timeout: float = 30.0
) -> ScenarioResult:
    result = ScenarioResult(scenario, protected)
    with tempfile.TemporaryDirectory(prefix="kairoseki-lab-") as tmp:
        root = Path(tmp)
        world = root / "world.json"
        world.write_text(json.dumps(scenario.world), encoding="utf-8")
        log = root / "calls.jsonl"
        home = root / "home"
        env = {
            "KAIROSEKI_HOME": str(home),
            "KAIROSEKI_SESSION": f"lab-{uuid.uuid4().hex[:12]}",
            "PYTHONIOENCODING": "utf-8",
        }
        clients: dict[str, StdioClient] = {}
        try:
            for server in dict.fromkeys(s.server for s in scenario.steps):
                lab = [
                    sys.executable,
                    "-m",
                    "kairoseki.lab.server",
                    "--role",
                    server,
                    "--world",
                    str(world),
                    "--log",
                    str(log),
                ]
                if protected:
                    cmd = [sys.executable, "-m", "kairoseki", "run", "--name", server]
                    if policy:
                        cmd += ["--policy", policy]
                    if mode:
                        cmd += ["--mode", mode]
                    cmd += ["--", *lab]
                else:
                    cmd = lab
                client = StdioClient(cmd, env=env, timeout=timeout)
                clients[server] = client
                client.initialize()
                client.list_tools()
            outputs: list[str] = []
            for i, step in enumerate(scenario.steps, start=1):
                client = clients[step.server]
                if step.action == "list_tools":
                    client.list_tools()
                    outputs.append("")
                    continue
                reply = client.call_tool(step.tool, _render(step.args, outputs))
                text = result_text(reply)
                if reply.get("isError") and "Kairoseki" in text:
                    result.blocked_steps.append(i)
                outputs.append(text)
        except Exception as e:  # a crash is a failure, never a silent pass
            result.error = f"{type(e).__name__}: {e}"
        finally:
            for client in clients.values():
                client.close()
        calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []
        for call in calls:
            exfil_point = (call["role"], call["tool"]) in scenario.exfil_points
            if exfil_point and _contains_canary(json.dumps(call["arguments"]), scenario.canary):
                result.leaked = True
        audit = home / "audit.jsonl"
        if audit.exists():
            for line in audit.read_text(encoding="utf-8").splitlines():
                event = json.loads(line)
                rule = event.get("rule") or event.get("event")
                if (
                    event.get("event") in ("decision", "redacted", "rug_pull", "poisoned_tool")
                    and rule not in result.rules
                ):
                    result.rules.append(rule)
    return result


def run_lab(
    policy: str | None = None, mode: str | None = None, baseline: bool = True, only: list[str] | None = None
) -> Report:
    start = time.monotonic()
    scenarios = [s for s in build_scenarios() if not only or s.id in only]
    results = [run_scenario(s, protected=True, policy=policy, mode=mode) for s in scenarios]
    base = [run_scenario(s, protected=False) for s in scenarios if s.kind == "attack"] if baseline else []
    return Report(mode=mode or "policy", results=results, baseline=base, seconds=time.monotonic() - start)
