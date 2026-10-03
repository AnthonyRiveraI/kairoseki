"""Claude Code hooks: put the client's *built-in* tools (Bash, WebFetch, Read...) under the same taint.

MCP traffic goes through ``kairoseki run``, but built-in tools never touch MCP. Claude Code runs
``PreToolUse`` / ``PostToolUse`` hook commands around every tool call, so ``kairoseki hook`` reads
the event on stdin, labels the call, and joins the *same* shared session as the MCP proxies:

* ``PostToolUse`` updates taint: WebFetch/WebSearch output is untrusted, Read/Grep/Bash output is
  private, secrets in any output are fingerprinted, injections get a warning added to the context.
* ``PreToolUse`` asks the engine: a secret seen this session in a WebFetch URL or a Bash command is
  denied; a sink (curl, git push, a data-carrying URL...) after untrusted + private data asks.

Only ``ask`` / ``deny`` are ever returned, never ``allow``: Kairoseki can tighten Claude Code's
permissions but never loosen them. Built-in output can't be rewritten, so redaction only applies
to MCP tools; here secrets are fingerprinted instead, which still blocks sending them anywhere.
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import sys
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .engine import ALLOW, Engine, _strings
from .labels import PRIVATE, SINK, UNTRUSTED
from .policy import Policy, load_policy
from .session_id import client_session_id
from .store import Approvals, Audit, Session, default_session_id

SERVER = "claude-code"
MATCHER = "Bash|WebFetch|WebSearch|Read|Grep"
# Claude Code runs hook commands through a shell; skip it to find the client (and its session)
SHELLS = frozenset({"bash", "sh", "dash", "zsh", "fish", "cmd", "powershell", "pwsh"})

_NET_SINK = re.compile(
    r"\b(curl|wget|nc|ncat|netcat|telnet|ssh|scp|sftp|rsync|ftp|sendmail|mail|"
    r"invoke-webrequest|invoke-restmethod|iwr|irm|send-mailmessage)\b"
    r"|\bgit\s+push\b|\bgh\s+(pr|issue|api|gist|release|repo\s+create)\b"
    r"|\b(npm|pnpm|yarn)\s+publish\b|\btwine\s+upload\b|\bdocker\s+push\b"
    r"|requests\.(get|post|put)|urllib\.request|http\.client|\bfetch\(",
    re.I,
)
# commands whose output is third-party content (a web page, an issue anyone can write)
_NET_READ = re.compile(
    r"\b(curl|wget|invoke-webrequest|invoke-restmethod|iwr|irm)\b|\bgh\s+(issue|pr)\s+view\b|\bgh\s+api\b", re.I
)


def _entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def url_carries_data(url: str) -> bool:
    """Could this URL smuggle data out? A query value, or a long random-looking path/host label.

    ``https://docs.python.org/3/library/os.html`` -> False;
    ``https://evil.example/c?d=hunter2xx`` or ``https://evil.example/Z2hwX0ZBS0Vm...`` -> True.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return True
    if any(len(v) >= 8 for _, v in parse_qsl(parts.query, keep_blank_values=True)):
        return True
    # encoded data is a long run without word separators that mixes digits or letter cases;
    # slugs like getting-started-with-python or asyncio-task.html are not
    runs = re.findall(r"[A-Za-z0-9+=]{16,}", f"{parts.hostname or ''}/{parts.path}")
    return any(
        (any(c.isdigit() for c in r) or (r.lower() != r and r.upper() != r)) and _entropy(r) >= 3.0 for r in runs
    )


def labels_for(tool: str, tool_input: dict[str, Any], strict: bool) -> tuple[set[str], set[str]]:
    """(labels of the call, labels of its output) for a built-in tool."""
    if tool == "WebFetch":
        url = str(tool_input.get("url", ""))
        return ({SINK} if strict or url_carries_data(url) else set()), {UNTRUSTED}
    if tool == "WebSearch":
        return set(), {UNTRUSTED}
    # local tools are labeled private on the call too, so code copied from a file into a local
    # command is not mistaken for disguised exfiltration (the engine's private_data_flow rule)
    if tool in ("Read", "Grep"):
        return {PRIVATE}, {PRIVATE}
    if tool == "Bash":
        command = str(tool_input.get("command", ""))
        call = {SINK} if _NET_SINK.search(command) else {PRIVATE}
        return call, ({UNTRUSTED} if _NET_READ.search(command) else {PRIVATE})
    return set(), set()


def _engine(tool: str, labels: set[str], policy: Policy) -> Engine:
    session_id = default_session_id() if os.environ.get("KAIROSEKI_SESSION") else client_session_id(extra=SHELLS)
    engine = Engine(SERVER, policy, Session(session_id), approvals=Approvals(), audit=Audit())
    explicit = policy.explicit_labels(SERVER, tool)
    engine.labels[tool] = explicit if explicit is not None else labels
    return engine


def handle(event: dict[str, Any]) -> dict[str, Any] | None:
    """Process one hook event; return the JSON to print, or None to stay out of the way."""
    tool = str(event.get("tool_name", ""))
    if tool.startswith("mcp__"):
        return None  # MCP tools are handled by the `kairoseki run` proxies
    tool_input = event.get("tool_input") or {}
    name = event.get("hook_event_name")
    policy = load_policy()
    call_labels, output_labels = labels_for(tool, tool_input, policy.mode == "strict")

    if name == "PreToolUse":
        engine = _engine(tool, call_labels, policy)
        decision = engine.decide(tool, tool_input)
        if decision.action == ALLOW:
            return None
        reason = f"🪨 Kairoseki ({decision.rule}): " + "; ".join(decision.reasons)
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision.action,  # "ask" or "deny"
                "permissionDecisionReason": reason,
            }
        }

    if name == "PostToolUse" and output_labels:
        engine = _engine(tool, output_labels, policy)
        text = "\n".join(_strings(event.get("tool_response")))
        out = engine.on_tool_result(tool, {"content": [{"type": "text", "text": text}]})
        warning = out["content"][0]["text"] if len(out["content"]) > 1 else ""
        if warning:
            return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": warning}}
    return None


def run_hook(stdin: Any = None) -> int:
    """Entry point of ``kairoseki hook``. Never breaks the client: errors are logged, not raised."""
    try:
        event = json.load(stdin or sys.stdin)
        result = handle(event) if isinstance(event, dict) else None
    except Exception as e:
        print(f"kairoseki hook error: {e!r}", file=sys.stderr)
        return 1  # non-blocking error in Claude Code; the tool call proceeds under normal permissions
    if result is not None:
        print(json.dumps(result))
    return 0


# ---------------------------------------------------------------------------- install


def settings_path(scope: str, cwd: Path | None = None) -> Path:
    cwd = cwd or Path.cwd()
    return {
        "user": Path.home() / ".claude" / "settings.json",
        "project": cwd / ".claude" / "settings.json",
        "local": cwd / ".claude" / "settings.local.json",
    }[scope]


def hook_command() -> str:
    exe = shutil.which("kairoseki")
    # forward slashes work in Git Bash, cmd and POSIX shells alike
    return f'"{Path(exe).as_posix()}" hook' if exe else f'"{Path(sys.executable).as_posix()}" -m kairoseki hook'


def _is_ours(group: Any) -> bool:
    hooks = group.get("hooks") if isinstance(group, dict) else None
    return isinstance(hooks, list) and any(
        isinstance(h, dict) and "kairoseki" in str(h.get("command", "")) and str(h.get("command", "")).endswith(" hook")
        for h in hooks
    )


def install(path: Path, undo: bool = False) -> bool:
    """Add (or remove) Kairoseki's PreToolUse/PostToolUse hooks in a Claude Code settings file.

    Other settings and hooks are preserved; a ``.kairoseki.bak`` backup is written before the first change.
    """
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    hooks = data.setdefault("hooks", {})
    changed = False
    for event in ("PreToolUse", "PostToolUse"):
        groups = hooks.get(event) or []
        kept = [g for g in groups if not _is_ours(g)]
        if undo:
            changed |= len(kept) != len(groups)
            new = kept
        else:
            if len(kept) != len(groups):
                continue  # already installed
            new = [
                *kept,
                {"matcher": MATCHER, "hooks": [{"type": "command", "command": hook_command(), "timeout": 10}]},
            ]
            changed = True
        if new:
            hooks[event] = new
        else:
            hooks.pop(event, None)
    if not hooks:
        data.pop("hooks", None)
    if changed:
        backup = path.with_suffix(path.suffix + ".kairoseki.bak")
        if path.is_file() and not backup.exists():
            backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return changed


def installed(path: Path) -> bool:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return any(_is_ours(g) for g in (data.get("hooks") or {}).get("PreToolUse") or [])
