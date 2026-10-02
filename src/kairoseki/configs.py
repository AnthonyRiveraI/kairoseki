"""Find MCP client config files and wrap / unwrap their servers with Kairoseki."""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ServerEntry:
    name: str
    command: str | None
    args: list[str]
    env: dict[str, str]
    url: str | None = None
    scope: str = "user"

    @property
    def wrapped(self) -> bool:
        return is_wrapped(self.command, self.args)

    def argv(self) -> list[str]:
        return [self.command, *self.args] if self.command else []


def candidate_configs(cwd: Path | None = None) -> list[tuple[str, Path]]:
    home = Path.home()
    cwd = cwd or Path.cwd()
    appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
    items = [
        ("Claude Code (project)", cwd / ".mcp.json"),
        ("Claude Code (user)", home / ".claude.json"),
        ("Cursor (project)", cwd / ".cursor" / "mcp.json"),
        ("Cursor (user)", home / ".cursor" / "mcp.json"),
        ("VS Code (project)", cwd / ".vscode" / "mcp.json"),
        ("Windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"),
    ]
    if sys.platform == "darwin":
        items.append(
            ("Claude Desktop", home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json")
        )
    elif os.name == "nt":
        items.append(("Claude Desktop", appdata / "Claude" / "claude_desktop_config.json"))
    else:
        items.append(("Claude Desktop", home / ".config" / "Claude" / "claude_desktop_config.json"))
    return [(label, p) for label, p in items if p.is_file()]


def _servers_key(data: dict[str, Any]) -> str | None:
    for key in ("mcpServers", "servers"):
        if isinstance(data.get(key), dict):
            return key
    return None


def _project_key(path: str | os.PathLike[str]) -> str:
    text = str(path).replace("\\", "/").rstrip("/") or "/"
    # Windows paths are case-insensitive; Claude Code writes them with forward slashes
    return text.lower() if re.match(r"^[A-Za-z]:", text) else text


def same_project(a: str | os.PathLike[str], b: str | os.PathLike[str]) -> bool:
    return _project_key(a) == _project_key(b)


def server_blocks(
    data: dict[str, Any], cwd: Path | None = None, all_projects: bool = False, top_scope: str = "user"
) -> list[tuple[str, dict[str, Any]]]:
    """Every ``{name: server}`` mapping in a client config, with its scope.

    Besides the top-level ``mcpServers`` (or VS Code's ``servers``), Claude Code keeps
    *local*-scope servers per project in ``~/.claude.json`` under
    ``projects["<project path>"].mcpServers``. Only the current project's block is
    included unless ``all_projects`` is set.
    """
    blocks: list[tuple[str, dict[str, Any]]] = []
    key = _servers_key(data)
    if key is not None:
        blocks.append((top_scope, data[key]))
    projects = data.get("projects")
    if isinstance(projects, dict):
        here = cwd or Path.cwd()
        for project, settings in projects.items():
            servers = settings.get("mcpServers") if isinstance(settings, dict) else None
            if isinstance(servers, dict) and servers and (all_projects or same_project(project, here)):
                blocks.append((f"local ({project})", servers))
    return blocks


def config_scope(path: Path, cwd: Path | None = None) -> str:
    """Claude Code's names: ``project`` for files in the project, ``user`` for global ones."""
    try:
        path.resolve().relative_to((cwd or Path.cwd()).resolve())
        return "project"
    except ValueError:
        return "user"


def read_servers(path: Path, cwd: Path | None = None, all_projects: bool = False) -> list[ServerEntry]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for scope, servers in server_blocks(data, cwd, all_projects, config_scope(path, cwd)):
        for name, entry in servers.items():
            if not isinstance(entry, dict):
                continue
            out.append(
                ServerEntry(
                    name=str(name),
                    command=entry.get("command"),
                    args=[str(a) for a in entry.get("args") or []],
                    env={str(k): str(v) for k, v in (entry.get("env") or {}).items()},
                    url=entry.get("url") or entry.get("serverUrl"),
                    scope=scope,
                )
            )
    return out


def kairoseki_command() -> list[str]:
    exe = shutil.which("kairoseki")
    return [exe] if exe else [sys.executable, "-m", "kairoseki"]


def is_wrapped(command: str | None, args: list[str]) -> bool:
    argv = [command or "", *args]
    return "run" in argv and "--" in argv and any("kairoseki" in a for a in argv[: argv.index("run")])


def unwrap_argv(command: str, args: list[str]) -> tuple[str, list[str]]:
    argv = [command, *args]
    rest = argv[argv.index("--") + 1 :]
    return rest[0], rest[1:]


def wrap_config(
    path: Path,
    policy: str | None = None,
    only: list[str] | None = None,
    cwd: Path | None = None,
    all_projects: bool = False,
) -> list[str]:
    """Route stdio servers in ``path`` through Kairoseki. Writes a ``.kairoseki.bak`` backup first."""
    data = json.loads(path.read_text(encoding="utf-8"))
    changed = []
    base = kairoseki_command()
    for _scope, servers in server_blocks(data, cwd, all_projects):
        for name, entry in servers.items():
            if only and name not in only:
                continue
            if not isinstance(entry, dict) or not entry.get("command"):
                continue  # remote (HTTP) servers are not supported yet
            args = [str(a) for a in entry.get("args") or []]
            if is_wrapped(entry["command"], args):
                continue
            new = [*base[1:], "run", "--name", name]
            if policy:
                new += ["--policy", str(Path(policy).resolve())]
            entry["args"] = [*new, "--", entry["command"], *args]
            entry["command"] = base[0]
            changed.append(name)
    if changed:
        backup = path.with_suffix(path.suffix + ".kairoseki.bak")
        if not backup.exists():
            shutil.copy2(path, backup)
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return changed


def unwrap_config(path: Path, cwd: Path | None = None, all_projects: bool = False) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    changed = []
    for _scope, servers in server_blocks(data, cwd, all_projects):
        for name, entry in servers.items():
            if not isinstance(entry, dict) or not entry.get("command"):
                continue
            args = [str(a) for a in entry.get("args") or []]
            if is_wrapped(entry["command"], args):
                entry["command"], entry["args"] = unwrap_argv(entry["command"], args)
                changed.append(name)
    if changed:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return changed
