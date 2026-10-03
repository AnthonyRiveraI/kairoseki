"""Policy parsing, shared session store, client configs and the CLI."""

from __future__ import annotations

import json
import multiprocessing
import subprocess
import sys
from pathlib import Path

import pytest

from kairoseki.configs import is_wrapped, read_servers, unwrap_config, wrap_config
from kairoseki.policy import DEFAULT_POLICY_YAML, PolicyError, load_policy, parse_policy
from kairoseki.store import Session

from .conftest import kairoseki_argv

# ---------------------------------------------------------------------------- policy


def test_default_policy_file_parses_to_defaults(tmp_path: Path) -> None:
    path = tmp_path / "k.yaml"
    path.write_text(DEFAULT_POLICY_YAML)
    p = load_policy(path)
    assert p.mode == "balanced" and p.redact_secrets and not p.redact_pii and p.pin_tools


@pytest.mark.parametrize(
    "data",
    [{"mode": "yolo"}, {"redact": {"secrets": "yes"}}, {"servers": {"gh": {"tools": {"x": ["superpower"]}}}}],
)
def test_invalid_policies_are_rejected(data: dict) -> None:
    with pytest.raises(PolicyError):
        parse_policy(data)


def test_missing_policy_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "nope.yaml")


def test_server_globs() -> None:
    p = parse_policy({"servers": {"git*": {"deny": ["delete_*"]}}})
    assert p.is_denied("github", "delete_repo") and not p.is_denied("slack", "delete_repo")


# ---------------------------------------------------------------------------- shared session


def _mark(args: tuple[str, str, int]) -> None:
    home, session, i = args
    import os

    os.environ["KAIROSEKI_HOME"] = home
    Session(session).mark("untrusted", f"srv{i}", "tool")


def test_concurrent_proxies_never_lose_updates(isolated_home: Path) -> None:
    with multiprocessing.get_context("spawn").Pool(8) as pool:
        pool.map(_mark, [(str(isolated_home), "shared", i) for i in range(40)])
    sources = Session("shared").snapshot()["untrusted"]
    assert len(sources) == 40


# ---------------------------------------------------------------------------- configs


def test_wrap_and_unwrap_roundtrip(tmp_path: Path) -> None:
    cfg = tmp_path / "claude_desktop_config.json"
    original = {
        "mcpServers": {
            "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},
            "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {"T": "x"}},
            "remote": {"url": "https://mcp.example.com/mcp"},
        },
        "otherSetting": True,
    }
    cfg.write_text(json.dumps(original))
    assert sorted(wrap_config(cfg)) == ["fetch", "github"]
    wrapped = json.loads(cfg.read_text())
    gh = wrapped["mcpServers"]["github"]
    assert is_wrapped(gh["command"], gh["args"]) and gh["env"] == {"T": "x"}
    assert gh["args"][-3:] == ["npx", "-y", "@modelcontextprotocol/server-github"]
    assert wrapped["mcpServers"]["remote"] == {"url": "https://mcp.example.com/mcp"}
    assert wrap_config(cfg) == []  # idempotent
    assert (tmp_path / "claude_desktop_config.json.kairoseki.bak").exists()
    assert sorted(unwrap_config(cfg)) == ["fetch", "github"]
    assert json.loads(cfg.read_text()) == original


def test_vscode_servers_key(tmp_path: Path) -> None:
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"servers": {"fs": {"command": "npx", "args": ["fs"]}}}))
    assert [s.name for s in read_servers(cfg)] == ["fs"]
    assert wrap_config(cfg) == ["fs"]


# ---------------------------------------------------------------------------- CLI


def cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(kairoseki_argv(*args), capture_output=True, encoding="utf-8", cwd=cwd, timeout=120)


def test_cli_init_writes_valid_policy(tmp_path: Path) -> None:
    assert cli("init", cwd=tmp_path).returncode == 0
    assert load_policy(tmp_path / "kairoseki.yaml").mode == "balanced"
    assert cli("init", cwd=tmp_path).returncode == 1  # refuses to overwrite


def test_cli_scan_finds_poison_and_trifecta(tmp_path: Path) -> None:
    lab = [sys.executable, "-m", "kairoseki.lab.server", "--role"]
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "web": {"command": lab[0], "args": [*lab[1:], "web"]},
                    "files": {"command": lab[0], "args": [*lab[1:], "files"]},
                    "evil": {"command": lab[0], "args": [*lab[1:], "poisoned"]},
                }
            }
        )
    )
    r = cli("scan", "--config", str(cfg))
    assert r.returncode == 1
    assert "poisoned description" in r.stdout
    assert "Lethal trifecta present" in r.stdout


def test_cli_scan_single_clean_server() -> None:
    r = cli("scan", "--", sys.executable, "-m", "kairoseki.lab.server", "--role", "files")
    assert r.returncode == 0 and "No lethal trifecta" in r.stdout


def test_cli_run_requires_a_command() -> None:
    assert cli("run").returncode == 2


def test_cli_rejects_bad_policy(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("mode: yolo\n")
    r = cli("run", "--policy", str(bad), "--", sys.executable, "-c", "pass")
    assert r.returncode == 2 and "mode must be one of" in r.stderr


def test_cli_log_and_status_and_pins_work_when_empty() -> None:
    for args in (["log"], ["status"], ["pins", "list"], ["approve"]):
        assert cli(*args).returncode == 0, args


# ---------------------------------------------------------------------------- Claude Code local scope


def _claude_json(tmp_path: Path, project_key: str) -> Path:
    cfg = tmp_path / ".claude.json"
    cfg.write_text(
        json.dumps(
            {
                "numStartups": 12,
                "mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}},
                "projects": {
                    project_key: {
                        "allowedTools": [],
                        "mcpServers": {"filesystem": {"type": "stdio", "command": "npx", "args": ["-y", "fs", "."]}},
                    },
                    "C:/Users/Neo/other": {"mcpServers": {"other": {"command": "node", "args": ["x.js"]}}},
                },
            }
        )
    )
    return cfg


def test_local_scope_servers_of_the_current_project_are_read(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    cfg = _claude_json(tmp_path, str(project).replace("\\", "/"))
    names = {(s.name, s.scope) for s in read_servers(cfg, cwd=project)}
    assert ("fetch", "user") in names
    assert any(n == "filesystem" and scope.startswith("local") for n, scope in names)
    assert all(n != "other" for n, _ in names)  # another project's servers are not touched by default
    assert any(n == "other" for n, _ in {(s.name, s.scope) for s in read_servers(cfg, cwd=project, all_projects=True)})


def test_windows_project_keys_match_regardless_of_slashes_and_case() -> None:
    from kairoseki.configs import same_project

    assert same_project("C:/Users/Neo/proj", r"c:\users\neo\proj")
    assert same_project("C:/Users/Neo/proj/", "C:/Users/Neo/proj")
    assert not same_project("/home/neo/proj", "/home/neo/Proj")  # POSIX paths stay case-sensitive


def test_wrap_and_unwrap_local_scope(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    cfg = _claude_json(tmp_path, str(project))
    original = json.loads(cfg.read_text())
    assert sorted(wrap_config(cfg, cwd=project)) == ["fetch", "filesystem"]
    data = json.loads(cfg.read_text())
    fs = data["projects"][str(project)]["mcpServers"]["filesystem"]
    assert is_wrapped(fs["command"], fs["args"]) and fs["type"] == "stdio"
    assert data["numStartups"] == 12 and data["projects"][str(project)]["allowedTools"] == []
    assert data["projects"]["C:/Users/Neo/other"] == original["projects"]["C:/Users/Neo/other"]
    assert sorted(unwrap_config(cfg, cwd=project)) == ["fetch", "filesystem"]
    assert json.loads(cfg.read_text()) == original


def test_session_alive() -> None:
    from kairoseki.session_id import client_session_id, session_alive

    assert session_alive(client_session_id()) is True  # our own client (the test runner's parent) is alive
    assert session_alive("proc-999999999-1") is False
    assert session_alive("lab-abc123") is None


def test_wrap_prints_a_protection_summary_and_status_lists_it(tmp_path: Path) -> None:
    import os

    home = tmp_path / "home"
    home.mkdir()
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},
                    "remote": {"url": "https://mcp.example.com/mcp"},
                }
            }
        )
    )
    # APPDATA too: on Windows the Claude Desktop config lives there, not under the home dir
    env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home), "APPDATA": str(home), "COLUMNS": "200"}
    before = subprocess.run(kairoseki_argv("status"), capture_output=True, encoding="utf-8", cwd=tmp_path, env=env)
    assert "not protected" in before.stdout and "0 protected, 1 not protected" in before.stdout
    assert "project" in before.stdout  # .mcp.json is Claude Code's project scope
    wrapped = subprocess.run(kairoseki_argv("wrap"), capture_output=True, encoding="utf-8", cwd=tmp_path, env=env)
    assert "1 protected, 0 not protected" in wrapped.stdout, wrapped.stdout
    assert "wrap --remote" in wrapped.stdout
    after = subprocess.run(kairoseki_argv("status"), capture_output=True, encoding="utf-8", cwd=tmp_path, env=env)
    assert "1 protected." in after.stdout


def test_wrap_remote_bridges_through_mcp_remote_and_undo_restores(tmp_path: Path) -> None:
    from kairoseki.configs import read_servers, unwrap_config, wrap_config

    original = {
        "figma": {"type": "http", "url": "https://mcp.figma.com/mcp", "headers": {"X-Key": "abc"}},
        "legacy": {"type": "sse", "url": "https://old.example.com/sse"},
        "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},
    }
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps({"mcpServers": original}))
    assert wrap_config(path, cwd=tmp_path) == ["fetch"]  # remote servers need an explicit --remote
    assert sorted(wrap_config(path, cwd=tmp_path, remote=True)) == ["figma", "legacy"]
    figma = json.loads(path.read_text())["mcpServers"]["figma"]
    assert figma["args"][-4:] == ["mcp-remote", "https://mcp.figma.com/mcp", "--header", "X-Key:abc"]
    assert "url" not in figma and figma["type"] == "stdio"
    assert all(e.wrapped for e in read_servers(path, cwd=tmp_path))
    assert sorted(unwrap_config(path, cwd=tmp_path)) == ["fetch", "figma", "legacy"]
    assert json.loads(path.read_text())["mcpServers"] == original


def test_local_servers_of_the_enclosing_git_root_are_found() -> None:
    from kairoseki.configs import current_project

    projects = ["C:/Users/Neo", "C:/Users/Neo/work/app", "C:/Users/Neo/work/app-old"]
    # a session started in a subfolder uses the deepest project that contains it
    assert current_project(projects, r"c:\users\neo\work\app\src") == "C:/Users/Neo/work/app"
    assert current_project(projects, r"C:\Users\Neo\Documents\other") == "C:/Users/Neo"
    assert current_project(projects, "C:/Users/Neo/work/app-older") == "C:/Users/Neo"  # not a prefix match
    assert current_project(["/home/neo/proj"], "/srv/elsewhere") is None
