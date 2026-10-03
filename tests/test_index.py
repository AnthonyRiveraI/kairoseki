"""The MCP Risk Index builder (scripts/index/build.py), without touching the network."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

from .conftest import ROOT

spec = importlib.util.spec_from_file_location("index_build", ROOT.parent / "scripts" / "index" / "build.py")
assert spec and spec.loader
build: Any = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


def test_launch_command_only_for_unattended_packages() -> None:
    npm = {"registryType": "npm", "identifier": "@acme/mcp", "version": "1.2.0", "transport": {"type": "stdio"}}
    assert build.launch_command({"packages": [npm]}) == ["npx", "-y", "@acme/mcp@1.2.0"]
    pypi = {**npm, "registryType": "pypi", "identifier": "acme-mcp"}
    assert build.launch_command({"packages": [pypi]}) == ["uvx", "acme-mcp==1.2.0"]
    keyed = {**npm, "environmentVariables": [{"name": "ACME_KEY", "isRequired": True}]}
    assert build.launch_command({"packages": [keyed]}) is None
    assert build.remote_url({"remotes": [{"type": "streamable-http", "url": "https://mcp.acme.dev"}]})
    assert build.remote_url({"remotes": [{"type": "sse", "url": "https://mcp.acme.dev/sse"}]}) is None


def test_scan_analyzes_a_real_stdio_server(monkeypatch: pytest.MonkeyPatch) -> None:
    server = {"name": "dev.kairoseki/lab-web", "version": "1"}
    monkeypatch.setattr(
        build, "launch_command", lambda s: [sys.executable, "-m", "kairoseki.lab.server", "--role", "web"]
    )
    entry = build.scan(server, timeout=30)
    assert entry["status"] == "ok" and entry["tools"]
    assert set(entry["legs"]) == {"private", "untrusted", "sink"}


def test_changed_definitions_and_rug_pulls() -> None:
    def server(version: str, digest: str) -> dict[str, Any]:
        return {"name": "a/b", "version": version, "status": "ok", "tools": [{"name": "t", "digest": digest}]}

    same = [server("1", "new")]
    build.diff_previous(same, {"servers": [server("1", "old")]})
    assert same[0]["changed"] == ["t"] and same[0]["rug_pull"] is True
    bumped = [server("2", "new")]
    build.diff_previous(bumped, {"servers": [server("1", "old")]})
    assert bumped[0]["rug_pull"] is False


def test_site_never_injects_server_text_as_html() -> None:
    html = (Path(build.SITE) / "index.html").read_text(encoding="utf-8")
    assert "innerHTML" not in html and "insertAdjacentHTML" not in html
