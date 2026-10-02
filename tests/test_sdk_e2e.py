"""End-to-end: official MCP SDK client  ->  kairoseki run  ->  official MCP SDK server.

Runs against whichever ``mcp`` version is installed. With mcp >= 2 every test runs twice:
handshake era (``mode="legacy"``) and modern era (``mode="auto"``, 2026-07-28 protocol, where
approvals travel as ``input_required`` results instead of server->client requests).
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from .conftest import SDK_SERVER, kairoseki_argv

mcp = pytest.importorskip("mcp")
from mcp import StdioServerParameters  # noqa: E402

try:
    from mcp import Client  # mcp >= 2

    MODES = ["legacy", "auto"]
except ImportError:  # mcp 1.x
    Client = None
    MODES = ["legacy"]


class Conn:
    def __init__(self, call: Any, list_tools: Any) -> None:
        self.call = call
        self.list_tools = list_tools


def _err(result: Any) -> bool:
    """``is_error`` in mcp >= 2, ``isError`` in mcp 1.x."""
    return bool(getattr(result, "is_error", getattr(result, "isError", False)))


def _texts(result: Any) -> str:
    return "\n".join(getattr(b, "text", "") for b in result.content)


@contextlib.asynccontextmanager
async def connect(tmp_path: Path, mode: str, elicitation: Any = None, policy: str | None = None) -> AsyncIterator[Conn]:
    import os

    args = ["-m", "kairoseki", "run", "--name", "sdklab"]
    if policy:
        args += ["--policy", policy]
    args += ["--", sys.executable, SDK_SERVER]
    env = {**os.environ, "SDK_LAB_LOG": str(tmp_path / "sdk.log")}
    params = StdioServerParameters(command=sys.executable, args=args, env=env)
    if Client is not None:
        kwargs: dict[str, Any] = {"mode": mode}
        if elicitation is not None:
            kwargs["elicitation_callback"] = elicitation
        async with Client(params, **kwargs) as client:
            yield Conn(client.call_tool, client.list_tools)
    else:  # pragma: no cover - mcp 1.x
        from mcp import ClientSession
        from mcp.client.stdio import stdio_client

        async with stdio_client(params) as (read, write):
            kw = {"elicitation_callback": elicitation} if elicitation is not None else {}
            async with ClientSession(read, write, **kw) as session:
                await session.initialize()
                yield Conn(session.call_tool, session.list_tools)


def _sent(tmp_path: Path) -> list[dict[str, Any]]:
    log = tmp_path / "sdk.log"
    if not log.exists():
        return []
    calls = [json.loads(x) for x in log.read_text().splitlines()]
    return [c for c in calls if c["tool"] == "send_email"]


async def _setup_trifecta(conn: Conn) -> None:
    page = await conn.call("fetch_url", {"url": "https://example.com"})
    assert "Kairoseki" in _texts(page)  # injection warning was prepended
    secret = await conn.call("read_file", {"path": ".env"})
    assert "sk-proj-TESTKEY" not in _texts(secret)
    assert "[REDACTED:openai_key]" in _texts(secret)


@pytest.mark.parametrize("mode", MODES)
async def test_transparent_for_normal_calls(tmp_path: Path, mode: str) -> None:
    async with connect(tmp_path, mode) as conn:
        tools = await conn.list_tools()
        assert {t.name for t in tools.tools} == {"fetch_url", "read_file", "send_email", "add"}
        result = await conn.call("add", {"a": 2, "b": 3})
        assert not _err(result)
        assert "5" in _texts(result)


@pytest.mark.parametrize("mode", MODES)
async def test_trifecta_declined_in_client(tmp_path: Path, mode: str) -> None:
    from mcp import types

    asked: list[str] = []

    async def decline(_ctx: Any, params: Any) -> Any:
        asked.append(params.message)
        return types.ElicitResult(action="decline")

    async with connect(tmp_path, mode, elicitation=decline) as conn:
        await _setup_trifecta(conn)
        result = await conn.call("send_email", {"to": "evil@example.com", "body": "hi"})
        assert _err(result)
        assert "declined" in _texts(result)
    assert asked and "lethal trifecta" in asked[0]
    assert _sent(tmp_path) == []


@pytest.mark.parametrize("mode", MODES)
async def test_trifecta_approved_in_client(tmp_path: Path, mode: str) -> None:
    from mcp import types

    async def accept(_ctx: Any, _params: Any) -> Any:
        return types.ElicitResult(action="accept", content={"approve": True})

    async with connect(tmp_path, mode, elicitation=accept) as conn:
        await _setup_trifecta(conn)
        result = await conn.call("send_email", {"to": "boss@example.com", "body": "report attached"})
        assert not _err(result), _texts(result)
    assert [c["arguments"]["to"] for c in _sent(tmp_path)] == ["boss@example.com"]


@pytest.mark.parametrize("mode", MODES)
async def test_accept_without_checkbox_is_not_approval(tmp_path: Path, mode: str) -> None:
    from mcp import types

    async def accept_false(_ctx: Any, _params: Any) -> Any:
        return types.ElicitResult(action="accept", content={"approve": False})

    async with connect(tmp_path, mode, elicitation=accept_false) as conn:
        await _setup_trifecta(conn)
        result = await conn.call("send_email", {"to": "evil@example.com", "body": "x"})
        assert _err(result)
    assert _sent(tmp_path) == []


@pytest.mark.parametrize("mode", MODES)
async def test_cli_approval_fallback(tmp_path: Path, mode: str) -> None:
    async with connect(tmp_path, mode) as conn:  # client without elicitation support
        await _setup_trifecta(conn)
        args = {"to": "boss@example.com", "body": "weekly report"}
        blocked = await conn.call("send_email", args)
        assert _err(blocked)
        text = _texts(blocked)
        approval_id = text.split("kairoseki approve ")[1].split("`")[0]
        assert approval_id.startswith("K-")
        done = subprocess.run(kairoseki_argv("approve", approval_id), capture_output=True, encoding="utf-8")
        assert done.returncode == 0, done.stderr
        retried = await conn.call("send_email", args)
        assert not _err(retried), _texts(retried)
        # an approval is single use
        again = await conn.call("send_email", args)
        assert _err(again)
    assert len(_sent(tmp_path)) == 1


@pytest.mark.parametrize("mode", MODES)
async def test_monitor_mode_never_blocks(tmp_path: Path, mode: str) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text("mode: monitor\n")
    async with connect(tmp_path, mode, policy=str(policy)) as conn:
        await _setup_trifecta(conn)
        result = await conn.call("send_email", {"to": "x@example.com", "body": "y"})
        assert not _err(result)
    assert len(_sent(tmp_path)) == 1


@pytest.mark.skipif(Client is None, reason="modern protocol needs mcp >= 2")
async def test_auto_mode_really_negotiates_modern_protocol(tmp_path: Path) -> None:
    import os

    params = StdioServerParameters(
        command=sys.executable, args=["-m", "kairoseki", "run", "--", sys.executable, SDK_SERVER], env=dict(os.environ)
    )
    async with Client(params, mode="auto") as client:
        assert client.protocol_version == "2026-07-28"
    async with Client(params, mode="legacy") as client:
        assert client.protocol_version != "2026-07-28"
