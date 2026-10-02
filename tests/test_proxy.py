"""Wire-level robustness of the stdio proxy, using raw JSON-RPC lines."""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

from .conftest import kairoseki_argv

ECHO_SERVER = textwrap.dedent(
    """
    import json, sys
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        if line == "CRASH":
            sys.exit(3)
        try:
            msg = json.loads(line)
        except ValueError:
            print(json.dumps({"echo_raw": line}), flush=True)
            continue
        if isinstance(msg, list):
            print(json.dumps([{"jsonrpc": "2.0", "id": m["id"], "result": {"n": i}} for i, m in enumerate(msg)]), flush=True)
            continue
        method, mid = msg.get("method"), msg.get("id")
        if method == "tools/list":
            tools = [{"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}}]
            print(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {"tools": tools}}), flush=True)
        elif method == "tools/call":
            size = msg["params"]["arguments"].get("size", 10)
            text = "x" * size + " ghp_" + "a" * 36
            print(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": text}]}}), flush=True)
            # a server->client notification and request pass through untouched
            print(json.dumps({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"p": 1}}), flush=True)
        elif method == "ping-server-request":
            print(json.dumps({"jsonrpc": "2.0", "id": "srv-1", "method": "roots/list"}), flush=True)
        elif mid is not None:
            print(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {"method": method, "params": msg.get("params")}}), flush=True)
        elif method == "client-response-check":
            pass
    """
)


def run_lines(tmp_path: Path, lines: list[str], timeout: float = 20) -> tuple[list[Any], int]:
    server = tmp_path / "echo.py"
    server.write_text(ECHO_SERVER)
    proc = subprocess.run(
        kairoseki_argv("run", "--name", "echo", "--", sys.executable, str(server)),
        input="\n".join(lines) + "\n",
        capture_output=True,
        encoding="utf-8",
        timeout=timeout,
    )
    out = []
    for line in proc.stdout.splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            out.append(line)
    return out, proc.returncode


def req(i: Any, method: str, params: dict[str, Any] | None = None) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params or {}})


def test_unknown_methods_pass_through_unchanged(tmp_path: Path) -> None:
    out, code = run_lines(
        tmp_path,
        [req(1, "prompts/get", {"name": "p", "arguments": {"a": "b"}}), req("abc", "some/extension", {"x": [1, 2]})],
    )
    assert code == 0
    assert out[0] == {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"method": "prompts/get", "params": {"name": "p", "arguments": {"a": "b"}}},
    }
    assert out[1]["id"] == "abc" and out[1]["result"]["params"] == {"x": [1, 2]}


def test_tool_results_are_redacted_and_notifications_pass(tmp_path: Path) -> None:
    out, _ = run_lines(tmp_path, [req(1, "tools/list"), req(2, "tools/call", {"name": "read_file", "arguments": {}})])
    call = next(m for m in out if isinstance(m, dict) and m.get("id") == 2)
    assert "ghp_" not in json.dumps(call)
    assert any(isinstance(m, dict) and m.get("method") == "notifications/progress" for m in out)


def test_large_messages(tmp_path: Path) -> None:
    out, _ = run_lines(
        tmp_path, [req(1, "tools/call", {"name": "read_file", "arguments": {"size": 5_000_000}})], timeout=60
    )
    call = next(m for m in out if isinstance(m, dict) and m.get("id") == 1)
    assert len(call["result"]["content"][0]["text"]) > 5_000_000


def test_malformed_lines_are_forwarded_not_fatal(tmp_path: Path) -> None:
    out, code = run_lines(tmp_path, ["this is not json", req(1, "ping")])
    assert code == 0
    assert {"echo_raw": "this is not json"} in out
    assert any(isinstance(m, dict) and m.get("id") == 1 for m in out)


def test_batches_are_supported(tmp_path: Path) -> None:
    batch = json.dumps([json.loads(req(1, "ping")), json.loads(req(2, "ping"))])
    out, _ = run_lines(tmp_path, [batch])
    ids = sorted(m["id"] for m in out if isinstance(m, dict) and "id" in m)
    assert ids == [1, 2]


def test_server_exit_code_is_propagated(tmp_path: Path) -> None:
    _, code = run_lines(tmp_path, ["CRASH"])
    assert code == 3


def test_server_requests_reach_the_client(tmp_path: Path) -> None:
    out, _ = run_lines(tmp_path, [json.dumps({"jsonrpc": "2.0", "method": "ping-server-request"})])
    assert {"jsonrpc": "2.0", "id": "srv-1", "method": "roots/list"} in out


def test_nothing_but_json_rpc_on_stdout(tmp_path: Path) -> None:
    out, _ = run_lines(tmp_path, [req(1, "tools/list")])
    assert all(isinstance(m, dict) for m in out)
