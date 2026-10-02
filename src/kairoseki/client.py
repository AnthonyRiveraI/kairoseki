"""A tiny synchronous MCP client over stdio, used by ``kairoseki scan`` and the attack lab.

It speaks the handshake-era protocol (``initialize``), which every server supports today.
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import threading
from typing import Any

CLIENT_VERSION = "2025-06-18"


class MCPError(RuntimeError):
    pass


class StdioClient:
    def __init__(
        self, command: list[str], env: dict[str, str] | None = None, cwd: str | None = None, timeout: float = 30.0
    ) -> None:
        self.timeout = timeout
        found = shutil.which(command[0])
        self.proc = subprocess.Popen(
            [found, *command[1:]] if found else command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, **(env or {})},
            cwd=cwd,
        )
        self._lines: queue.Queue[bytes | None] = queue.Queue()
        self._ids = 0
        self.stderr_lines: list[str] = []
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()
        self.server_info: dict[str, Any] = {}

    def _read_stdout(self) -> None:
        assert self.proc.stdout is not None
        for line in iter(self.proc.stdout.readline, b""):
            self._lines.put(line)
        self._lines.put(None)

    def _read_stderr(self) -> None:
        assert self.proc.stderr is not None
        for line in iter(self.proc.stderr.readline, b""):
            self.stderr_lines.append(line.decode(errors="replace").rstrip())

    def _send(self, msg: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        self.proc.stdin.flush()

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._ids += 1
        req_id = self._ids
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg)
        while True:
            try:
                line = self._lines.get(timeout=self.timeout)
            except queue.Empty:
                raise MCPError(f"timeout waiting for {method}") from None
            if line is None:
                err = "\n".join(self.stderr_lines[-5:])
                raise MCPError(f"server exited while waiting for {method}: {err}")
            try:
                reply = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "method" in reply:
                if "id" in reply:  # a server->client request we do not support
                    self._send(
                        {
                            "jsonrpc": "2.0",
                            "id": reply["id"],
                            "error": {"code": -32601, "message": "not supported by kairoseki client"},
                        }
                    )
                continue
            if reply.get("id") != req_id:
                continue
            if "error" in reply:
                raise MCPError(f"{method}: {reply['error'].get('message')}")
            return reply.get("result") or {}

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg)

    def initialize(self) -> dict[str, Any]:
        result = self.request(
            "initialize",
            {
                "protocolVersion": CLIENT_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "kairoseki", "version": "0"},
            },
        )
        self.server_info = result.get("serverInfo") or {}
        self.notify("notifications/initialized")
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cursor = None
        while True:
            result = self.request("tools/list", {"cursor": cursor} if cursor else {})
            tools += result.get("tools") or []
            cursor = result.get("nextCursor")
            if not cursor:
                return tools

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            self.proc.kill()
            self.proc.wait()

    def __enter__(self) -> StdioClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def result_text(result: dict[str, Any]) -> str:
    return "\n".join(str(block.get("text", "")) for block in result.get("content") or [] if isinstance(block, dict))
