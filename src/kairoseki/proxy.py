"""The stdio proxy: ``client <-> kairoseki <-> real MCP server``.

Kairoseki speaks raw JSON-RPC instead of depending on an MCP SDK, so it stays transparent to
every protocol feature it does not inspect (prompts, sampling, tasks, extensions) and works
with both protocol eras:

* handshake era (``initialize``; 2024-11-05 ... 2025-11-25)
* modern era (``server/discover`` + per-request ``_meta``; 2026-07-28)

Only these messages are inspected or rewritten:

* ``tools/list`` results  -> pin definitions, strip hidden text, neutralize poisoned tools
* ``tools/call`` requests -> allow / ask / deny
* ``tools/call`` and ``resources/read`` results -> sanitize, redact, update session taint
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import itertools
import json
import os
import secrets
import shutil
import sys
import threading
import time
from collections.abc import Callable
from typing import Any

from .engine import ALLOW, ASK, DENY, Decision, Engine
from .store import args_digest

APPROVAL_KEY = "kairoseki_approval"
STATE_PREFIX = "kairoseki:"
CAPS_META_KEY = "io.modelcontextprotocol/clientCapabilities"
VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion"
_LINE_LIMIT = 256 * 1024 * 1024


def _approval_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "approve": {
                "type": "boolean",
                "title": "Allow this call once",
                "description": "Only approve if you asked the agent to do exactly this.",
                "default": False,
            }
        },
        "required": ["approve"],
    }


class Proxy:
    def __init__(
        self,
        engine: Engine,
        command: list[str],
        write_client: Callable[[bytes], None] | None = None,
        verbose: bool = False,
    ) -> None:
        self.engine = engine
        self.command = command
        self.verbose = verbose
        self._write_client_raw = write_client or _stdout_writer()
        self._child: asyncio.subprocess.Process | None = None
        self._pending: dict[str, tuple[str, Any]] = {}  # request id -> (method, info)
        self._own_requests: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._ids = itertools.count(1)
        self._legacy_elicitation = False
        self._hmac_key = secrets.token_bytes(32)
        self._tasks: set[asyncio.Task[Any]] = set()

    # ------------------------------------------------------------------ io
    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"kairoseki[{self.engine.server}]: {msg}", file=sys.stderr, flush=True)

    def send_client(self, msg: Any) -> None:
        self._write_client_raw((json.dumps(msg, separators=(",", ":"), ensure_ascii=False) + "\n").encode())

    async def send_server(self, msg: Any) -> None:
        assert self._child is not None and self._child.stdin is not None
        self._child.stdin.write((json.dumps(msg, separators=(",", ":"), ensure_ascii=False) + "\n").encode())
        with contextlib.suppress(ConnectionError):
            await self._child.stdin.drain()

    # ------------------------------------------------------------------ main loop
    async def run(self, client_lines: asyncio.Queue[bytes | None]) -> int:
        self._child = await asyncio.create_subprocess_exec(
            *resolve_command(self.command),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            limit=_LINE_LIMIT,
        )
        server_task = asyncio.create_task(self._pump_server())
        client_task = asyncio.create_task(self._pump_client(client_lines))
        done, _ = await asyncio.wait({server_task, client_task}, return_when=asyncio.FIRST_COMPLETED)
        if client_task in done:
            # client went away: let the server finish in-flight work, then stop it
            if self._child.stdin is not None:
                with contextlib.suppress(Exception):
                    self._child.stdin.close()
            try:
                await asyncio.wait_for(server_task, timeout=5)
            except asyncio.TimeoutError:
                server_task.cancel()
        else:
            client_task.cancel()
        for task in list(self._tasks):
            task.cancel()
        try:
            return await asyncio.wait_for(self._child.wait(), timeout=5)
        except asyncio.TimeoutError:
            self._child.terminate()
            return await self._child.wait()

    async def _pump_client(self, lines: asyncio.Queue[bytes | None]) -> None:
        while True:
            line = await lines.get()
            if line is None:
                return
            await self._from_client(line)

    async def _pump_server(self) -> None:
        assert self._child is not None and self._child.stdout is not None
        while True:
            line = await self._child.stdout.readline()
            if not line:
                return
            await self._from_server(line)

    # ------------------------------------------------------------------ client -> server
    async def _from_client(self, line: bytes) -> None:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            assert self._child is not None and self._child.stdin is not None
            self._child.stdin.write(line if line.endswith(b"\n") else line + b"\n")
            return
        for item in msg if isinstance(msg, list) else [msg]:
            await self._client_message(item)

    async def _client_message(self, msg: Any) -> None:
        if not isinstance(msg, dict):
            await self.send_server(msg)
            return
        method = msg.get("method")
        msg_id = msg.get("id")
        if method is None and msg_id is not None and str(msg_id).startswith("kairoseki-"):
            fut = self._own_requests.pop(str(msg_id), None)
            if fut is not None and not fut.done():
                fut.set_result(msg)
            return
        if method == "initialize":
            caps = (msg.get("params") or {}).get("capabilities") or {}
            self._legacy_elicitation = "elicitation" in caps
        if method == "tools/call" and msg_id is not None:
            # approvals may wait on the user, so never block the pump
            task = asyncio.create_task(self._handle_call(msg))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
            return
        if msg_id is not None and method in ("tools/list", "resources/read"):
            self._pending[_key(msg_id)] = (method, (msg.get("params") or {}).get("uri"))
        await self.send_server(msg)

    async def _handle_call(self, msg: dict[str, Any]) -> None:
        params = dict(msg.get("params") or {})
        tool = str(params.get("name", ""))
        arguments = params.get("arguments") or {}
        modern = VERSION_META_KEY in (params.get("_meta") or {})

        # retry carrying an answer to our own approval prompt (modern era, SEP-2322)
        state = params.get("requestState")
        if isinstance(state, str) and state.startswith(STATE_PREFIX):
            responses = dict(params.get("inputResponses") or {})
            answer = responses.pop(APPROVAL_KEY, None)
            if not self._verify_state(state, tool, arguments):
                self._reply_error_result(msg, "🪨 Kairoseki: invalid or expired approval state.", modern)
                return
            if not _approved(answer):
                self.engine._log("declined", tool=tool, via="elicitation")
                self._reply_error_result(msg, f"🪨 Kairoseki: the user declined '{tool}'.", modern)
                return
            # the approval only overrides an "ask"; anything that is now a hard deny stays denied
            recheck = self.engine.decide(tool, arguments)
            if recheck.action == DENY:
                self._reply_error_result(msg, self.engine.deny_text(tool, recheck), modern)
                return
            self.engine._log("approved", tool=tool, via="elicitation")
            params.pop("requestState", None)
            if responses:
                params["inputResponses"] = responses
            else:
                params.pop("inputResponses", None)
            await self._forward_call({**msg, "params": params}, tool, arguments)
            return

        decision = self.engine.decide(tool, arguments)
        if decision.action == ALLOW:
            await self._forward_call(msg, tool, arguments)
            return
        if decision.action == ASK:
            if self.engine.consume_approval(tool, arguments):
                await self._forward_call(msg, tool, arguments)
                return
            caps = (params.get("_meta") or {}).get(CAPS_META_KEY) or {}
            if modern and "elicitation" in caps:
                self._reply_input_required(msg, tool, arguments, decision)
                return
            if not modern and self._legacy_elicitation:
                if await self._legacy_ask(tool, decision):
                    self.engine._log("approved", tool=tool, via="elicitation")
                    await self._forward_call(msg, tool, arguments)
                else:
                    self.engine._log("declined", tool=tool, via="elicitation")
                    self._reply_error_result(msg, f"🪨 Kairoseki: the user declined '{tool}'.", modern)
                return
            approval_id = self.engine.approvals.request(self.engine.server, tool, arguments, decision.reasons)
            self._reply_error_result(msg, self.engine.deny_text(tool, decision, approval_id), modern)
            return
        self._reply_error_result(msg, self.engine.deny_text(tool, decision), modern)

    async def _forward_call(self, msg: dict[str, Any], tool: str, arguments: Any) -> None:
        self._pending[_key(msg["id"])] = ("tools/call", tool)
        await self.send_server(msg)

    def _reply_error_result(self, msg: dict[str, Any], text: str, modern: bool) -> None:
        result: dict[str, Any] = {"content": [{"type": "text", "text": text}], "isError": True}
        if modern:
            result["resultType"] = "complete"
        self.send_client({"jsonrpc": "2.0", "id": msg["id"], "result": result})

    # ------------------------------------------------------------------ approvals
    def _prompt(self, tool: str, decision: Decision) -> str:
        reasons = "; ".join(decision.reasons)
        return f"🪨 Kairoseki: allow '{tool}' on '{self.engine.server}'? Reason: {reasons}"

    def _make_state(self, tool: str, arguments: Any) -> str:
        body = json.dumps({"k": args_digest(tool, arguments), "exp": time.time() + self.engine.policy.approval_ttl})
        b = base64.urlsafe_b64encode(body.encode()).decode()
        sig = hmac.new(self._hmac_key, b.encode(), hashlib.sha256).hexdigest()
        return f"{STATE_PREFIX}{b}.{sig}"

    def _verify_state(self, state: str, tool: str, arguments: Any) -> bool:
        try:
            b, sig = state[len(STATE_PREFIX) :].rsplit(".", 1)
            good = hmac.new(self._hmac_key, b.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, good):
                return False
            body = json.loads(base64.urlsafe_b64decode(b.encode()))
            return body["k"] == args_digest(tool, arguments) and time.time() < float(body["exp"])
        except (ValueError, KeyError, json.JSONDecodeError):
            return False

    def _reply_input_required(self, msg: dict[str, Any], tool: str, arguments: Any, decision: Decision) -> None:
        self.send_client(
            {
                "jsonrpc": "2.0",
                "id": msg["id"],
                "result": {
                    "resultType": "input_required",
                    "inputRequests": {
                        APPROVAL_KEY: {
                            "method": "elicitation/create",
                            "params": {
                                "mode": "form",
                                "message": self._prompt(tool, decision),
                                "requestedSchema": _approval_schema(),
                            },
                        }
                    },
                    "requestState": self._make_state(tool, arguments),
                },
            }
        )

    async def _legacy_ask(self, tool: str, decision: Decision) -> bool:
        req_id = f"kairoseki-{next(self._ids)}"
        fut: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._own_requests[req_id] = fut
        self.send_client(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "elicitation/create",
                "params": {"message": self._prompt(tool, decision), "requestedSchema": _approval_schema()},
            }
        )
        try:
            reply = await asyncio.wait_for(fut, timeout=self.engine.policy.approval_timeout)
        except asyncio.TimeoutError:
            self._own_requests.pop(req_id, None)
            return False
        return _approved(reply.get("result"))

    # ------------------------------------------------------------------ server -> client
    async def _from_server(self, line: bytes) -> None:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            self._write_client_raw(line if line.endswith(b"\n") else line + b"\n")
            return
        if isinstance(msg, list):
            self.send_client([self._server_message(m) for m in msg])
        else:
            self.send_client(self._server_message(msg))

    def _server_message(self, msg: Any) -> Any:
        if not isinstance(msg, dict) or "method" in msg or "id" not in msg:
            return msg  # notifications and server->client requests pass through
        pending = self._pending.pop(_key(msg["id"]), None)
        result = msg.get("result")
        if pending is None or not isinstance(result, dict) or result.get("resultType") == "input_required":
            return msg
        method, info = pending
        try:
            if method == "tools/list":
                result = self.engine.on_tools_list(result)
            elif method == "tools/call":
                result = self.engine.on_tool_result(str(info), result)
            elif method == "resources/read":
                result = self.engine.on_resource_result(str(info), result)
        except Exception as e:  # never let an inspection bug crash the user's agent
            self._log(f"inspection error on {method}: {e!r}")
            self.engine._log("internal_error", method=method, error=repr(e))
            if method == "tools/call":
                result = {
                    "content": [
                        {"type": "text", "text": "🪨 Kairoseki could not inspect this tool output, so it was withheld."}
                    ],
                    "isError": True,
                }
        return {**msg, "result": result}


def resolve_command(argv: list[str]) -> list[str]:
    """Resolve the executable on PATH (finds ``npx.cmd`` / ``uvx.exe`` on Windows)."""
    found = shutil.which(argv[0])
    return [found, *argv[1:]] if found else argv


def _key(msg_id: Any) -> str:
    return json.dumps(msg_id)


def _approved(answer: Any) -> bool:
    return (
        isinstance(answer, dict)
        and answer.get("action") == "accept"
        and isinstance(answer.get("content"), dict)
        and answer["content"].get("approve") is True
    )


def _stdout_writer() -> Callable[[bytes], None]:
    lock = threading.Lock()
    out = sys.stdout.buffer

    def write(data: bytes) -> None:
        with lock:
            out.write(data)
            out.flush()

    return write


def stdin_queue(loop: asyncio.AbstractEventLoop) -> asyncio.Queue[bytes | None]:
    """Read stdin in a thread (portable across Windows and POSIX) into an asyncio queue."""
    queue: asyncio.Queue[bytes | None] = asyncio.Queue()
    stream = sys.stdin.buffer

    def reader() -> None:
        try:
            for line in iter(stream.readline, b""):
                loop.call_soon_threadsafe(queue.put_nowait, line)
        finally:
            loop.call_soon_threadsafe(queue.put_nowait, None)

    threading.Thread(target=reader, name="kairoseki-stdin", daemon=True).start()
    return queue


async def serve(engine: Engine, command: list[str], verbose: bool = False) -> int:
    loop = asyncio.get_running_loop()
    proxy = Proxy(engine, command, verbose=verbose)
    return await proxy.run(stdin_queue(loop))


def run_proxy(engine: Engine, command: list[str], verbose: bool = False) -> int:
    if os.name == "nt":  # subprocess pipes need the proactor loop on Windows
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())  # type: ignore[attr-defined]
    return asyncio.run(serve(engine, command, verbose))
