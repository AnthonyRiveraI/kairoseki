from __future__ import annotations

import json
import subprocess
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from kairoseki.denden import ask
from kairoseki.policy import DenDen, PolicyError, parse_policy
from kairoseki.store import Session

from .conftest import kairoseki_argv
from .test_proxy import ECHO_SERVER

CFG = DenDen(topic="kairoseki-test-topic-123", url="http://ntfy.invalid")


class FakeNtfy:
    """In-memory ntfy: published notifications, and what the phone 'taps' (a button index or a raw reply)."""

    def __init__(self, tap: int | str | None) -> None:
        self.tap, self.published, self.replies = tap, [], []  # type: ignore[var-annotated]

    def __call__(self, req: urllib.request.Request, timeout: float) -> bytes:
        if req.data:
            msg = json.loads(req.data)
            self.published.append(msg)
            if isinstance(self.tap, int):
                self.replies.append(msg["actions"][self.tap]["body"])
            elif isinstance(self.tap, str):
                self.replies.append(self.tap)
            return b"{}"
        return "\n".join(json.dumps({"message": r}) for r in self.replies).encode()


def run_ask(fake: Any) -> bool | None:
    return ask(
        CFG, "mail", "send_email", ["lethal trifecta"], "K-ABC123", timeout=0.05, fetch=fake, sleep=lambda _: None
    )


def test_phone_approves_and_denies() -> None:
    approve = FakeNtfy(tap=0)
    assert run_ask(approve) is True
    sent = approve.published[0]
    assert sent["topic"] == CFG.topic and "mail.send_email" in sent["title"]
    assert "arguments" not in json.dumps(sent)  # only server, tool and reason leave the machine
    assert run_ask(FakeNtfy(tap=1)) is False


def test_forged_or_replayed_answers_are_ignored() -> None:
    assert run_ask(FakeNtfy(tap="approve K-ABC123 guessed-nonce")) is None
    assert run_ask(FakeNtfy(tap="approve K-OTHER1 x")) is None
    assert run_ask(FakeNtfy(tap=None)) is None  # nobody answered before the timeout


def test_unreachable_ntfy_falls_back() -> None:
    def down(req: urllib.request.Request, timeout: float) -> bytes:
        raise OSError("network down")

    assert run_ask(down) is None


def test_policy_requires_a_random_topic() -> None:
    assert parse_policy({"denden": {"topic": "kairoseki-abcdefghijklmnop"}}).denden is not None
    with pytest.raises(PolicyError):
        parse_policy({"denden": {"topic": "short"}})
    with pytest.raises(PolicyError):
        parse_policy({"denden": {"topic": "kairoseki-REPLACE-WITH-RANDOM"}})


def test_proxy_rings_the_phone_and_forwards_an_approved_call(tmp_path: Path) -> None:
    replies: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            replies.append(msg["actions"][0]["body"])  # the user taps Approve right away
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()
            self.wfile.write("\n".join(json.dumps({"message": r}) for r in replies).encode())

        def log_message(self, *args: Any) -> None:
            pass

    ntfy = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=ntfy.serve_forever, daemon=True).start()
    policy = tmp_path / "kairoseki.yaml"
    policy.write_text(f"denden:\n  topic: kairoseki-test-topic-123\n  url: http://127.0.0.1:{ntfy.server_port}\n")

    session = Session()
    session.mark("untrusted", "web", "fetch")
    session.mark("private", "files", "read_file")
    server = tmp_path / "echo.py"
    server.write_text(ECHO_SERVER)
    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "send_email", "arguments": {}}}
    # keep stdin open like a real client: the approval is still in flight when the call is sent
    proc = subprocess.Popen(
        kairoseki_argv("run", "--name", "mail", "--policy", str(policy), "--", sys.executable, str(server)),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        encoding="utf-8",
    )
    try:
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write(json.dumps(call) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
    finally:
        proc.kill()
        ntfy.shutdown()
    result = json.loads(line)["result"]
    assert not result.get("isError"), result  # forwarded to the server after the phone said yes
    assert len(replies) == 1


def test_prefer_rings_the_phone_even_when_the_client_could_ask(tmp_path: Path) -> None:
    """With prefer: true the proxy asks the phone before an in-client prompt (unattended agents)."""
    replies: list[str] = []
    published: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            published.append(msg)
            replies.append(msg["actions"][0]["body"])
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()
            self.wfile.write("\n".join(json.dumps({"message": r}) for r in replies).encode())

        def log_message(self, *args: Any) -> None:
            pass

    ntfy = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=ntfy.serve_forever, daemon=True).start()
    policy = tmp_path / "kairoseki.yaml"
    policy.write_text(
        f"denden:\n  topic: kairoseki-test-topic-123\n  url: http://127.0.0.1:{ntfy.server_port}\n  prefer: true\n"
    )
    session = Session()
    session.mark("untrusted", "web", "fetch")
    session.mark("private", "files", "read_file")
    server = tmp_path / "echo.py"
    server.write_text(ECHO_SERVER)
    init = {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"capabilities": {"elicitation": {}}}}
    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "send_email", "arguments": {}}}
    proc = subprocess.Popen(
        kairoseki_argv("run", "--name", "mail", "--policy", str(policy), "--", sys.executable, str(server)),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        encoding="utf-8",
    )
    try:
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write(json.dumps(init) + "\n" + json.dumps(call) + "\n")
        proc.stdin.flush()
        lines = [json.loads(proc.stdout.readline()) for _ in range(2)]
    finally:
        proc.kill()
        ntfy.shutdown()
    call_reply = next(m for m in lines if m.get("id") == 1)
    assert not call_reply["result"].get("isError"), call_reply  # approved on the phone, forwarded
    assert not any(m.get("method") == "elicitation/create" for m in lines)  # the screen was never asked
    assert published and "send_email" in published[0]["title"]


def test_policy_parses_prefer() -> None:
    assert parse_policy({"denden": {"topic": "kairoseki-abcdefghijklmnop", "prefer": True}}).denden.prefer  # type: ignore[union-attr]
    assert not parse_policy({"denden": {"topic": "kairoseki-abcdefghijklmnop"}}).denden.prefer  # type: ignore[union-attr]
