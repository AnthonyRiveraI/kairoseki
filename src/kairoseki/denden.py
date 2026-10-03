"""Den Den Mushi: approve risky tool calls from your phone, through ntfy (https://ntfy.sh).

When a call needs approval and the client can't show a prompt, Kairoseki publishes a notification
with Approve / Deny buttons to ``<url>/<topic>``. Tapping a button makes the ntfy app publish
``approve <id> <nonce>`` to ``<topic>-reply``, which Kairoseki polls until the approval timeout.

* Only the server, tool and reason leave the machine, never the arguments.
* Answers must carry the approval id and a fresh random nonce, so a replayed or forged message
  for another call is ignored. Anyone who knows the topic can still answer: keep it random (and
  use a token on a self-hosted ntfy for more).
"""

from __future__ import annotations

import json
import secrets
import time
import urllib.request
from collections.abc import Callable
from typing import Any

from .policy import DenDen

Fetch = Callable[[urllib.request.Request, float], bytes]


def _fetch(req: urllib.request.Request, timeout: float) -> bytes:
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return bytes(resp.read())


def _request(cfg: DenDen, url: str, body: dict[str, Any] | None = None) -> urllib.request.Request:
    headers = {"Content-Type": "application/json"}
    if cfg.token:
        headers["Authorization"] = f"Bearer {cfg.token}"
    data = json.dumps(body).encode() if body is not None else None
    return urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")


def publish(
    cfg: DenDen, server: str, tool: str, reasons: list[str], approval_id: str, nonce: str, fetch: Fetch
) -> None:
    reply = f"{cfg.url}/{cfg.topic}-reply"
    message = {
        "topic": cfg.topic,
        "title": f"🪨 Kairoseki: allow {server}.{tool}?",
        "message": "; ".join(reasons)[:500] + f"\n\nOr from a terminal: kairoseki approve {approval_id}",
        "priority": 4,
        "tags": ["warning"],
        "actions": [
            {
                "action": "http",
                "label": "Approve",
                "url": reply,
                "method": "POST",
                "body": f"approve {approval_id} {nonce}",
                "clear": True,
            },
            {
                "action": "http",
                "label": "Deny",
                "url": reply,
                "method": "POST",
                "body": f"deny {approval_id} {nonce}",
                "clear": True,
            },
        ],
    }
    fetch(_request(cfg, cfg.url, message), 10)


def poll(cfg: DenDen, approval_id: str, nonce: str, since: int, fetch: Fetch) -> bool | None:
    """True/False once the phone answered this exact request, None if not yet."""
    raw = fetch(_request(cfg, f"{cfg.url}/{cfg.topic}-reply/json?poll=1&since={since}"), 10)
    for line in raw.decode("utf-8", "replace").splitlines():
        try:
            text = str(json.loads(line).get("message", "")).strip()
        except (ValueError, AttributeError):
            continue
        if text == f"approve {approval_id} {nonce}":
            return True
        if text == f"deny {approval_id} {nonce}":
            return False
    return None


def ask(
    cfg: DenDen,
    server: str,
    tool: str,
    reasons: list[str],
    approval_id: str,
    timeout: float,
    fetch: Fetch = _fetch,
    interval: float = 2.0,
    sleep: Callable[[float], None] = time.sleep,
) -> bool | None:
    """Ring the phone and wait. True = approved, False = denied, None = no answer or ntfy unreachable."""
    nonce = secrets.token_urlsafe(9)
    since = int(time.time()) - 5
    try:
        publish(cfg, server, tool, reasons, approval_id, nonce, fetch)
    except OSError:
        return None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            answer = poll(cfg, approval_id, nonce, since, fetch)
        except OSError:
            answer = None
        if answer is not None:
            return answer
        sleep(interval)
    return None
