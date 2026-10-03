"""Build the public MCP Risk Index: scan servers from the official MCP registry, publish JSON + a static page.

    uv run python scripts/index/build.py --out site --limit 300 --previous https://anthonyriverai.github.io/kairoseki/index.json

For every server's latest version with an npm or PyPI stdio package that needs no credentials, the
script starts it (``npx -y pkg@version`` / ``uvx pkg==version``), lists its tools, labels them by
lethal-trifecta leg, flags poisoned descriptions, and diffs tool definitions against the previous
index to surface silent changes (rug pulls). Remote servers are skipped for now (most need OAuth).

It runs third-party code: run it only somewhere disposable without secrets, like a CI job with
read-only permissions.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from kairoseki import __version__
from kairoseki.client import StdioClient
from kairoseki.detect import find_injection, is_poisoned_definition, sanitize
from kairoseki.labels import PRIVATE, SINK, UNTRUSTED, classify
from kairoseki.proxy import CAPS_META_KEY, VERSION_META_KEY
from kairoseki.store import tool_digest

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
SITE = Path(__file__).parent / "site"


def _get_json(url: str) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": f"kairoseki-index/{__version__}"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # fixed https URLs
        return json.load(resp)


def registry_servers(limit: int) -> list[dict[str, Any]]:
    """Latest version of each registry server, up to ``limit``."""
    out: list[dict[str, Any]] = []
    cursor = ""
    while len(out) < limit:
        page = _get_json(f"{REGISTRY}?limit=100&version=latest" + (f"&cursor={cursor}" if cursor else ""))
        out += [item["server"] for item in page.get("servers", []) if "server" in item]
        cursor = (page.get("metadata") or {}).get("nextCursor") or ""
        if not cursor:
            break
    return out[:limit]


def launch_command(server: dict[str, Any]) -> list[str] | None:
    """A command starting the server without credentials, or None if it can't be scanned unattended."""
    for pkg in server.get("packages") or []:
        if (pkg.get("transport") or {}).get("type") != "stdio":
            continue
        if any(v.get("isRequired") for v in pkg.get("environmentVariables") or []):
            continue  # needs an API key
        if any(a.get("isRequired") for a in pkg.get("packageArguments") or []):
            continue
        ident, version = pkg.get("identifier"), pkg.get("version")
        if not ident or not version:
            continue
        if pkg.get("registryType") == "npm":
            return ["npx", "-y", f"{ident}@{version}"]
        if pkg.get("registryType") == "pypi":
            return ["uvx", f"{ident}=={version}"]
    return None


def remote_url(server: dict[str, Any]) -> str | None:
    for remote in server.get("remotes") or []:
        needs_header = any(h.get("isRequired") for h in remote.get("headers") or [])
        if (
            remote.get("type") == "streamable-http"
            and str(remote.get("url", "")).startswith("https://")
            and not needs_header
        ):
            return str(remote["url"])
    return None


HANDSHAKE_ERA, MODERN_ERA = "2025-06-18", "2026-07-28"


def http_list_tools(url: str, timeout: float) -> list[dict[str, Any]]:
    """tools/list over Streamable HTTP, without auth, in either protocol era. PermissionError on 401/403."""
    session: dict[str, str] = {"MCP-Protocol-Version": HANDSHAKE_ERA}

    def rpc(method: str, params: dict[str, Any], msg_id: int | None) -> dict[str, Any] | None:
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": params}
        if msg_id is not None:
            body["id"] = msg_id
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": f"kairoseki-index/{__version__}",
            **session,
        }
        if session["MCP-Protocol-Version"] == MODERN_ERA:
            headers["Mcp-Method"] = method  # 2026-07-28: must match the body, so gateways can route without parsing it
        req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
        try:
            resp = urllib.request.urlopen(req, timeout=timeout)  # registry https URL
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise PermissionError("needs auth") from e
            if e.code == 400 and "json" in (e.headers.get("Content-Type") or ""):
                return dict(json.loads(e.read()))  # a JSON-RPC error, e.g. an unsupported protocol version
            raise
        with resp:
            if resp.headers.get("Mcp-Session-Id"):
                session["Mcp-Session-Id"] = resp.headers["Mcp-Session-Id"]
            if msg_id is None:
                return None
            raw = resp.read().decode("utf-8", "replace")
        if "text/event-stream" in (resp.headers.get("Content-Type") or ""):
            for line in raw.splitlines():
                if line.startswith("data:"):
                    msg = json.loads(line[5:])
                    if msg.get("id") == msg_id:
                        return dict(msg)
            raise ValueError("no response in event stream")
        return dict(json.loads(raw))

    init = {
        "protocolVersion": HANDSHAKE_ERA,
        "capabilities": {},
        "clientInfo": {"name": "kairoseki-index", "version": __version__},
    }
    reply = rpc("initialize", init, 1) or {}
    meta: dict[str, Any] = {}
    supported = ((reply.get("error") or {}).get("data") or {}).get("supported") or []
    if MODERN_ERA in supported:
        # 2026-07-28 servers have no handshake: every request carries its protocol version in _meta
        session["MCP-Protocol-Version"] = MODERN_ERA
        meta = {"_meta": {VERSION_META_KEY: MODERN_ERA, CAPS_META_KEY: {}}}
    elif "error" in reply:
        raise ValueError(str(reply["error"])[:200])
    else:
        rpc("notifications/initialized", {}, None)
    tools: list[dict[str, Any]] = []
    cursor: str | None = None
    for page in range(2, 12):
        reply = rpc("tools/list", {**meta, **({"cursor": cursor} if cursor else {})}, page) or {}
        if "error" in reply:
            raise ValueError(str(reply["error"])[:200])
        result = reply.get("result") or {}
        tools += result.get("tools") or []
        cursor = result.get("nextCursor")
        if not cursor:
            break
    return tools


def analyze(name: str, tools: list[dict[str, Any]]) -> dict[str, Any]:
    legs: dict[str, list[str]] = {PRIVATE: [], UNTRUSTED: [], SINK: []}
    poisoned: dict[str, list[str]] = {}
    rows = []
    for tool in tools:
        tool_name = str(tool.get("name"))
        labels = classify(tool, server=name.rsplit("/", 1)[-1])
        texts = [str(tool.get("description") or ""), json.dumps(tool.get("inputSchema") or {})]
        hits = sorted(
            {h for t in texts for h in find_injection(t)}
            | ({"hidden_unicode"} if any(sanitize(t).hidden for t in texts) else set())
        )
        if is_poisoned_definition(hits):
            poisoned[tool_name] = hits
        for leg in legs:
            if leg in labels:
                legs[leg].append(tool_name)
        rows.append({"name": tool_name, "labels": sorted(labels), "digest": tool_digest(tool)})
    return {"tools": rows, "legs": legs, "poisoned": poisoned, "trifecta": all(legs.values())}


def scan(server: dict[str, Any], timeout: float) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "name": server.get("name"),
        "title": server.get("title") or "",
        "description": (server.get("description") or "")[:300],
        "version": server.get("version"),
        "repository": (server.get("repository") or {}).get("url", ""),
    }
    command, url = launch_command(server), remote_url(server)
    try:
        if command is not None:
            entry["command"] = " ".join(command)
            with StdioClient(command, env={}, timeout=timeout) as client:
                client.initialize()
                tools = client.list_tools()
        elif url is not None:
            entry["remote"] = url
            tools = http_list_tools(url, timeout)
        else:
            return {**entry, "status": "skipped", "reason": "needs credentials to start"}
    except PermissionError:
        return {**entry, "status": "skipped", "reason": "remote server that needs auth"}
    except Exception as e:
        return {**entry, "status": "error", "reason": str(e)[:200]}
    return {**entry, "status": "ok", **analyze(str(server.get("name")), tools)}


def diff_previous(entries: list[dict[str, Any]], previous: dict[str, Any] | None) -> None:
    """Mark tools whose definition changed since the last index. Same version + changed = possible rug pull."""
    if not previous:
        return
    before = {e["name"]: e for e in previous.get("servers", []) if e.get("status") == "ok"}
    for entry in entries:
        old = before.get(entry["name"])
        if entry.get("status") != "ok" or old is None:
            continue
        old_digests = {t["name"]: t["digest"] for t in old.get("tools", [])}
        changed = [
            t["name"] for t in entry["tools"] if t["name"] in old_digests and old_digests[t["name"]] != t["digest"]
        ]
        if changed:
            entry["changed"] = changed
            entry["rug_pull"] = old.get("version") == entry.get("version")


def build(out: Path, limit: int, workers: int, timeout: float, previous_url: str | None) -> dict[str, Any]:
    servers = registry_servers(limit)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        entries = list(pool.map(lambda s: scan(s, timeout), servers))
    previous = None
    if previous_url:
        try:
            previous = _get_json(previous_url)
        except (OSError, ValueError):
            previous = None
    diff_previous(entries, previous)
    ok = [e for e in entries if e["status"] == "ok"]
    index = {
        "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "kairoseki": __version__,
        "summary": {
            "listed": len(entries),
            "scanned": len(ok),
            "trifecta": sum(e["trifecta"] for e in ok),
            "poisoned": sum(bool(e["poisoned"]) for e in ok),
            "changed": sum(bool(e.get("changed")) for e in ok),
            "rug_pulls": sum(bool(e.get("rug_pull")) for e in ok),
        },
        "servers": sorted(
            entries,
            key=lambda e: (e["status"] != "ok", -len(e.get("poisoned") or {}), not e.get("trifecta"), e["name"] or ""),
        ),
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / "index.json").write_text(json.dumps(index, indent=1), encoding="utf-8")
    for page in SITE.iterdir():  # index.html, the video player, posters
        shutil.copy2(page, out / page.name)
    return index


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--out", default="site")
    p.add_argument("--limit", type=int, default=300)
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--timeout", type=float, default=60.0)
    p.add_argument("--previous", help="URL of the previous index.json, to detect changed tool definitions")
    a = p.parse_args(argv)
    index = build(Path(a.out), a.limit, a.workers, a.timeout, a.previous)
    print(json.dumps(index["summary"]), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
