"""On-disk state shared by every Kairoseki proxy of one agent session.

An agent usually talks to several MCP servers (fetch, filesystem, GitHub...). Each one is
wrapped by its own ``kairoseki run`` process, but the lethal trifecta spans servers: the
untrusted web page comes from one, the private file from another, the exfiltration happens
through a third. So taint lives in a small JSON file keyed by session, guarded by a lock
file, that all proxies of the same agent read and update.

The session key defaults to the parent process id (all servers of one Claude Code / Cursor
window are children of the same process) and can be forced with ``KAIROSEKI_SESSION``.

Secrets are never written to disk: only truncated SHA-256 hashes of them are stored.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import secrets
import time
import urllib.parse
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .policy import home_dir

SESSION_TTL = 12 * 3600
SHINGLE = 32  # chars copied verbatim from untrusted content that mark an argument as attacker-derived
_SHINGLE_STRIDE = 8
_MAX_SHINGLES = 60_000
_MAX_SOURCES = 50


def digest(value: str) -> str:
    """Short keyed-free fingerprint (80 bits). Only fingerprints of secrets ever touch disk."""
    return hashlib.blake2b(value.encode("utf-8", "surrogatepass"), digest_size=10).hexdigest()


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(path, 0o700)
    return path


@contextlib.contextmanager
def file_lock(path: Path, timeout: float = 5.0, stale: float = 10.0) -> Iterator[None]:
    """Portable lock using an exclusively created lock file (works on Linux, macOS, Windows)."""
    lock = path.with_suffix(path.suffix + ".lock")
    deadline = time.monotonic() + timeout
    while True:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            break
        except FileExistsError:
            with contextlib.suppress(OSError):
                if time.time() - lock.stat().st_mtime > stale:
                    lock.unlink()
                    continue
            if time.monotonic() > deadline:
                raise TimeoutError(f"could not acquire {lock}") from None
            time.sleep(0.005)
    try:
        yield
    finally:
        with contextlib.suppress(FileNotFoundError):
            lock.unlink()


def _atomic_write(path: Path, data: dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
    with contextlib.suppress(OSError):
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _read(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def default_session_id() -> str:
    env = os.environ.get("KAIROSEKI_SESSION")
    if env:
        return "".join(c for c in env if c.isalnum() or c in "-_")[:64] or "default"
    ppid = os.getppid()
    start = ""
    with contextlib.suppress(OSError, IndexError):
        # field 22 of /proc/<pid>/stat is the start time; guards against pid reuse on Linux
        stat = Path(f"/proc/{ppid}/stat").read_text()
        start = stat.rsplit(")", 1)[1].split()[19]
    return f"ppid-{ppid}" + (f"-{start}" if start else "")


def secret_variants(value: str) -> set[str]:
    """Encodings an agent might use to smuggle a secret out."""
    raw = value.encode()
    variants = {
        value,
        base64.b64encode(raw).decode().rstrip("="),
        base64.urlsafe_b64encode(raw).decode().rstrip("="),
        raw.hex(),
        urllib.parse.quote(value, safe=""),
        urllib.parse.quote_plus(value),
        value[::-1],
    }
    return {v for v in variants if len(v) >= 8}


class Session:
    """Taint shared across all proxies of one agent session."""

    def __init__(self, session_id: str | None = None, root: Path | None = None) -> None:
        self.id = session_id or default_session_id()
        self.path = _private_dir((root or home_dir()) / "sessions") / f"{self.id}.json"

    @contextlib.contextmanager
    def _update(self) -> Iterator[dict[str, Any]]:
        with file_lock(self.path):
            data = _read(self.path)
            now = time.time()
            if not data or now - data.get("updated", now) > SESSION_TTL:
                data = {"created": now, "untrusted": [], "private": [], "secrets": {}, "shingles": []}
            yield data
            data["updated"] = now
            _atomic_write(self.path, data)

    def snapshot(self) -> dict[str, Any]:
        data = _read(self.path)
        if data and time.time() - data.get("updated", 0) > SESSION_TTL:
            return {}
        return data

    # ------------------------------------------------------------------ writers
    def mark(self, label: str, server: str, tool: str, detail: str = "") -> None:
        with self._update() as data:
            sources = data.setdefault(label, [])
            sources.append({"server": server, "tool": tool, "detail": detail, "ts": time.time()})
            del sources[:-_MAX_SOURCES]

    def learn_secrets(self, values: list[str]) -> None:
        if not values:
            return
        with self._update() as data:
            table: dict[str, list[str]] = data.setdefault("secrets", {})
            for value in values:
                for v in secret_variants(value):
                    bucket = table.setdefault(str(len(v)), [])
                    h = digest(v)
                    if h not in bucket:
                        bucket.append(h)

    def learn_untrusted_text(self, text: str) -> None:
        self._learn_shingles("shingles", text)

    def learn_private_text(self, text: str) -> None:
        self._learn_shingles("private_shingles", text)

    def _learn_shingles(self, key: str, text: str) -> None:
        norm = " ".join(text.split()).lower()
        if len(norm) < SHINGLE:
            return
        new = {digest(norm[i : i + SHINGLE]) for i in range(0, len(norm) - SHINGLE + 1, _SHINGLE_STRIDE)}
        with self._update() as data:
            current = set(data.get(key, []))
            current |= new
            data[key] = list(current)[-_MAX_SHINGLES:]

    # ------------------------------------------------------------------ readers
    @staticmethod
    def leaked_secret(data: dict[str, Any], text: str) -> bool:
        """True if ``text`` contains a known secret (or an encoding of it)."""
        table: dict[str, list[str]] = data.get("secrets") or {}
        text = text[:200_000]
        for length_s, hashes in table.items():
            length = int(length_s)
            wanted = set(hashes)
            for i in range(0, len(text) - length + 1):
                if digest(text[i : i + length]) in wanted:
                    return True
        return False

    @staticmethod
    def untrusted_overlap(data: dict[str, Any], text: str) -> bool:
        """True if ``text`` copies a long run of characters from untrusted content."""
        return Session._overlap(data, "shingles", text)

    @staticmethod
    def private_overlap(data: dict[str, Any], text: str) -> bool:
        """True if ``text`` carries a long run of characters from private tool output."""
        return Session._overlap(data, "private_shingles", text)

    @staticmethod
    def _overlap(data: dict[str, Any], key: str, text: str) -> bool:
        shingles = set(data.get(key) or [])
        if not shingles:
            return False
        norm = " ".join(text.split()).lower()[:200_000]
        return any(digest(norm[i : i + SHINGLE]) in shingles for i in range(0, len(norm) - SHINGLE + 1))


# ---------------------------------------------------------------------------- pins


def tool_digest(tool: dict[str, Any]) -> str:
    material = {k: tool.get(k) for k in ("name", "description", "inputSchema", "annotations", "title")}
    return digest(json.dumps(material, sort_keys=True, default=str))


class PinStore:
    """Trust-on-first-use pins of tool definitions, per server (rug-pull defense)."""

    def __init__(self, server: str, root: Path | None = None) -> None:
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in server) or "server"
        self.path = _private_dir((root or home_dir()) / "pins") / f"{safe}.json"

    def check(self, tools: list[dict[str, Any]]) -> tuple[set[str], set[str]]:
        """Pin unseen tools; return (changed, new_since_first_pin) tool names."""
        with file_lock(self.path):
            data = _read(self.path)
            first_time = not data
            pinned: dict[str, str] = data.setdefault("pinned", {})
            pending: dict[str, str] = data.setdefault("pending", {})
            changed: set[str] = set()
            new: set[str] = set()
            for tool in tools:
                name = str(tool.get("name"))
                d = tool_digest(tool)
                if name not in pinned:
                    pinned[name] = d
                    if not first_time:
                        new.add(name)
                elif pinned[name] != d:
                    changed.add(name)
                    pending[name] = d
                else:
                    pending.pop(name, None)
            _atomic_write(self.path, data)
        return changed, new

    def approve(self, tool: str | None = None) -> list[str]:
        with file_lock(self.path):
            data = _read(self.path)
            pending: dict[str, str] = data.get("pending", {})
            names = [tool] if tool else list(pending)
            approved = [n for n in names if n in pending]
            for n in approved:
                data.setdefault("pinned", {})[n] = pending.pop(n)
            _atomic_write(self.path, data)
        return approved

    def pending(self) -> dict[str, str]:
        return dict(_read(self.path).get("pending", {}))

    def reset(self) -> None:
        with contextlib.suppress(FileNotFoundError):
            self.path.unlink()


def all_pin_stores(root: Path | None = None) -> list[tuple[str, PinStore]]:
    folder = (root or home_dir()) / "pins"
    if not folder.is_dir():
        return []
    return [(p.stem, PinStore(p.stem, root)) for p in sorted(folder.glob("*.json"))]


# ---------------------------------------------------------------------------- approvals


def args_digest(tool: str, arguments: Any) -> str:
    return digest(tool + "\x00" + json.dumps(arguments, sort_keys=True, default=str))


class Approvals:
    """Out-of-band approvals: ``kairoseki approve K-XXXXXX`` from any terminal."""

    def __init__(self, root: Path | None = None) -> None:
        self.dir = _private_dir((root or home_dir()) / "approvals")

    def _path(self, approval_id: str) -> Path:
        safe = "".join(c for c in approval_id.upper() if c.isalnum() or c == "-")
        return self.dir / f"{safe}.json"

    def request(self, server: str, tool: str, arguments: Any, reasons: list[str]) -> str:
        key = args_digest(tool, arguments)
        for path in self.dir.glob("K-*.json"):
            item = _read(path)
            if item.get("server") == server and item.get("key") == key and item.get("status") == "pending":
                return str(item["id"])
        approval_id = "K-" + secrets.token_hex(3).upper()
        _atomic_write(
            self._path(approval_id),
            {
                "id": approval_id,
                "server": server,
                "tool": tool,
                "key": key,
                "reasons": reasons,
                "arguments_preview": json.dumps(arguments, default=str)[:500],
                "status": "pending",
                "created": time.time(),
            },
        )
        return approval_id

    def approve(self, approval_id: str) -> dict[str, Any] | None:
        path = self._path(approval_id)
        with file_lock(path):
            item = _read(path)
            if not item:
                return None
            item["status"] = "approved"
            item["approved_at"] = time.time()
            _atomic_write(path, item)
        return item

    def consume(self, server: str, tool: str, arguments: Any, ttl: float) -> str | None:
        """Use up a matching, unexpired approval. Returns its id or None."""
        key = args_digest(tool, arguments)
        now = time.time()
        for path in self.dir.glob("K-*.json"):
            item = _read(path)
            if item.get("server") != server or item.get("key") != key or item.get("status") != "approved":
                continue
            if now - float(item.get("approved_at", 0)) > ttl:
                continue
            with file_lock(path):
                item = _read(path)
                if item.get("status") != "approved":
                    continue
                item["status"] = "used"
                item["used_at"] = now
                _atomic_write(path, item)
            return str(item["id"])
        return None

    def list(self, status: str | None = None) -> list[dict[str, Any]]:
        items = [_read(p) for p in self.dir.glob("K-*.json")]
        items = [i for i in items if i and (status is None or i.get("status") == status)]
        return sorted(items, key=lambda i: i.get("created", 0))


# ---------------------------------------------------------------------------- audit


class Audit:
    def __init__(self, root: Path | None = None) -> None:
        self.path = _private_dir(root or home_dir()) / "audit.jsonl"

    def write(self, **event: Any) -> None:
        event.setdefault("ts", time.time())
        line = json.dumps(event, default=str, separators=(",", ":"))
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def tail(self, n: int = 20) -> list[dict[str, Any]]:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()[-n:]
        except FileNotFoundError:
            return []
        out = []
        for line in lines:
            with contextlib.suppress(json.JSONDecodeError):
                out.append(json.loads(line))
        return out
