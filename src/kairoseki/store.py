"""On-disk state shared by every Kairoseki proxy of one agent session.

An agent usually talks to several MCP servers (fetch, filesystem, GitHub...). Each one is
wrapped by its own ``kairoseki run`` process, but the lethal trifecta spans servers: the
untrusted web page comes from one, the private file from another, the exfiltration happens
through a third. So taint lives in a small JSON file keyed by session, guarded by a lock
file, that all proxies of the same agent read and update.

The session key defaults to the MCP client process that started the servers (all servers of one
Claude Code / Cursor window share it, see ``session_id.py``) and can be forced with
``KAIROSEKI_SESSION``.

Secrets are never written to disk. A session stores 80-bit BLAKE2b fingerprints of each
secret, of its encodings and of its 12-character fragments, indexed by a 20-bit CRC-32 tag
of their first 8 bytes. Text fingerprints (shingles) of untrusted and private output are
64-bit CRC-32 + Adler-32 keys of 32-character windows.

Scanning a tool call is linear in its size and has no length limit (a cap would let an
attacker pad past it); expect roughly a second per few megabytes of arguments in Python.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import re
import secrets
import time
import urllib.parse
import zlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .policy import home_dir
from .session_id import client_session_id

SESSION_TTL = 12 * 3600
SHINGLE = 32  # chars copied verbatim from untrusted content that mark an argument as attacker-derived
_SHINGLE_STRIDE = 8
_MAX_SHINGLES = 60_000
FRAGMENT = 12  # characters of a secret that count as leaking it, even when the rest is elsewhere
_PREFIX = 8  # bytes of a secret used to find candidate positions in a tool call
_TAG_MASK = 0xFFFFF  # only 20 bits of a prefix checksum are stored, so the index reveals ~nothing
_MAX_SOURCES = 50


def digest(value: str) -> str:
    """Short fingerprint (80 bits). Only fingerprints of secrets ever touch disk."""
    return _digest_bytes(value.encode("utf-8", "surrogatepass"))


def _digest_bytes(value: bytes | memoryview) -> str:
    return hashlib.blake2b(value, digest_size=10).hexdigest()


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
        except (FileExistsError, PermissionError):  # Windows reports a lock file being deleted as EACCES
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
    # Windows refuses to replace a file another process has open for reading; retry briefly
    for attempt in range(200):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt == 199:
                raise
            time.sleep(0.01)


def _read(path: Path) -> dict[str, Any]:
    for _ in range(200):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
        except PermissionError:  # Windows: the file is being replaced right now
            time.sleep(0.01)
            continue
        return data if isinstance(data, dict) else {}
    return {}


def default_session_id() -> str:
    """``$KAIROSEKI_SESSION`` if set, otherwise the MCP client process (see ``session_id.py``)."""
    env = os.environ.get("KAIROSEKI_SESSION")
    if env:
        return "".join(c for c in env if c.isalnum() or c in "-_")[:64] or "default"
    return client_session_id()


# Vendor prefixes are the same in every key ("sk-ant-api03-" is exactly 12 characters), so they
# are never fingerprinted as fragments: only the random part after them identifies a secret.
_PUBLIC_PREFIX = re.compile(
    r"^(?:sk-ant-(?:api|admin)\d\d-|sk-ant-|sk-(?:proj|svcacct|admin)-|sk-|gh[pousr]_|github_pat_\d*_?|"
    r"AKIA|ASIA|xox[abposr]-|AIza|[sr]k_(?:live|test)_|npm_|glpat-|hf_|pk_(?:live|test)_)"
)


def random_part(secret: str) -> str:
    """The part of a secret that differs between keys: everything after a known vendor prefix."""
    m = _PUBLIC_PREFIX.match(secret)
    return secret[m.end() :] if m else secret


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
                data = {"created": now, "untrusted": [], "private": [], "secret_index": {}, "shingles": []}
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

    def learn_secrets(self, values: list[str], fragment: list[str] | None = None) -> None:
        """Fingerprint secrets (and their encodings). Values in ``fragment`` also get every
        ``FRAGMENT``-character piece fingerprinted, so a secret split across arguments
        (``?a=<first half>&b=<second half>``) is still recognized."""
        values = list(values)
        fragment = list(fragment or [])
        if not values and not fragment:
            return
        with self._update() as data:
            index: dict[str, list[list[Any]]] = data.setdefault("secret_index", {})
            pieces = {
                body[i : i + FRAGMENT]
                for body in (random_part(f) for f in fragment)
                for i in range(len(body) - FRAGMENT + 1)
                if len(set(body[i : i + FRAGMENT])) >= 4  # skip runs like "------------" or "AAAAAAAAAAAA"
            }
            for value in [*values, *fragment, *pieces]:
                for v in secret_variants(value) if value not in pieces else {value}:
                    raw = v.encode("utf-8", "surrogatepass")
                    if len(raw) < _PREFIX:
                        continue
                    bucket = index.setdefault(str(zlib.crc32(raw[:_PREFIX]) & _TAG_MASK), [])
                    entry = [len(raw), _digest_bytes(raw)]
                    if entry not in bucket:
                        bucket.append(entry)

    def learn_untrusted_text(self, text: str) -> None:
        self._learn_shingles("shingles", text)

    def learn_private_text(self, text: str) -> None:
        self._learn_shingles("private_shingles", text)

    def _learn_shingles(self, key: str, text: str) -> None:
        view = memoryview(_normalize(text))
        if len(view) < SHINGLE:
            return
        new = {_window_key(view[i : i + SHINGLE]) for i in range(0, len(view) - SHINGLE + 1, _SHINGLE_STRIDE)}
        with self._update() as data:
            current = {k for k in data.get(key, []) if isinstance(k, int)}
            current |= new
            data[key] = list(current)[-_MAX_SHINGLES:]

    # ------------------------------------------------------------------ readers
    @staticmethod
    def leaked_secret(data: dict[str, Any], text: str) -> bool:
        """True if ``text`` contains a known secret (or an encoding of it), anywhere in it.

        One pass over the text: a C checksum of each 8-byte window is looked up in the index,
        and only candidate positions pay for a full BLAKE2 comparison.
        """
        index = data.get("secret_index") or {}
        if not index:
            return False
        tags = {int(k): v for k, v in index.items()}
        view = memoryview(text.encode("utf-8", "surrogatepass"))
        n, crc = len(view), zlib.crc32
        for i in range(n - _PREFIX + 1):
            candidates = tags.get(crc(view[i : i + _PREFIX]) & _TAG_MASK)
            if candidates:
                for length, wanted in candidates:
                    if i + length <= n and _digest_bytes(view[i : i + length]) == wanted:
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
        shingles = {k for k in data.get(key) or [] if isinstance(k, int)}
        if not shingles:
            return False
        view = memoryview(_normalize(text))
        return any(_window_key(view[i : i + SHINGLE]) in shingles for i in range(len(view) - SHINGLE + 1))


def _normalize(text: str) -> bytes:
    return " ".join(text.split()).lower().encode("utf-8", "surrogatepass")


def _window_key(window: memoryview) -> int:
    """64-bit fingerprint of a window from two C checksums (fast enough to run at every offset)."""
    return (zlib.crc32(window) << 32) | zlib.adler32(window)


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
