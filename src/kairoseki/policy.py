"""User policy: modes, redaction switches, and per-server overrides (``kairoseki.yaml``)."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .labels import ALL_LABELS

MODES = ("monitor", "balanced", "strict")

DEFAULT_POLICY_YAML = """\
# Kairoseki policy - https://github.com/AnthonyRiveraI/kairoseki
#
# mode:
#   monitor  - never block, only log what would have been blocked (good for a first week)
#   balanced - block exfiltration, ask before the lethal trifecta closes (default)
#   strict   - also ask before any sink or destructive tool once untrusted content was read
mode: balanced

redact:
  secrets: true   # API keys, tokens and private keys never reach the model
  pii: false      # emails, phone numbers and card numbers

pin_tools: true             # trust-on-first-use: block tools whose definition changes later
block_poisoned_tools: true  # block tools whose description contains prompt-injection text
warn_on_injection: true     # prepend a warning to tool output that looks like instructions

approval:
  timeout_seconds: 120  # how long to wait for an in-client approval prompt
  ttl_seconds: 600      # how long a `kairoseki approve <id>` stays valid

# Den Den Mushi: approve risky calls from your phone with the free ntfy app (https://ntfy.sh).
# Only the server, tool and reason are sent, never the arguments. Get a random topic with `kairoseki denden setup`.
# denden:
#   topic: kairoseki-REPLACE-WITH-RANDOM
#   url: https://ntfy.sh       # or your self-hosted ntfy
#   token: ""                  # access token, if your ntfy server needs one

# Per-server overrides. Keys are the --name you give `kairoseki run` (globs allowed).
# servers:
#   github:
#     tools:
#       get_issue: [untrusted]               # explicit labels replace the heuristics
#       create_or_update_file: [sink, destructive]
#     allow: [search_repositories]           # never ask (redaction still applies). Careful: allow
#                                            # skips the lethal-trifecta rule, the main safety net
#     deny: [delete_repository]              # always block
"""


@dataclass
class ServerRules:
    tools: dict[str, set[str]] = field(default_factory=dict)
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)


@dataclass
class DenDen:
    topic: str
    url: str = "https://ntfy.sh"
    token: str = ""


@dataclass
class Policy:
    mode: str = "balanced"
    redact_secrets: bool = True
    redact_pii: bool = False
    pin_tools: bool = True
    block_poisoned_tools: bool = True
    warn_on_injection: bool = True
    approval_timeout: float = 120.0
    approval_ttl: float = 600.0
    servers: dict[str, ServerRules] = field(default_factory=dict)
    denden: DenDen | None = None

    # ------------------------------------------------------------------ lookups
    def _rules_for(self, server: str) -> list[ServerRules]:
        return [r for pattern, r in self.servers.items() if fnmatch.fnmatchcase(server, pattern)]

    def explicit_labels(self, server: str, tool: str) -> set[str] | None:
        for rules in self._rules_for(server):
            for pattern, labels in rules.tools.items():
                if fnmatch.fnmatchcase(tool, pattern):
                    return set(labels)
        return None

    def is_allowed(self, server: str, tool: str) -> bool:
        return any(fnmatch.fnmatchcase(tool, p) for r in self._rules_for(server) for p in r.allow)

    def is_denied(self, server: str, tool: str) -> bool:
        return any(fnmatch.fnmatchcase(tool, p) for r in self._rules_for(server) for p in r.deny)


class PolicyError(ValueError):
    pass


def _as_bool(data: dict[str, Any], key: str, default: bool) -> bool:
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise PolicyError(f"'{key}' must be true or false, got {value!r}")
    return value


def parse_policy(data: dict[str, Any] | None) -> Policy:
    data = data or {}
    if not isinstance(data, dict):
        raise PolicyError("policy must be a mapping")
    mode = data.get("mode", "balanced")
    if mode not in MODES:
        raise PolicyError(f"mode must be one of {', '.join(MODES)}, got {mode!r}")
    redact = data.get("redact") or {}
    approval = data.get("approval") or {}
    servers: dict[str, ServerRules] = {}
    for name, raw in (data.get("servers") or {}).items():
        raw = raw or {}
        tools: dict[str, set[str]] = {}
        for tool, labels in (raw.get("tools") or {}).items():
            labels = set(labels or [])
            unknown = labels - ALL_LABELS
            if unknown:
                raise PolicyError(f"servers.{name}.tools.{tool}: unknown labels {sorted(unknown)}")
            tools[str(tool)] = labels
        servers[str(name)] = ServerRules(
            tools=tools, allow=[str(x) for x in raw.get("allow") or []], deny=[str(x) for x in raw.get("deny") or []]
        )
    denden = None
    if data.get("denden"):
        raw_dd = data["denden"]
        topic = str(raw_dd.get("topic") or "") if isinstance(raw_dd, dict) else ""
        if len(topic) < 16 or "REPLACE" in topic:
            raise PolicyError("denden.topic must be a random name of 16+ characters (run: kairoseki denden setup)")
        denden = DenDen(
            topic=topic,
            url=str(raw_dd.get("url") or "https://ntfy.sh").rstrip("/"),
            token=str(raw_dd.get("token") or ""),
        )
    return Policy(
        mode=mode,
        redact_secrets=_as_bool(redact, "secrets", True),
        redact_pii=_as_bool(redact, "pii", False),
        pin_tools=_as_bool(data, "pin_tools", True),
        block_poisoned_tools=_as_bool(data, "block_poisoned_tools", True),
        warn_on_injection=_as_bool(data, "warn_on_injection", True),
        approval_timeout=float(approval.get("timeout_seconds", 120)),
        approval_ttl=float(approval.get("ttl_seconds", 600)),
        servers=servers,
        denden=denden,
    )


def default_policy_path() -> Path | None:
    """``$KAIROSEKI_POLICY``, then ``./kairoseki.yaml``, then ``~/.kairoseki/kairoseki.yaml``."""
    env = os.environ.get("KAIROSEKI_POLICY")
    if env:
        return Path(env)
    for candidate in (Path.cwd() / "kairoseki.yaml", home_dir() / "kairoseki.yaml"):
        if candidate.is_file():
            return candidate
    return None


def load_policy(path: str | os.PathLike[str] | None = None) -> Policy:
    resolved = Path(path) if path else default_policy_path()
    if resolved is None:
        return Policy()
    try:
        data = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise PolicyError(f"policy file not found: {resolved}") from e
    except yaml.YAMLError as e:
        raise PolicyError(f"invalid YAML in {resolved}: {e}") from e
    return parse_policy(data)


def home_dir() -> Path:
    return Path(os.environ.get("KAIROSEKI_HOME") or Path.home() / ".kairoseki")
