"""Content inspection: sanitization, prompt-injection heuristics, secret and PII detection.

Detection here is a *signal*, never the only line of defense. Kairoseki's core guarantee
comes from data-flow rules (see ``engine.py`` and ``store.py``); these heuristics only add taint early and
make audit logs readable.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass

# --------------------------------------------------------------------------- sanitization

_ANSI_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])")
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿᠎"), None)
_BIDI = dict.fromkeys(map(ord, "‪‫‬‭‮⁦⁧⁨⁩"), None)
_TAG_RANGE = (0xE0000, 0xE007F)


def decode_tag_smuggling(text: str) -> str:
    """Return the ASCII hidden in Unicode tag characters (U+E0020..U+E007E), if any."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


@dataclass
class SanitizeResult:
    text: str
    hidden: str  # text that was invisible to a human reviewer (tag smuggling, ANSI-concealed)
    changed: bool


def sanitize(text: str) -> SanitizeResult:
    """Make invisible or terminal-control content visible and inert.

    * ANSI escape sequences are replaced by a visible ``[ESC]`` marker (they can hide text
      in terminals and rewrite what a human reviewer sees).
    * Unicode tag characters (ASCII smuggling) are removed; their decoded payload is
      returned in ``hidden`` so it can still be scanned.
    * Zero-width and bidi-override characters are removed.
    """
    hidden = decode_tag_smuggling(text)
    out = _ANSI_RE.sub("[ESC]", text)
    out = out.replace("\x1b", "[ESC]")
    out = "".join(c for c in out if not (_TAG_RANGE[0] <= ord(c) <= _TAG_RANGE[1]))
    out = out.translate(_ZERO_WIDTH).translate(_BIDI)
    return SanitizeResult(text=out, hidden=hidden, changed=out != text)


# --------------------------------------------------------------------------- injection

# a directive, not a warning: "do not include credentials" or "never send data to http://" must not match
_NOT = r"(?<!\bnot\s)(?<!n't\s)(?<!\bnever\s)(?<!\bno\s)"

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (name, re.compile(rx, re.IGNORECASE))
    for name, rx in [
        (
            "override_instructions",
            r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|your|system)\b[^.\n]{0,20}\b(instructions?|prompts?|rules|directives)",
        ),
        ("new_instructions", r"\b(new|updated|real|actual)\s+(system\s+)?(instructions?|directives?|task)\s*[:\-]"),
        ("role_hijack", r"\b(you are now|from now on,? you|act as (an?|the) (admin|system|root))\b"),
        (
            "hidden_from_user",
            r"\b(do not|don't|never)\s+(tell|inform|mention|show|reveal|alert)\b[^.\n]{0,30}\b(user|human|developer)",
        ),
        ("important_tag", r"<\s*(important|system|instructions?|admin|secret)\s*>"),
        (
            "chat_template",
            r"(<\|im_start\|>|<\|im_end\|>|\[/?INST\]|<\|system\|>|<\|assistant\|>|^\s*(system|assistant)\s*:)",
        ),
        (
            "tool_directive",
            r"\b(before|after|instead of)\s+(using|calling|running|answering)\b[^.\n]{0,40}\b(you must|always|first)\b",
        ),
        (
            "exfil_directive",
            _NOT
            + r"\b(send|post|upload|forward|leak|exfiltrate)\b[^.\n]{0,60}\b(https?://|to\s+[\w.+-]+@[\w-]+\.[\w.]+|webhook|attacker)",
        ),
        (
            "secret_seeking",
            _NOT
            + r"\b(read|cat|print|send|include|copy)\b[^.\n]{0,40}(\.env\b|id_rsa|\.ssh|api[_ -]?keys?|credentials|secrets?|tokens?|mcp\.json|\.aws)",
        ),
        ("es_override", r"\b(ignora|olvida|omite)\b[^.\n]{0,40}\b(instrucciones|reglas)\b"),
    ]
]


def find_injection(text: str) -> list[str]:
    """Return the names of injection heuristics that match ``text`` (empty if none)."""
    if not text:
        return []
    probe = text + "\n" + decode_tag_smuggling(text)
    probe = unicodedata.normalize("NFKC", probe)
    return [name for name, rx in _INJECTION_PATTERNS if rx.search(probe)]


# --------------------------------------------------------------------------- secrets

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "private_key",
        re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z]+ )?PRIVATE KEY-----"),
    ),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai_key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
    ("stripe_key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
]
# Names of variables that hold secrets: a whole underscore-separated word, so GITHUB_PAT and
# OPENAI_API_KEY match but PATH, PATHEXT, PWD and MONKEY_D_LUFFY don't.
SECRET_NAME = re.compile(
    r"(?:^|_)(?:API_?KEY|KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|CREDENTIALS?|AUTH|PAT|PRIVATE_?KEY)(?:_|$)", re.I
)
_PATH_LIKE = re.compile(r"^(?:[/~\\]|[A-Za-z]:[\\/]|https?://|\.{1,2}[\\/])")
# key = value assignments in env files / configs; the value is the secret (group 2)
_ASSIGNMENT = re.compile(r"""(?im)^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*[:=]\s*["']?([^\s"'#]{8,})""")


def is_secret_assignment(name: str, value: str) -> bool:
    """True for ``OPENAI_API_KEY=sk-...``; False for ``PATH=C:\\...`` or ``SECRET_DIR=/etc/x``."""
    return bool(SECRET_NAME.search(name)) and len(value) >= 8 and not _PATH_LIKE.match(value)


@dataclass(frozen=True)
class SecretMatch:
    kind: str
    value: str
    start: int
    end: int


def find_secrets(text: str) -> list[SecretMatch]:
    """Find credential-looking values. Overlapping matches keep the earliest, longest one."""
    found: list[SecretMatch] = []
    for kind, rx in _SECRET_PATTERNS:
        for m in rx.finditer(text):
            found.append(SecretMatch(kind, m.group(0), m.start(), m.end()))
    for m in _ASSIGNMENT.finditer(text):
        if is_secret_assignment(m.group(1), m.group(2)):
            found.append(SecretMatch(f"assigned:{m.group(1).lower()}", m.group(2), m.start(2), m.end(2)))
    found.sort(key=lambda s: (s.start, -(s.end - s.start)))
    result: list[SecretMatch] = []
    last_end = -1
    for s in found:
        if s.start >= last_end:
            result.append(s)
            last_end = s.end
    return result


def redact_secrets(text: str) -> tuple[str, list[SecretMatch]]:
    """Replace secrets with ``[REDACTED:kind]`` and return the matches that were removed."""
    matches = find_secrets(text)
    if not matches:
        return text, []
    parts: list[str] = []
    cursor = 0
    for s in matches:
        parts.append(text[cursor : s.start])
        parts.append(f"[REDACTED:{s.kind}]")
        cursor = s.end
    parts.append(text[cursor:])
    return "".join(parts), matches


# --------------------------------------------------------------------------- PII

_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_PHONE = re.compile(r"(?<![\w+])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)|\d{2,4})[\s.-]\d{3,4}[\s.-]?\d{3,4}(?![\w])")


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def redact_pii(text: str) -> tuple[str, int]:
    """Redact emails, Luhn-valid card numbers and phone numbers. Returns (text, count)."""
    count = 0

    def card(m: re.Match[str]) -> str:
        nonlocal count
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            count += 1
            return "[REDACTED:card]"
        return m.group(0)

    def sub(label: str) -> Callable[[re.Match[str]], str]:
        def repl(_: re.Match[str]) -> str:
            nonlocal count
            count += 1
            return f"[REDACTED:{label}]"

        return repl

    text = _CARD.sub(card, text)
    text = _EMAIL.sub(sub("email"), text)
    text = _PHONE.sub(sub("phone"), text)
    return text, count
