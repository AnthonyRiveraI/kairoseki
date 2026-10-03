"""Plain-language explanations of Kairoseki decisions, in English or Spanish.

The rule names and reasons in :class:`~kairoseki.engine.Decision` are for logs. People (and the
agent, which relays them) need to know what was attempted, why it looks risky, and what to do.
These are built from the session's own data, locally: sending the context to an AI service to
summarize it would itself be the kind of data flow Kairoseki exists to stop.
"""

from __future__ import annotations

import locale
import os
import re
import shlex
from typing import Any
from urllib.parse import urlsplit

from .detect import redact_secrets

# what each source means to a person; MCP tools fall back to "server (tool)"
_BUILTIN = {
    "en": {
        "WebFetch": "a web page",
        "WebSearch": "web search results",
        "Read": "your files",
        "Grep": "a search through your files",
        "Bash": "terminal output",
    },
    "es": {
        "WebFetch": "una página web",
        "WebSearch": "resultados de búsqueda web",
        "Read": "tus archivos",
        "Grep": "una búsqueda en tus archivos",
        "Bash": "la salida de la terminal",
    },
}

_TEXT = {
    "en": {
        "ask_title": "🪨 Kairoseki paused this so you can confirm it.",
        "deny_title": "🪨 Kairoseki blocked this.",
        "what": "What the agent is trying to do",
        "why": "Why",
        "todo": "What to do",
        "and": "and",
        "injected": "⚠️ That content contained text that looks like hidden instructions for the AI.",
        "lethal_trifecta": "this session read {untrusted} and also {private}. If that outside content tricked the agent, this step could send your data to someone else.",
        "private_data_flow": "this would hand private data from this session to {tool}, after the session read {untrusted}. Any tool you send data to can pass it on.",
        "secret_exfiltration": "the request contains a secret (a key or token that appeared earlier in this session){encoded}. Kairoseki never lets secrets leave.",
        "poisoned_tool": "the description of this tool hides instructions aimed at the AI, a known attack (tool poisoning).",
        "rug_pull": "this tool changed its definition after you first used it. A server that changes its tools silently may be turning malicious.",
        "policy_deny": "your Kairoseki policy always blocks this tool.",
        "strict_untrusted_action": "strict mode asks before any action that can send data out or change things once outside content was read ({untrusted}).",
        "strict_overlap": "strict mode: the request copies text from outside content.",
        "encoded": ", possibly encoded or split up",
        "todo_ask": "If you asked for this, approve it. If you didn't expect it, deny it and check what the agent read.",
        "todo_secret": "If you really meant to send that secret, do it yourself outside the agent.",
        "todo_rug": "Review the change, then run: kairoseki pins approve {server}",
        "todo_policy": "Change the policy (kairoseki.yaml) if you want to allow it.",
        "todo_deny": "Nothing to do: the call did not run.",
        "run": "run `{command}`",
        "open": "open {url}",
        "use": "use {tool}",
        "use_with": "use {tool} with {args}",
    },
    "es": {
        "ask_title": "🪨 Kairoseki pausó esto para que lo confirmes.",
        "deny_title": "🪨 Kairoseki bloqueó esto.",
        "what": "Qué intenta hacer el agente",
        "why": "Por qué",
        "todo": "Qué hacer",
        "and": "y",
        "injected": "⚠️ Ese contenido traía texto que parece instrucciones escondidas para la IA.",
        "lethal_trifecta": "en esta sesión el agente leyó {untrusted} y también {private}. Si ese contenido de fuera engañó al agente, este paso podría enviar tus datos a un tercero.",
        "private_data_flow": "esto le pasaría datos privados de la sesión a {tool}, después de haber leído {untrusted}. Cualquier herramienta que reciba datos puede reenviarlos.",
        "secret_exfiltration": "la petición contiene un secreto (una clave o token que apareció antes en esta sesión){encoded}. Kairoseki nunca deja salir secretos.",
        "poisoned_tool": "la descripción de esta herramienta esconde instrucciones dirigidas a la IA, un ataque conocido (tool poisoning).",
        "rug_pull": "esta herramienta cambió su definición después de que la usaste por primera vez. Un servidor que cambia sus herramientas en silencio podría estar volviéndose malicioso.",
        "policy_deny": "tu política de Kairoseki bloquea siempre esta herramienta.",
        "strict_untrusted_action": "el modo estricto pregunta antes de cualquier acción que pueda sacar datos o cambiar cosas cuando ya se leyó contenido de fuera ({untrusted}).",
        "strict_overlap": "modo estricto: la petición copia texto de contenido de fuera.",
        "encoded": ", quizá codificado o troceado",
        "todo_ask": "Si tú pediste esto, apruébalo. Si no lo esperabas, recházalo y revisa qué leyó el agente.",
        "todo_secret": "Si de verdad querías enviar ese secreto, hazlo tú mismo fuera del agente.",
        "todo_rug": "Revisa el cambio y luego ejecuta: kairoseki pins approve {server}",
        "todo_policy": "Cambia la política (kairoseki.yaml) si quieres permitirla.",
        "todo_deny": "Nada: la llamada no se ejecutó.",
        "run": "ejecutar `{command}`",
        "open": "abrir {url}",
        "use": "usar {tool}",
        "use_with": "usar {tool} con {args}",
    },
}


def language() -> str:
    """``$KAIROSEKI_LANG``, then ``$LC_ALL``/``$LC_MESSAGES``/``$LANG``, then the OS locale. ``es`` or ``en``."""
    for var in ("KAIROSEKI_LANG", "LC_ALL", "LC_MESSAGES", "LANG"):
        value = os.environ.get(var, "")
        if value and value not in ("C", "POSIX"):
            return "es" if value.lower().startswith("es") else "en"
    try:
        name = (locale.getlocale()[0] or "").lower()
    except ValueError:
        name = ""
    return "es" if name.startswith(("es", "spanish")) else "en"


def _short(text: str, limit: int = 140) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _sources(items: list[dict[str, Any]], lang: str) -> str:
    names: list[str] = []
    for item in items[-4:]:
        server, tool = str(item.get("server", "")), str(item.get("tool", ""))
        name = _BUILTIN[lang].get(tool, tool) if server == "claude-code" else f"{server} ({tool})"
        if name not in names:
            names.append(name)
    if not names:
        return "?"
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + f" {_TEXT[lang]['and']} " + names[-1]


def _action(tool: str, server: str, arguments: Any, lang: str, show_args: bool) -> str:
    t = _TEXT[lang]
    args = arguments if isinstance(arguments, dict) else {}
    if server == "claude-code" and tool == "Bash" and "command" in args:
        raw = str(args["command"])
        if show_args:
            return t["run"].format(command=_short(redact_secrets(raw)[0], 120))
        # the command may carry the secret: show only the program and where it was going
        host = re.search(r"https?://([^/\s?#'\"]+)", raw)
        return t["run"].format(command=(raw.split() or ["?"])[0]) + (f" → {host.group(1)}" if host else "")
    if "url" in args and isinstance(args["url"], str):
        parts = urlsplit(args["url"])
        url = f"{parts.scheme}://{parts.netloc}{parts.path}" + ("?…" if parts.query else "")
        return t["open"].format(url=_short(url if show_args else f"{parts.scheme}://{parts.netloc}", 100))
    name = tool if server == "claude-code" else f"{server}.{tool}"
    if not show_args or not args:
        return t["use"].format(tool=name)
    preview = ", ".join(f"{k}={shlex.quote(str(v))}" for k, v in list(args.items())[:3])
    return t["use_with"].format(tool=name, args=_short(redact_secrets(preview)[0], 100))


def explain(
    rule: str,
    action: str,
    tool: str,
    server: str,
    arguments: Any,
    snapshot: dict[str, Any] | None,
    lang: str | None = None,
    hide_args: bool = False,
) -> str:
    """A short, plain-language message: what the agent is trying to do, why it was stopped, what to do.

    ``hide_args`` leaves the call's arguments out (for messages that leave the machine, like Den Den Mushi);
    they are always left out when the call carries a secret.
    """
    lang = lang or language()
    t = _TEXT[lang]
    snapshot = snapshot or {}
    untrusted = snapshot.get("untrusted") or []
    private = snapshot.get("private") or []
    secret = rule == "secret_exfiltration"
    hide_args = hide_args or secret
    tool_name = tool if server == "claude-code" else f"{server}.{tool}"
    why = t.get(rule, rule).format(
        untrusted=_sources(untrusted, lang),
        private=_sources(private, lang),
        tool=tool_name,
        encoded=t["encoded"],
    )
    if rule in ("lethal_trifecta", "private_data_flow", "strict_untrusted_action") and any(
        item.get("detail") for item in untrusted
    ):
        why += " " + t["injected"]
    if secret:
        todo = t["todo_secret"]
    elif rule == "rug_pull":
        todo = t["todo_rug"].format(server=server)
    elif rule == "policy_deny":
        todo = t["todo_policy"]
    elif action == "ask":
        todo = t["todo_ask"]
    else:
        todo = t["todo_deny"]
    lines = [
        t["ask_title"] if action == "ask" else t["deny_title"],
        f"{t['what']}: {_action(tool, server, arguments, lang, show_args=not hide_args)}.",
        f"{t['why']}: {why[0].upper() + why[1:]}",
        f"{t['todo']}: {todo}",
    ]
    return "\n".join(lines)
