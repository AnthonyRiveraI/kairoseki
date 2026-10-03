"""Classify MCP tools into the three legs of the lethal trifecta.

* ``private``   - the tool returns data the user would not want to leak (files, repos, inbox, DBs).
* ``untrusted`` - the tool returns content a third party can control (web pages, issues, email).
* ``sink``      - the tool can move data out of the user's control (HTTP, email, comments, push).

Plus ``destructive`` for tools that change or delete state.

Heuristics read a tool name as *verb + object* (``get_issue``, ``send_email``,
``create_pull_request``), then look at the description and the MCP annotations.

Classification sources, in order of precedence:

1. Explicit labels in the user's policy (replace everything below for that tool).
2. Name and description heuristics.
3. MCP tool annotations. Annotations come from the (untrusted) server, so they may only *add*
   risk labels - a server can never talk Kairoseki out of a label by claiming ``readOnlyHint``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

PRIVATE = "private"
UNTRUSTED = "untrusted"
SINK = "sink"
DESTRUCTIVE = "destructive"
ALL_LABELS = frozenset({PRIVATE, UNTRUSTED, SINK, DESTRUCTIVE})
_ORDER = [PRIVATE, UNTRUSTED, SINK, DESTRUCTIVE]

# Verbs ---------------------------------------------------------------------------------
READ_VERBS = {
    "get",
    "list",
    "read",
    "search",
    "query",
    "find",
    "view",
    "show",
    "describe",
    "lookup",
    "retrieve",
    "load",
    "open",
    "cat",
    "check",
    "inspect",
    "select",
    "count",
    "recall",
}
# Verbs that reach the network: the response is attacker-controllable and the request itself
# (URL, query string) is an exfiltration channel - markdown images, link previews, DNS.
NETWORK_VERBS = {
    "fetch",
    "browse",
    "navigate",
    "visit",
    "scrape",
    "crawl",
    "curl",
    "wget",
    "download",
    "http",
    "request",
    "goto",
    "ping",
}
# Verbs that move data to someone else.
SEND_VERBS = {
    "send",
    "post",
    "publish",
    "reply",
    "comment",
    "upload",
    "push",
    "forward",
    "share",
    "submit",
    "notify",
    "invite",
    "tweet",
    "email",
    "mail",
    "message",
    "dm",
    "broadcast",
    "webhook",
    "transfer",
    "pay",
    "export",
}
WRITE_VERBS = {
    "create",
    "update",
    "delete",
    "write",
    "edit",
    "add",
    "set",
    "merge",
    "remove",
    "rm",
    "move",
    "rename",
    "insert",
    "drop",
    "truncate",
    "overwrite",
    "kill",
    "deploy",
    "save",
    "append",
    "patch",
    "put",
    "upsert",
    "close",
    "archive",
    "fork",
    "commit",
}
EXEC_TOKENS = {
    "shell",
    "bash",
    "exec",
    "terminal",
    "command",
    "cmd",
    "eval",
    "powershell",
    "subprocess",
    "sh",
    "zsh",
    "repl",
}
DB_TOKENS = {"sql", "query", "select", "db", "database"}

# Objects -------------------------------------------------------------------------------
# Content third parties can write: reading it brings untrusted text into the context.
UNTRUSTED_OBJECTS = {
    "issue",
    "issues",
    "pullrequest",
    "pullrequests",
    "pr",
    "prs",
    "comment",
    "comments",
    "web",
    "url",
    "page",
    "pages",
    "webpage",
    "website",
    "site",
    "html",
    "email",
    "emails",
    "mail",
    "inbox",
    "message",
    "messages",
    "tweet",
    "tweets",
    "post",
    "posts",
    "feed",
    "rss",
    "news",
    "discussion",
    "discussions",
    "review",
    "reviews",
    "notification",
    "notifications",
    "mention",
    "mentions",
    "chat",
    "channel",
    "thread",
    "ticket",
    "tickets",
    "results",
    "link",
    "links",
    "article",
    "articles",
    "readme",
    "wiki",
    "wikis",
}
# The user's own data.
PRIVATE_OBJECTS = {
    "file",
    "files",
    "repo",
    "repos",
    "repository",
    "repositories",
    "db",
    "database",
    "sql",
    "table",
    "tables",
    "row",
    "rows",
    "record",
    "records",
    "env",
    "environment",
    "secret",
    "secrets",
    "credential",
    "credentials",
    "vault",
    "key",
    "keys",
    "token",
    "tokens",
    "calendar",
    "event",
    "events",
    "contact",
    "contacts",
    "drive",
    "doc",
    "docs",
    "document",
    "documents",
    "note",
    "notes",
    "memory",
    "memories",
    "history",
    "keychain",
    "config",
    "ssh",
    "home",
    "directory",
    "dir",
    "folder",
    "customer",
    "customers",
    "user",
    "users",
    "account",
    "accounts",
    "payment",
    "payments",
    "invoice",
    "invoices",
    "order",
    "orders",
    "inbox",
    "email",
    "emails",
    "mail",
    "message",
    "messages",
    "code",
    "branch",
    "commit",
    "commits",
    "contents",
    "content",
    "path",
    "workspace",
    "project",
    "projects",
    "spreadsheet",
    "sheet",
    "sheets",
    "crm",
    "lead",
    "leads",
    "employee",
    "employees",
    "salary",
    "profile",
}
EXPLORE_VERBS = {
    "search",
    "explore",
    "find",
    "grep",
    "lookup",
    "query",
    "trace",
    "inspect",
    "analyze",
    "analyse",
    "locate",
    "resolve",
    "index",
}
# Code intelligence (code graphs, language servers, indexes): the user's own source code.
CODE_OBJECTS = {
    "node",
    "nodes",
    "context",
    "symbol",
    "symbols",
    "graph",
    "codebase",
    "definition",
    "definitions",
    "reference",
    "references",
    "caller",
    "callers",
    "callee",
    "callees",
    "function",
    "functions",
    "class",
    "classes",
    "method",
    "methods",
    "module",
    "modules",
    "source",
    "ast",
    "dependency",
    "dependencies",
    "impact",
    "usage",
    "usages",
    "outline",
    "structure",
    "snippet",
    "snippets",
    "hover",
    "implementation",
    "implementations",
    "diagnostics",
    "embedding",
    "embeddings",
}
PRIVATE_OBJECTS |= CODE_OBJECTS

# Objects whose creation is visible to other people (publishing = sink).
PUBLIC_WRITE_OBJECTS = {
    "issue",
    "issues",
    "pullrequest",
    "pullrequests",
    "pr",
    "comment",
    "comments",
    "post",
    "posts",
    "tweet",
    "message",
    "messages",
    "email",
    "mail",
    "gist",
    "release",
    "discussion",
    "review",
    "reply",
    "channel",
    "webhook",
    "page",
    "wiki",
    "status",
}

_COMPOUNDS = [
    ("pull_request", "pullrequest"),
    ("pull-request", "pullrequest"),
    ("pullrequest", "pullrequest"),
    ("web_search", "web search"),
    ("run_command", "exec"),
    ("run_shell", "exec"),
    ("run_terminal", "exec"),
    ("http_request", "http"),
]

_DESCRIPTION_PHRASES: list[tuple[set[str], re.Pattern[str]]] = [
    (
        {UNTRUSTED, SINK},
        re.compile(
            r"\b(fetch(es)?|retrieves?|downloads?|opens?|visits?)\b[^.]{0,30}\b(url|web ?page|website|link)", re.I
        ),
    ),
    ({UNTRUSTED, SINK}, re.compile(r"\b(makes?|sends?|performs?)\b[^.]{0,20}\bhttp\b", re.I)),
    (
        {SINK},
        re.compile(
            r"\b(sends?|posts?|publish(es)?|repl(y|ies)|forwards?|uploads?)\b[^.]{0,30}\b(email|message|comment|tweet|post|webhook|channel|file)",
            re.I,
        ),
    ),
    (
        {PRIVATE, UNTRUSTED, SINK, DESTRUCTIVE},
        re.compile(r"\b(executes?|runs?)\b[^.]{0,20}\b(shell|command|script|code)\b", re.I),
    ),
    ({UNTRUSTED}, re.compile(r"\b(search(es)? the web|web search|search results)\b", re.I)),
]


def split_name(name: str) -> list[str]:
    """``getFileContents`` / ``get_file-contents`` / ``github.get_file`` -> ['get', 'file', 'contents']."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()
    for src, dst in _COMPOUNDS:
        spaced = spaced.replace(src, dst)
    return [t for t in re.split(r"[^a-z0-9]+", spaced) if t]


def strip_server_prefix(tokens: list[str], server: str) -> list[str]:
    """``codegraph_search`` on server ``codegraph`` -> ``search``. Never strips the whole name."""
    prefix = split_name(server) if server else []
    if prefix and len(tokens) > len(prefix) and tokens[: len(prefix)] == prefix:
        return tokens[len(prefix) :]
    if prefix and len(tokens) > 1 and tokens[0] == "".join(prefix):  # server "code-graph", tool "codegraph_x"
        return tokens[1:]
    return tokens


def classify(tool: dict[str, Any], server: str = "") -> set[str]:
    """Heuristic labels for a tool definition as found in a ``tools/list`` result.

    ``server`` is the name the server runs under; tools are often prefixed with it
    (``codegraph_search``), which would otherwise hide the verb.
    """
    tokens = strip_server_prefix(split_name(str(tool.get("name", ""))), server)
    toks = set(tokens)
    labels: set[str] = set()

    if toks & EXEC_TOKENS:
        labels |= set(ALL_LABELS)
    if toks & NETWORK_VERBS:
        labels |= {UNTRUSTED, SINK}
    if toks & SEND_VERBS:
        labels |= {SINK}
    if toks & DB_TOKENS:
        labels.add(PRIVATE)
        if toks & {"execute", "run"}:
            labels.add(DESTRUCTIVE)
    if toks & {"execute", "run", "eval"} and toks & {"code", "script", "python", "javascript", "js", "node"}:
        labels |= set(ALL_LABELS)
    writes = bool(toks & WRITE_VERBS)
    reads = bool(toks & READ_VERBS) or not (writes or toks & SEND_VERBS)
    if writes:
        labels.add(DESTRUCTIVE)
        if toks & PUBLIC_WRITE_OBJECTS:
            labels.add(SINK)
    if reads:
        if toks & UNTRUSTED_OBJECTS:
            labels.add(UNTRUSTED)
        if toks & PRIVATE_OBJECTS:
            labels.add(PRIVATE)

    description = str(tool.get("description") or "")
    for extra, rx in _DESCRIPTION_PHRASES:
        if rx.search(description):
            labels |= extra

    ann = tool.get("annotations") or {}
    if ann.get("openWorldHint") is True:
        labels.add(UNTRUSTED)
        if ann.get("readOnlyHint") is not True:
            labels.add(SINK)
    if ann.get("destructiveHint") is True:
        labels.add(DESTRUCTIVE)

    # a bare exploratory verb ("search", "explore") with nothing else to go on: these tools
    # look through the user's own data (code graphs, notes, indexes)
    if not labels and toks & EXPLORE_VERBS:
        labels.add(PRIVATE)
    return labels


def describe(labels: Iterable[str]) -> str:
    s = set(labels)
    return ", ".join(x for x in _ORDER if x in s) or "-"
