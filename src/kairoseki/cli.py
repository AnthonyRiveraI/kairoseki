"""Command-line interface."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import json
import os
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from . import __version__
from .configs import ServerEntry, candidate_configs, read_servers, unwrap_argv, unwrap_config, wrap_config
from .detect import find_injection, sanitize
from .labels import PRIVATE, SINK, UNTRUSTED, classify, describe
from .policy import DEFAULT_POLICY_YAML, PolicyError, home_dir, load_policy
from .report import ScanResult, render_card
from .store import Approvals, Audit, PinStore, Session, all_pin_stores

console = Console(stderr=False, highlight=False)
err = Console(stderr=True, highlight=False)


# ---------------------------------------------------------------------------- run
def cmd_run(a: argparse.Namespace) -> int:
    from .engine import Engine
    from .proxy import run_proxy

    command = a.command[1:] if a.command and a.command[0] == "--" else a.command
    if not command:
        err.print("usage: kairoseki run [--name NAME] -- <server command> [args...]")
        return 2
    try:
        policy = load_policy(a.policy)
    except PolicyError as e:
        err.print(f"[red]kairoseki: {e}[/red]")
        return 2
    if a.mode:
        policy.mode = a.mode
    name = a.name or Path(command[0]).name
    engine = Engine(name, policy, Session(), pins=PinStore(name), approvals=Approvals(), audit=Audit())
    return run_proxy(engine, command, verbose=a.verbose)


# ---------------------------------------------------------------------------- scan
def _scan_entries(entries: list[tuple[str, ServerEntry]], timeout: float, result: ScanResult) -> int:
    from .client import StdioClient

    legs = result.legs
    table = Table(title="MCP tools by trifecta leg", show_lines=False)
    for col in ("server", "tool", "labels", "notes"):
        table.add_column(col)
    problems = 0
    for source, entry in entries:
        if entry.url and not entry.command:
            table.add_row(
                entry.name,
                "-",
                "-",
                f"[dim]remote server ({source}): kairoseki wrap --remote to scan and protect it[/dim]",
            )
            continue
        result.servers += 1
        if not entry.wrapped:
            result.unprotected.append(entry.name)
        argv = entry.argv()
        if entry.wrapped:
            cmd, args = unwrap_argv(argv[0], argv[1:])
            argv = [cmd, *args]
        try:
            with StdioClient(argv, env=entry.env, timeout=timeout) as client:
                client.initialize()
                tools = client.list_tools()
        except Exception as e:
            table.add_row(entry.name, "-", "-", f"[red]could not start: {e}[/red]")
            continue
        for tool in tools:
            name = str(tool.get("name"))
            labels = classify(tool, server=entry.name)
            notes = []
            texts = [str(tool.get("description") or ""), json.dumps(tool.get("inputSchema") or {})]
            hits = sorted({h for t in texts for h in find_injection(t)})
            if any(sanitize(t).hidden for t in texts):
                hits.append("hidden_unicode")
            if hits:
                problems += 1
                result.poisoned.append(f"{entry.name}.{name}")
                notes.append(f"[red]poisoned description: {', '.join(hits)}[/red]")
            for leg in legs:
                if leg in labels:
                    legs[leg].append(f"{entry.name}.{name}")
            table.add_row(entry.name, name, describe(labels), " ".join(notes))
    console.print(table)
    if all(legs.values()):
        console.print(
            "\n[bold red]⚠ Lethal trifecta present.[/bold red] One prompt injection can chain:\n"
            f"  untrusted content  ← {', '.join(legs[UNTRUSTED][:4])}\n"
            f"  private data       ← {', '.join(legs[PRIVATE][:4])}\n"
            f"  exfiltration       ← {', '.join(legs[SINK][:4])}\n"
            "Protect these servers with: [bold]kairoseki wrap[/bold]"
        )
        problems += 1
    else:
        missing = [leg for leg, tools in legs.items() if not tools]
        console.print(f"\n[green]No lethal trifecta[/green] (missing: {', '.join(missing)}).")
    return 1 if problems else 0


def cmd_scan(a: argparse.Namespace) -> int:
    command = a.command[1:] if a.command and a.command[0] == "--" else a.command
    entries: list[tuple[str, ServerEntry]] = []
    if command:
        entries.append(("command line", ServerEntry(Path(command[0]).name, command[0], command[1:], {})))
    else:
        configs = [("--config", Path(c)) for c in a.config] if a.config else candidate_configs()
        if not configs:
            err.print("No MCP client config found. Pass --config FILE or `kairoseki scan -- <server command>`.")
            return 2
        for label, path in configs:
            if not a.json:
                console.print(f"[dim]reading {label}: {path}[/dim]")
            entries += [(label, e) for e in read_servers(path, all_projects=a.all_projects)]
    result = ScanResult()
    console.quiet = a.json  # --json: only the JSON document goes to stdout
    try:
        code = _scan_entries(entries, a.timeout, result)
    finally:
        console.quiet = False
    if a.json:
        print(json.dumps({"grade": result.grade, "verdict": result.verdict, **vars(result)}, indent=2))
    else:
        console.print(f"[bold]Grade {result.grade}[/bold]: {result.verdict}.")
    if a.share:
        Path(a.share).write_text(render_card(result), encoding="utf-8")
        if not a.json:
            console.print(f"Shareable card written to {a.share} (counts only: no paths, commands or secrets).")
    return code


# ---------------------------------------------------------------------------- wrap / unwrap
def _protection_table(configs: list[tuple[str, Path]], all_projects: bool, title: str) -> tuple[Table, int, int]:
    table = Table(title=title)
    for col in ("server", "scope", "config", "status"):
        table.add_column(col)
    protected = unprotected = 0
    for _label, path in configs:
        try:
            servers = read_servers(path, all_projects=all_projects)
        except (OSError, ValueError) as e:
            table.add_row("-", "-", str(path), f"[red]unreadable: {e}[/red]")
            continue
        for entry in servers:
            if entry.url and not entry.command:
                status = "[yellow]remote: protect with kairoseki wrap --remote[/yellow]"
            elif entry.wrapped:
                status = "[green]🪨 protected[/green]"
                protected += 1
            else:
                status = "[red]not protected[/red]"
                unprotected += 1
            table.add_row(entry.name, entry.scope, str(path), status)
    return table, protected, unprotected


def cmd_wrap(a: argparse.Namespace) -> int:
    configs = [("--config", Path(c)) for c in a.config] if a.config else candidate_configs()
    if not configs:
        err.print("No MCP client config found. Pass --config FILE.")
        return 2
    changed_any = False
    for _label, path in configs:
        if a.undo:
            changed = unwrap_config(path, all_projects=a.all_projects)
        else:
            changed = wrap_config(path, a.policy, a.only, all_projects=a.all_projects, remote=a.remote)
        changed_any |= bool(changed)
        verb = "unwrapped" if a.undo else "wrapped"
        if changed:
            console.print(f"[green]{verb}[/green] {', '.join(changed)} in {path}")
    table, protected, unprotected = _protection_table(configs, a.all_projects, "MCP servers after this change")
    console.print(table)
    console.print(f"{protected} protected, {unprotected} not protected.")
    if changed_any:
        console.print("Restart your MCP client so it picks up the new commands.")
    if os.name == "nt":
        console.print(
            "[dim]Windows: to upgrade Kairoseki later, close your MCP client first. "
            "uv cannot replace kairoseki.exe while a client is running it (os error 32).[/dim]"
        )
    return 0


# ---------------------------------------------------------------------------- hooks
def cmd_hook(a: argparse.Namespace) -> int:
    from .hooks import run_hook

    return run_hook()


def cmd_hooks(a: argparse.Namespace) -> int:
    from .hooks import install, installed, settings_path

    path = settings_path(a.scope)
    if a.action == "status":
        state = "[green]🪨 installed[/green]" if installed(path) else "[red]not installed[/red]"
        console.print(f"Claude Code built-in tools ({a.scope}, {path}): {state}")
        return 0
    changed = install(path, undo=a.action == "uninstall")
    if not changed:
        console.print(f"Nothing to do: hooks already {'absent from' if a.action == 'uninstall' else 'in'} {path}")
        return 0
    if a.action == "uninstall":
        console.print(f"[green]Removed[/green] Kairoseki hooks from {path}")
    else:
        console.print(
            f"[green]Installed[/green] Kairoseki hooks in {path}\n"
            "Bash, WebFetch, WebSearch, Read and Grep now share taint with your wrapped MCP servers.\n"
            "Restart Claude Code (or run /hooks) to load them."
        )
    return 0


# ---------------------------------------------------------------------------- den den mushi
def cmd_denden(a: argparse.Namespace) -> int:
    import secrets

    from .denden import ask

    if a.action == "setup":
        topic = f"kairoseki-{secrets.token_urlsafe(12)}"
        console.print(
            "🐌 Den Den Mushi: approve risky calls from your phone.\n\n"
            "1. Install the free ntfy app (iOS / Android) and subscribe to this topic:\n"
            f"   [bold]{topic}[/bold]\n"
            f"2. Add this to your kairoseki.yaml ({home_dir() / 'kairoseki.yaml'}, or run `kairoseki init`):\n\n"
            f"denden:\n  topic: {topic}\n  url: https://ntfy.sh\n\n"
            "3. Ring it: kairoseki denden test\n\n"
            "[dim]Keep the topic secret: anyone who knows it can answer. Only server, tool and reason are sent.[/dim]"
        )
        return 0
    policy = load_policy(a.policy)
    if policy.denden is None:
        err.print("No `denden:` section in your policy. Run: kairoseki denden setup")
        return 2
    console.print(f"Ringing {policy.denden.url}/{policy.denden.topic} ... tap Approve or Deny (60s).")
    answer = ask(policy.denden, "test", "ring", ["this is a test from `kairoseki denden test`"], "K-TEST00", 60)
    console.print(
        {True: "[green]Approved[/green] ✓", False: "[red]Denied[/red] ✓", None: "[yellow]No answer[/yellow]"}[answer]
    )
    return 0 if answer is not None else 1


# ---------------------------------------------------------------------------- attack
def cmd_attack(a: argparse.Namespace) -> int:
    from .lab.attack import run_lab
    from .lab.badge import render_badge

    if a.policy:
        try:
            load_policy(a.policy)
        except PolicyError as e:
            err.print(f"[red]kairoseki: {e}[/red]")
            return 2
    spinner = console.status("Replaying attacks against a fully hijacked agent...")
    with contextlib.nullcontext() if console.record or a.json else spinner:
        report = run_lab(policy=a.policy, mode=a.mode, baseline=not a.no_baseline, only=a.only)
    if a.json:
        print(json.dumps(report.to_json(), indent=2))
    else:
        table = Table(title="Kairoseki attack lab", show_lines=False)
        for col in ("", "scenario", "result", "stopped by"):
            table.add_column(col)
        base = {r.scenario.id: r for r in report.baseline}
        for r in report.results:
            kind = "⚔️" if r.scenario.kind == "attack" else "🧭"
            if r.error:
                status = f"[red]error: {r.error}[/red]"
            elif r.scenario.kind == "attack":
                status = "[green]blocked[/green]" if r.passed else "[red]LEAKED[/red]"
                if r.scenario.id in base:
                    status += (
                        " [dim](leaks without kairoseki)[/dim]"
                        if base[r.scenario.id].leaked
                        else " [dim](baseline did not leak)[/dim]"
                    )
            else:
                status = (
                    "[green]allowed[/green]" if r.passed else f"[yellow]interrupted at step {r.blocked_steps}[/yellow]"
                )
            table.add_row(
                kind, f"{r.scenario.title}\n[dim]{r.scenario.reference}[/dim]", status, ", ".join(r.rules) or "-"
            )
        console.print(table)
        console.print(
            f"\n[bold]Grade {report.grade}[/bold]: {report.blocked}/{len(report.attacks)} attacks blocked, "
            f"{report.benign_ok}/{len(report.benign)} normal tasks uninterrupted ({report.seconds:.1f}s)."
        )
    if a.badge:
        Path(a.badge).write_text(render_badge(report.grade, report.blocked, len(report.attacks)), encoding="utf-8")
        if not a.json:
            console.print(f"Badge written to {a.badge}")
    failed = any(r.error for r in report.results) or report.blocked < len(report.attacks)
    return 1 if failed else 0


# ---------------------------------------------------------------------------- approvals & pins
def cmd_approve(a: argparse.Namespace) -> int:
    store = Approvals()
    if not a.id:
        pending = store.list("pending")
        if not pending:
            console.print("No pending approvals.")
            return 0
        table = Table(title="Pending approvals")
        for col in ("id", "server", "tool", "why", "arguments"):
            table.add_column(col)
        for item in pending:
            table.add_row(
                item["id"],
                item["server"],
                item["tool"],
                "; ".join(item.get("reasons", [])),
                item.get("arguments_preview", ""),
            )
        console.print(table)
        return 0
    approved = store.approve(a.id)
    if approved is None:
        err.print(f"[red]No approval request {a.id}.[/red]")
        return 1
    console.print(
        f"[green]Approved[/green] {approved['server']}.{approved['tool']} once "
        f"(valid for {int(load_policy(a.policy).approval_ttl)}s). Ask the agent to retry."
    )
    return 0


def cmd_pins(a: argparse.Namespace) -> int:
    if a.action == "list":
        stores = all_pin_stores()
        if not stores:
            console.print("No pinned servers yet.")
        for name, store in stores:
            pending = store.pending()
            status = f"[red]{len(pending)} changed: {', '.join(pending)}[/red]" if pending else "[green]ok[/green]"
            console.print(f"{name}: {status}")
        return 0
    if not a.server:
        err.print("pass a server name")
        return 2
    store = PinStore(a.server)
    if a.action == "approve":
        approved = store.approve(a.tool)
        console.print(f"Re-pinned: {', '.join(approved) or 'nothing pending'}")
    else:
        store.reset()
        console.print(f"Forgot all pins for {a.server}.")
    return 0


# ---------------------------------------------------------------------------- misc
def cmd_init(a: argparse.Namespace) -> int:
    path = Path(a.path)
    if path.exists() and not a.force:
        err.print(f"{path} already exists (use --force to overwrite)")
        return 1
    path.write_text(DEFAULT_POLICY_YAML, encoding="utf-8")
    console.print(f"Wrote {path}")
    return 0


def cmd_log(a: argparse.Namespace) -> int:
    events = Audit().tail(a.n)
    if a.json:
        for e in events:
            print(json.dumps(e))
        return 0
    if not events:
        console.print(f"No events yet in {home_dir() / 'audit.jsonl'}")
        return 0
    colors = {
        "deny": "red",
        "ask": "yellow",
        "rug_pull": "red",
        "poisoned_tool": "red",
        "injection_detected": "yellow",
        "redacted": "cyan",
        "approved": "green",
        "declined": "red",
    }
    for e in events:
        when = dt.datetime.fromtimestamp(e.get("ts", 0)).strftime("%H:%M:%S")
        kind = e.get("action") or e.get("event", "")
        color = colors.get(kind, colors.get(e.get("event", ""), "white"))
        detail = e.get("rule") or ", ".join(e.get("patterns", []) or e.get("kinds", [])) or e.get("detail", "")
        reasons = "; ".join(e.get("reasons", []))
        console.print(
            f"[dim]{when}[/dim] [{color}]{kind:<18}[/{color}] {e.get('server')}.{e.get('tool', '-')} "
            f"{detail} [dim]{reasons}[/dim]"
        )
    return 0


def cmd_status(a: argparse.Namespace) -> int:
    from .session_id import session_alive

    configs = candidate_configs()
    if configs:
        table, protected, unprotected = _protection_table(configs, a.all_projects, "Protection")
        console.print(table)
        console.print(
            f"{protected} protected, {unprotected} not protected. Protect them with: kairoseki wrap\n"
            if unprotected
            else f"{protected} protected.\n"
        )
    folder = home_dir() / "sessions"
    files = sorted(folder.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True) if folder.is_dir() else []
    sessions = []
    for path in files:
        if path.name.endswith(".tmp") or ".json." in path.name:
            continue
        data: dict[str, Any] = Session(path.stem).snapshot() or {}
        if data:
            sessions.append((path.stem, data, session_alive(path.stem)))
    shown = [s for s in sessions if s[2] is not False] if not a.all else sessions
    if not shown:
        console.print("No active sessions." + (" Use --all to see ended ones." if sessions else ""))
        return 0
    for sid, data, alive in shown[: a.n]:
        state = {True: "[green]● active[/green]", False: "[dim]○ ended[/dim]", None: "[dim]? unknown[/dim]"}[alive]
        untrusted = {f"{x['server']}.{x['tool']}" for x in data.get("untrusted", [])}
        private = {f"{x['server']}.{x['tool']}" for x in data.get("private", [])}
        console.print(
            f"[bold]{sid}[/bold] {state}\n  untrusted: {', '.join(sorted(untrusted)) or '-'}\n"
            f"  private:   {', '.join(sorted(private)) or '-'}\n"
            f"  secrets fingerprinted: {sum(len(v) for v in (data.get('secret_index') or {}).values())}"
        )
    hidden = len(sessions) - len(shown)
    if hidden:
        console.print(f"[dim]{hidden} ended session(s) hidden; use --all to show them.[/dim]")
    return 0


def cmd_session(a: argparse.Namespace) -> int:
    from .session_id import client_session_id
    from .store import default_session_id

    trace: list[str] = []
    detected = client_session_id(trace)
    print(f"session: {default_session_id()}")
    if os.environ.get("KAIROSEKI_SESSION"):
        print("(forced with KAIROSEKI_SESSION)")
    if a.explain:
        print(f"detected from the process tree: {detected}")
        for line in trace:
            print(f"  {line}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kairoseki", description="🪨 Seastone for your AI agents: an MCP firewall.")
    p.add_argument("--version", action="version", version=f"kairoseki {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run an MCP server behind Kairoseki (use this in your client config)")
    r.add_argument("--name", help="server name used in policy, logs and pins (default: command name)")
    r.add_argument(
        "--policy", help="policy YAML (default: $KAIROSEKI_POLICY, ./kairoseki.yaml, ~/.kairoseki/kairoseki.yaml)"
    )
    r.add_argument("--mode", choices=["monitor", "balanced", "strict"], help="override the policy mode")
    r.add_argument("--verbose", action="store_true", help="log decisions to stderr")
    r.add_argument("command", nargs=argparse.REMAINDER, help="-- <server command> [args...]")
    r.set_defaults(func=cmd_run)

    s = sub.add_parser("scan", help="list your MCP tools by trifecta leg and find poisoned descriptions")
    s.add_argument("--config", action="append", help="client config file (default: auto-detect)")
    s.add_argument("--timeout", type=float, default=20.0)
    s.add_argument("--all-projects", action="store_true", help="include Claude Code local servers of every project")
    s.add_argument("--share", metavar="CARD.svg", help="write a shareable report card (counts only, no paths)")
    s.add_argument("--json", action="store_true", help="machine-readable output")
    s.add_argument("command", nargs=argparse.REMAINDER, help="optional: -- <server command> to scan one server")
    s.set_defaults(func=cmd_scan)

    w = sub.add_parser("wrap", help="route the servers in your client config through Kairoseki")
    w.add_argument("--config", action="append", help="client config file (default: auto-detect)")
    w.add_argument("--policy", help="policy file to pin in the wrapped commands")
    w.add_argument("--only", action="append", help="only wrap these server names")
    w.add_argument("--undo", action="store_true", help="restore the original commands")
    w.add_argument(
        "--remote", action="store_true", help="also bridge remote (HTTP/SSE) servers through mcp-remote (needs Node.js)"
    )
    w.add_argument("--all-projects", action="store_true", help="include Claude Code local servers of every project")
    w.set_defaults(func=cmd_wrap)

    hk = sub.add_parser("hook", help="handle one Claude Code hook event on stdin (used by `kairoseki hooks install`)")
    hk.set_defaults(func=cmd_hook)

    hs = sub.add_parser("hooks", help="protect Claude Code's built-in tools (Bash, WebFetch, Read...) with hooks")
    hs.add_argument("action", choices=["install", "uninstall", "status"])
    hs.add_argument(
        "--scope", choices=["user", "project", "local"], default="user", help="which Claude Code settings file"
    )
    hs.set_defaults(func=cmd_hooks)

    dd = sub.add_parser("denden", help="🐌 Den Den Mushi: approve risky calls from your phone (ntfy)")
    dd.add_argument("action", choices=["setup", "test"])
    dd.add_argument("--policy")
    dd.set_defaults(func=cmd_denden)

    at = sub.add_parser("attack", help="replay real-world MCP attacks against Kairoseki and grade it")
    at.add_argument("--policy", help="policy YAML to test")
    at.add_argument("--mode", choices=["monitor", "balanced", "strict"])
    at.add_argument("--badge", help="write an SVG badge with the grade to this path")
    at.add_argument("--json", action="store_true", help="machine-readable output")
    at.add_argument("--only", action="append", help="run only these scenario ids")
    at.add_argument("--no-baseline", action="store_true", help="skip the unprotected baseline run")
    at.set_defaults(func=cmd_attack)

    ap = sub.add_parser("approve", help="list pending approvals, or approve one: kairoseki approve K-XXXXXX")
    ap.add_argument("id", nargs="?")
    ap.add_argument("--policy")
    ap.set_defaults(func=cmd_approve)

    pn = sub.add_parser("pins", help="manage trust-on-first-use tool pins")
    pn.add_argument("action", choices=["list", "approve", "reset"])
    pn.add_argument("server", nargs="?")
    pn.add_argument("tool", nargs="?")
    pn.set_defaults(func=cmd_pins)

    i = sub.add_parser("init", help="write a commented kairoseki.yaml")
    i.add_argument("path", nargs="?", default="kairoseki.yaml")
    i.add_argument("--force", action="store_true")
    i.set_defaults(func=cmd_init)

    lg = sub.add_parser("log", help="show recent decisions")
    lg.add_argument("-n", type=int, default=30)
    lg.add_argument("--json", action="store_true")
    lg.set_defaults(func=cmd_log)

    st = sub.add_parser("status", help="show what each session has been exposed to")
    st.add_argument("-n", type=int, default=5)
    st.add_argument("--all", action="store_true", help="also show sessions whose client has exited")
    st.add_argument("--all-projects", action="store_true", help="include Claude Code local servers of every project")
    st.set_defaults(func=cmd_status)

    se = sub.add_parser("session", help="show which session this process joins (all servers of a client share one)")
    se.add_argument("--explain", action="store_true", help="show the process-tree walk")
    se.set_defaults(func=cmd_session)
    return p


def main(argv: list[str] | None = None) -> int:
    if os.name == "nt":
        for stream in (sys.stdout, sys.stderr):
            reconfigure = getattr(stream, "reconfigure", None)
            if reconfigure:
                reconfigure(encoding="utf-8")
    args = build_parser().parse_args(argv)
    return int(args.func(args))
