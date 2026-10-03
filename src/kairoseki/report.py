"""Grade an MCP setup from a scan and render a shareable report card (``kairoseki scan --share``)."""

from __future__ import annotations

from dataclasses import dataclass, field
from html import escape

from .labels import PRIVATE, SINK, UNTRUSTED

_COLORS = {"A": "#3fb950", "B": "#d29922", "D": "#f85149", "F": "#b62324"}


@dataclass
class ScanResult:
    legs: dict[str, list[str]] = field(default_factory=lambda: {PRIVATE: [], UNTRUSTED: [], SINK: []})
    poisoned: list[str] = field(default_factory=list)
    servers: int = 0
    unprotected: list[str] = field(default_factory=list)  # stdio servers not behind kairoseki

    @property
    def trifecta(self) -> bool:
        return all(self.legs.values())

    @property
    def exposed(self) -> bool:
        """Is any server that contributes a trifecta leg reachable without Kairoseki?"""
        leg_servers = {t.split(".", 1)[0] for tools in self.legs.values() for t in tools}
        return bool(leg_servers & set(self.unprotected))

    @property
    def grade(self) -> str:
        if self.poisoned:
            return "F"  # one tool description is already an injection
        if self.trifecta and self.exposed:
            return "D"  # one prompt injection can steal data today
        return "B" if self.unprotected else "A"

    @property
    def verdict(self) -> str:
        return {
            "F": "poisoned tool descriptions found",
            "D": "lethal trifecta open: one injection can leak your data",
            "B": "no open trifecta, some servers unprotected",
            "A": "every server behind Kairoseki",
        }[self.grade]


def render_card(result: ScanResult) -> str:
    """A 600x315 SVG (the 1.91:1 social card ratio) summarizing the scan, safe to post anywhere.

    Only counts and leg names appear: no paths, commands, environment or tool arguments.
    """
    grade, color = result.grade, _COLORS[result.grade]
    rows = []
    for i, (leg, title) in enumerate(
        ((PRIVATE, "private data"), (UNTRUSTED, "untrusted content"), (SINK, "a way to send data out"))
    ):
        tools = result.legs[leg]
        mark, mark_color = ("●", "#f85149") if tools else ("○", "#3fb950")
        detail = f"{len(tools)} tool{'s' if len(tools) != 1 else ''}" if tools else "none"
        y = 150 + i * 30
        rows.append(
            f'<text x="40" y="{y}" fill="{mark_color}">{mark}</text>'
            f'<text x="62" y="{y}">{escape(title)}</text>'
            f'<text x="330" y="{y}" fill="#8b949e">{escape(detail)}</text>'
        )
    protected = result.servers - len(result.unprotected)
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="600" height="315" viewBox="0 0 600 315" role="img" '
        f'aria-label="Kairoseki MCP scan: grade {grade}, {escape(result.verdict)}">'
        f"<title>Kairoseki MCP scan: grade {grade}</title>"
        '<rect width="600" height="315" rx="16" fill="#0b1026"/>'
        f'<rect x="0" y="0" width="8" height="315" fill="{color}"/>'
        '<g font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" fill="#e6edf3">'
        '<text x="40" y="52" font-size="16" fill="#f2c94c">🪨 kairoseki scan</text>'
        '<text x="40" y="90" font-size="22" font-weight="bold">My MCP setup</text>'
        f'<text x="40" y="116" font-size="14" fill="{color}">{escape(result.verdict)}</text>'
        f'<text x="560" y="118" font-size="96" font-weight="bold" text-anchor="end" fill="{color}">{grade}</text>'
        f'<g font-size="15">{"".join(rows)}</g>'
        f'<text x="40" y="262" font-size="13" fill="#8b949e">{result.servers} servers · {protected} protected · '
        f"{len(result.poisoned)} poisoned tools</text>"
        '<text x="40" y="290" font-size="13">Check yours: <tspan fill="#f2c94c">uvx kairoseki scan</tspan></text>'
        "</g></svg>\n"
    )
