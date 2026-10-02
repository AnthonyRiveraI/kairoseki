"""Render the 'Kairoseki Score' README badge as a standalone SVG."""

from __future__ import annotations

from html import escape

_COLORS = {"A+": "#2ea043", "A": "#3fb950", "B": "#d29922", "C": "#db6d28", "D": "#f85149", "F": "#b62324"}


def _width(text: str) -> int:
    return 7 * len(text) + 12  # monospace, 11px font


def render_badge(grade: str, blocked: int, total: int) -> str:
    left = "🪨 kairoseki"
    right = f"{grade} · {blocked}/{total} attacks blocked"
    lw, rw = _width(left) + 4, _width(right)
    w, h = lw + rw, 20
    color = _COLORS.get(grade, "#8b949e")
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" role="img" '
        f'aria-label="{escape(left)}: {escape(right)}" shape-rendering="crispEdges">'
        f"<title>{escape(left)}: {escape(right)}</title>"
        f'<rect width="{lw}" height="{h}" fill="#0b1026"/>'
        f'<rect x="{lw}" width="{rw}" height="{h}" fill="{color}"/>'
        f'<rect y="{h - 2}" width="{w}" height="2" fill="#000" opacity=".25"/>'
        f'<g font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="11" fill="#fff">'
        f'<text x="6" y="14" fill="#f2c94c">{escape(left)}</text>'
        f'<text x="{lw + 6}" y="14">{escape(right)}</text></g></svg>\n'
    )
