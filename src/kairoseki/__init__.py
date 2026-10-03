"""Kairoseki: seastone for your AI agents. An MCP firewall that breaks the lethal trifecta."""

from typing import Any

__version__ = "0.2.2"
__all__ = ["Guard", "KairosekiBlocked", "__version__"]


def __getattr__(name: str) -> Any:
    # lazy, so the CLI doesn't import the engine just to print its version
    if name in ("Guard", "KairosekiBlocked"):
        from . import guard

        return getattr(guard, name)
    raise AttributeError(name)
