"""Kairoseki as a library: guard the Python tools of any agent framework.

```python
from kairoseki import Guard

guard = Guard()

@guard.tool()                       # labels inferred from the name/docstring, or pass labels={"sink"}
def send_email(to: str, body: str) -> str: ...
```

Each call is decided like an MCP tool call (deny / ask / allow) and each result updates the
session taint, redacting secrets in string or MCP-shaped results. The wrapper keeps the function's
name, docstring and signature, so it can sit *under* a framework decorator (Claude Agent SDK
``@tool``, OpenAI Agents SDK ``@function_tool``, LangChain ``@tool``...).

A Guard sets ``KAIROSEKI_SESSION`` for its process, so MCP servers this agent starts through
``kairoseki run`` share the same taint as its Python tools.
"""

from __future__ import annotations

import functools
import inspect
import json
import os
import uuid
from collections.abc import Callable
from typing import Any, TypeVar

from .engine import ALLOW, ASK, Decision, Engine
from .labels import classify
from .policy import Policy, load_policy
from .store import Approvals, Audit, Session

F = TypeVar("F", bound=Callable[..., Any])


class KairosekiBlocked(PermissionError):
    """Raised instead of running a tool call Kairoseki denied (or that needed an approval it didn't get)."""

    def __init__(self, tool: str, decision: Decision) -> None:
        self.tool, self.decision = tool, decision
        super().__init__(f"🪨 Kairoseki blocked '{tool}' ({decision.rule}): " + "; ".join(decision.reasons))


class Guard:
    def __init__(
        self,
        name: str = "agent",
        policy: Policy | str | None = None,
        session_id: str | None = None,
        on_ask: Callable[[str, Decision], bool] | None = None,
        share_session: bool = True,
    ) -> None:
        """``on_ask(tool, decision) -> bool`` approves or refuses an *ask*; without it, Den Den Mushi is used
        if the policy configures it, otherwise the call is refused."""
        self.policy = policy if isinstance(policy, Policy) else load_policy(policy)
        self.session_id = session_id or os.environ.get("KAIROSEKI_SESSION") or f"guard-{uuid.uuid4().hex[:12]}"
        if share_session:
            os.environ["KAIROSEKI_SESSION"] = self.session_id
        self.engine = Engine(name, self.policy, Session(self.session_id), approvals=Approvals(), audit=Audit())
        self.on_ask = on_ask

    # ------------------------------------------------------------------ decisions
    def check(self, tool: str, arguments: dict[str, Any]) -> None:
        """Raise :class:`KairosekiBlocked` unless the call may run."""
        decision = self.engine.decide(tool, arguments)
        if decision.action == ALLOW or (decision.action == ASK and self._approve(tool, decision)):
            return
        raise KairosekiBlocked(tool, decision)

    def _approve(self, tool: str, decision: Decision) -> bool:
        if self.on_ask is not None:
            approved = bool(self.on_ask(tool, decision))
        elif self.policy.denden is not None:
            from .denden import ask

            approval_id = self.engine.approvals.request(self.engine.server, tool, {}, decision.reasons)
            approved = bool(
                ask(
                    self.policy.denden,
                    self.engine.server,
                    tool,
                    decision.reasons,
                    approval_id,
                    self.policy.approval_timeout,
                )
            )
        else:
            return False
        self.engine._log("approved" if approved else "declined", tool=tool, via="guard")
        return approved

    def observe(self, tool: str, result: Any) -> Any:
        """Update taint from a tool result; returns it with secrets redacted when it is text or MCP-shaped."""
        if isinstance(result, str):
            out = self.engine.on_tool_result(tool, {"content": [{"type": "text", "text": result}]})
            return "".join(block["text"] for block in out["content"])  # the warning block ends with a blank line
        if isinstance(result, dict) and isinstance(result.get("content"), list):
            return self.engine.on_tool_result(tool, result)
        text = json.dumps(result, default=str)
        self.engine.on_tool_result(tool, {"content": [{"type": "text", "text": text}]})
        return result

    @staticmethod
    def tool_error(ctx: Any, error: Exception) -> str:
        """Error text for the model, e.g. ``@function_tool(failure_error_function=guard.tool_error)``.

        Some frameworks (OpenAI Agents SDK) replace tool exceptions with "An error occurred... Please try
        again", which hides why the call was blocked and invites a retry.
        """
        if isinstance(error, KairosekiBlocked):
            return f"{error} Do not retry this call; tell the user what you were trying to do."
        return f"An error occurred while running the tool: {error}"

    # ------------------------------------------------------------------ decorator
    def tool(self, labels: set[str] | None = None, name: str | None = None) -> Callable[[F], F]:
        def decorate(fn: F) -> F:
            tool_name = name or fn.__name__
            if labels is not None:
                self.engine.labels[tool_name] = set(labels)
            elif self.policy.explicit_labels(self.engine.server, tool_name) is None:
                self.engine.labels[tool_name] = classify({"name": tool_name, "description": fn.__doc__ or ""})
            signature = inspect.signature(fn)

            def arguments(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
                try:
                    bound = signature.bind_partial(*args, **kwargs)
                except TypeError:
                    return {"args": list(args), **kwargs}
                return dict(bound.arguments)

            if inspect.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    self.check(tool_name, arguments(args, kwargs))
                    return self.observe(tool_name, await fn(*args, **kwargs))

                return async_wrapper  # type: ignore[return-value]

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                self.check(tool_name, arguments(args, kwargs))
                return self.observe(tool_name, fn(*args, **kwargs))

            return wrapper  # type: ignore[return-value]

        return decorate
