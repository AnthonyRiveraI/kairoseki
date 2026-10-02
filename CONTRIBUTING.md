# Contributing

Thanks for helping make agents harder to hijack! 🪨

## Setup

```bash
git clone https://github.com/AnthonyRiveraI/kairoseki
cd kairoseki
uv sync --group dev
uv run pytest
uv run ruff check src tests && uv run mypy
```

## Add an attack scenario (the best first contribution)

1. Find a real, public write-up of an MCP or prompt-injection attack.
2. Add a `Scenario` to `src/kairoseki/lab/scenarios.py`:
   * `world`: the content the lab servers will serve (issues, pages, files, inbox, notes, shell outputs)
   * `steps`: the calls a fully hijacked agent would make. Use `{out:N}`, `{grep:N:REGEX}` or `{b64grep:N:REGEX}`
     to reuse what the agent saw at step N.
   * `canary` and `exfil_points`: what must not reach which tool
   * `reference`: credit the original researchers
3. If you need a new kind of server, add a role in `src/kairoseki/lab/server.py`.
4. Run `uv run kairoseki attack --only <your-id>`. The baseline (without Kairoseki) **must leak**, otherwise the
   scenario proves nothing. `tests/test_lab.py` enforces this.

If your scenario leaks *with* Kairoseki, you found a bypass. Please report it privately first (see `SECURITY.md`).

## Fix a false positive

Add the tool name to `tests/test_labels.py` with the labels you expect, then adjust `src/kairoseki/labels.py`.

## Pull requests

* Keep PRs focused, with tests.
* `ruff`, `mypy --strict` and `pytest` must pass. CI runs Linux, macOS and Windows, Python 3.10 and 3.13,
  and MCP SDK 1.x and 2.x.
