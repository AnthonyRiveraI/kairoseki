<p align="center">
  <img src="docs/assets/banner.svg" width="100%" alt="Kairoseki - seastone for your AI agents" />
</p>

<p align="center"><b>English</b> · <a href="README.es.md">Español</a></p>

<p align="center">
  <a href="https://github.com/AnthonyRiveraI/kairoseki/actions/workflows/ci.yml"><img src="https://github.com/AnthonyRiveraI/kairoseki/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <img src="https://img.shields.io/badge/version-0.1.0-0b1026?labelColor=0b1026" alt="Version 0.1.0" />
  <img src="https://img.shields.io/badge/python-3.10%20%E2%86%92%203.13-0b1026?labelColor=0b1026" alt="Python" />
  <img src="https://img.shields.io/badge/MCP-2024--11%20%E2%86%92%202026--07-0b1026?labelColor=0b1026" alt="MCP versions" />
  <img src="docs/assets/score.svg" alt="Kairoseki score" />
</p>

<p align="center">
  <b>An MCP firewall that stops prompt-injection data theft by tracking <i>where data came from</i>,<br/>
  not by guessing what attacks look like.</b>
</p>

---

In One Piece, **kairoseki** (seastone) cancels Devil Fruit powers. Kairoseki does the same for your agent's
most dangerous power: reading something an attacker wrote, and then quietly sending your data somewhere.

```bash
uv tool install git+https://github.com/AnthonyRiveraI/kairoseki
kairoseki scan              # what can a single prompt injection do with your MCP setup?
kairoseki wrap              # put every MCP server in your Claude / Cursor / VS Code config behind Kairoseki
kairoseki attack            # replay 9 real-world attacks against your setup and get a grade
```

<p align="center"><img src="docs/assets/attack.svg" width="92%" alt="kairoseki attack: 9 of 9 real-world attacks blocked, 7 of 7 normal tasks uninterrupted" /></p>

## Why

An agent is exploitable **by design** when it has all three legs of the
[lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/):

1. **access to private data** (your files, repos, inbox),
2. **exposure to untrusted content** (a web page, a GitHub issue, an email), and
3. **a way to send data out** (HTTP, email, a comment, a pull request).

Plug a filesystem server and a fetch server into Claude Code, Cursor or Claude Desktop and you have all three.
This keeps happening in the real world:

| Incident | What happened |
| :-- | :-- |
| [GitHub MCP exploit](https://invariantlabs.ai/blog/mcp-github-vulnerability) (May 2025) | A malicious public issue made an agent copy private repo data into a public pull request |
| [Tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) (Apr 2025) | Hidden instructions in a tool *description* stole `~/.cursor/mcp.json` |
| [MCPoison, CVE-2025-54136](https://nvd.nist.gov/vuln/detail/CVE-2025-54136) (Jul 2025) | An approved MCP config was silently swapped later (rug pull) |
| [Comment and Control](https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/) (Apr 2026) | Injections in PR titles and comments made Claude Code, Gemini CLI and Copilot agents leak their own secrets |

Most defenses scan text for attack patterns, and attackers just rephrase. Kairoseki breaks the trifecta instead.
The idea is inspired by [CaMeL](https://arxiv.org/abs/2503.18813) (Google DeepMind): track taint across the
whole session and step in exactly when untrusted content, private data and an outbound channel meet.

## What it does

| | |
| :-- | :-- |
| 🔗 **Session taint across servers** | Every `kairoseki run` in one agent session shares state. The web page comes from the `fetch` server, the secret from `filesystem`, the leak goes through `github`: Kairoseki still sees one chain. |
| 🧪 **Secret fingerprints** | Secrets seen in tool output or in a server's environment are fingerprinted (never stored). If one shows up in a later tool call, even base64, hex, URL-encoded or reversed, the call is denied. |
| 🫥 **Redaction** | API keys, tokens and private keys are replaced with `[REDACTED:kind]` before they reach the model. The model can't leak what it never saw. |
| ☠️ **Poisoned tool detection** | Tool descriptions and schemas with injection text, ANSI escapes or invisible Unicode are neutralized before the model reads them, and the tool is blocked. |
| 📌 **Rug-pull pins** | Tool definitions are pinned on first use. If a server changes one later, that tool is blocked until you re-approve it. |
| ✋ **Approvals that fit your client** | When the trifecta closes, Kairoseki asks *you*: an in-client prompt (MCP elicitation, in both protocol eras), or a one-time `kairoseki approve K-1A2B3C` from any terminal. |
| ⚔️ **Attack lab and badge** | `kairoseki attack` replays real attacks against a *fully hijacked* agent and checks, on the attacker's side, whether the canary leaked. |
| 🔍 **Scanner** | `kairoseki scan` labels every tool in your config and tells you if you already have the lethal trifecta. |

It is a transparent stdio proxy that speaks raw JSON-RPC, so it works with any MCP server and client, in
both the handshake era (`initialize`, 2024-11-05 → 2025-11-25) and the modern era (`server/discover`,
2026-07-28). Two dependencies: `pyyaml` and `rich`.

<p align="center"><img src="docs/assets/scan.svg" width="80%" alt="kairoseki scan finds a poisoned tool and the lethal trifecta in a real config" /></p>

## Quickstart

### 0. Prerequisites

| You need | Why | How to get it |
| :-- | :-- | :-- |
| **[uv](https://docs.astral.sh/uv/)** (recommended) or **pipx** | Installs Kairoseki as an isolated command-line tool | macOS / Linux: `curl -LsSf https://astral.sh/uv/install.sh \| sh`<br/>Windows (PowerShell): `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 \| iex"` |
| **Python 3.10+** | Kairoseki is written in Python | uv downloads a suitable Python automatically if you don't have one. With pipx, install Python yourself. |
| **Git** | To install straight from GitHub | [git-scm.com](https://git-scm.com/downloads) |
| **An MCP client** | Something to protect | Claude Code, Claude Desktop, Cursor, VS Code, Windsurf... |
| **Node.js** *(optional)* | Only if your MCP servers start with `npx` | [nodejs.org](https://nodejs.org/) |

### 1. Install

Kairoseki is not on PyPI yet, so install it from GitHub:

```bash
uv tool install git+https://github.com/AnthonyRiveraI/kairoseki
# or with pipx:
pipx install git+https://github.com/AnthonyRiveraI/kairoseki
```

Then make sure the `kairoseki` command is on your `PATH`, and open a **new** terminal:

```bash
uv tool update-shell     # or: pipx ensurepath
kairoseki --version      # should print: kairoseki 0.1.0
```

> **`kairoseki: command not found`, or your MCP client can't start it?** The tool lives in `~/.local/bin`
> (`%USERPROFILE%\.local\bin` on Windows). Run `uv tool update-shell`, then fully restart your terminal **and**
> your MCP client so they pick up the new `PATH`. `kairoseki wrap` also writes the absolute path into your config,
> which avoids the problem entirely.

To update later: `uv tool upgrade kairoseki` (or `pipx upgrade kairoseki`).

### 2. See your exposure

```bash
kairoseki scan
```

It reads the MCP configs of Claude Desktop, Claude Code (`.mcp.json`, `~/.claude.json`), Cursor, Windsurf and
VS Code, starts each server, and labels every tool as `private`, `untrusted`, `sink` and/or `destructive`.

### 3. Wrap your servers

```bash
kairoseki wrap            # all detected configs (a .kairoseki.bak backup is written first)
kairoseki wrap --undo     # restore
```

Or wrap a single server by hand. Every client uses the same pattern, `kairoseki run --name <name> -- <original command>`:

```jsonc
{
  "mcpServers": {
    "fetch": {
      "command": "kairoseki",
      "args": ["run", "--name", "fetch", "--", "uvx", "mcp-server-fetch"]
    }
  }
}
```

With Claude Code:

```bash
claude mcp add fetch -- kairoseki run --name fetch -- uvx mcp-server-fetch
```

Restart your client and check that the server connects (with Claude Code: `claude mcp get fetch`). That's it.

### 4. Try to break it

```bash
kairoseki attack                        # grade your current policy
kairoseki attack --badge kairoseki.svg  # and get a README badge
```

## How decisions are made

```mermaid
flowchart LR
    A[tool call] --> B{denied by policy,<br/>poisoned or rug-pulled?}
    B -- yes --> X[⛔ deny]
    B -- no --> C{arguments contain a<br/>secret seen this session?}
    C -- yes --> X
    C -- no --> D{session saw untrusted content<br/>AND private data<br/>AND this tool is a sink?}
    D -- yes --> Q[✋ ask the user]
    D -- no --> E{untrusted content seen AND private data<br/>flows into an unclassified tool?}
    E -- yes --> Q
    E -- no --> OK[✅ forward to the server]
    OK --> R[result: sanitize, redact,<br/>fingerprint secrets, update taint]
```

| Mode | Behaviour |
| :-- | :-- |
| `monitor` | Never blocks. Logs what would have happened (redaction still applies). Good for your first week. |
| `balanced` *(default)* | Denies exfiltration, poisoned tools and rug pulls. Asks before the lethal trifecta closes. |
| `strict` | Also asks before **any** sink or destructive tool once untrusted content entered the session. |

When Kairoseki asks:

* **In-client prompt.** If your client supports MCP elicitation, you get an "Allow this call once?" form.
  Kairoseki sends `elicitation/create` in the handshake era and an `input_required` result (SEP-2322) in the 2026-07-28 era.
* **Terminal.** Otherwise the agent gets a clear refusal with an id. Run `kairoseki approve K-1A2B3C`, then ask the
  agent to retry. Approvals are single-use, bound to the exact arguments, and expire after 10 minutes.

Learn more in [docs/how-it-works.md](docs/how-it-works.md).

## Policy

```bash
kairoseki init   # writes a commented kairoseki.yaml
```

```yaml
mode: balanced
redact:
  secrets: true
  pii: false
servers:
  github:
    tools:
      create_or_update_file: [sink, destructive]  # explicit labels replace the heuristics
    allow: [search_repositories]                  # never ask (redaction still applies)
    deny: [delete_repository]                     # always block
```

Kairoseki looks for `--policy`, then `$KAIROSEKI_POLICY`, then `./kairoseki.yaml`, then `~/.kairoseki/kairoseki.yaml`.

## Other commands

```bash
kairoseki log             # recent decisions, redactions and detections
kairoseki status          # what each session has been exposed to
kairoseki approve         # list pending approvals
kairoseki pins list       # servers whose tools changed since you pinned them
kairoseki pins approve github
```

## How it compares

| | Kairoseki | Pattern scanners / guardrail models | [mcp-context-protector](https://github.com/trailofbits/mcp-context-protector) | Enterprise MCP gateways |
| :-- | :--: | :--: | :--: | :--: |
| Blocks rephrased or novel injections (data-flow based) | ✅ | ❌ | ❌ | ➖ |
| Taint shared across servers in one session | ✅ | ❌ | ❌ | ➖ |
| Detects encoded secret exfiltration | ✅ | ➖ | ❌ | ➖ |
| Rug-pull pinning | ✅ | ❌ | ✅ | ✅ |
| Poisoned descriptions, ANSI, invisible Unicode | ✅ | ✅ | ✅ | ➖ |
| Runs locally, no service or API key | ✅ | ➖ | ✅ | ❌ |
| Measurable attack lab with a grade | ✅ | ❌ | ❌ | ❌ |

➖ = depends on the product. Kairoseki borrows trust-on-first-use pinning and ANSI sanitization from Trail of Bits'
excellent mcp-context-protector. The two are complementary.

## Limitations (please read)

* **It only sees MCP traffic.** Built-in client tools (for example Claude Code's own `Bash` or `WebFetch`) never go
  through MCP. Pair Kairoseki with your client's permission rules.
* **Labels are heuristics.** Tool names and descriptions are read as verb + object (`get_issue`, `send_email`).
  They can be wrong, and the [policy](#policy) lets you fix them. Server annotations can only *add* risk, never remove it.
* **Taint is per session and coarse on purpose.** Once untrusted content is in the context, Kairoseki assumes it may
  have influenced everything after it. That is what makes it robust, and it is why `strict` mode asks more often.
* **stdio servers only** in v0.1. Streamable HTTP servers are on the roadmap.
* **It is not a sandbox.** A malicious server binary can still do anything your user account can. Kairoseki protects
  against malicious *content*, not malicious *code*.

## Roadmap

- [ ] Publish on PyPI (`pipx install kairoseki`)
- [ ] Streamable HTTP transport
- [ ] 🐌 Den Den Mushi: Kairoseki *calls your phone* to approve risky actions
- [ ] OpenTelemetry export of decisions
- [ ] More attack scenarios. [Propose one!](https://github.com/AnthonyRiveraI/kairoseki/issues/new?template=attack-scenario.yml)

## Contributing

The most valuable contribution is a new **attack scenario**: a real write-up turned into a replayable test.
See [CONTRIBUTING.md](CONTRIBUTING.md). Found a bypass? Please [report it privately](SECURITY.md).

## License

MIT © Anthony Rivera
