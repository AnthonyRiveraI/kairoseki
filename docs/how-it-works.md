# How Kairoseki works

## Threat model

Kairoseki assumes the **model is fully hijacked** as soon as attacker-controlled text enters its context.
It does not try to keep the model honest. It controls what a hijacked model can *do* with the tools it has.

In scope:

* Indirect prompt injection through tool output (web pages, issues, PRs, emails, documents)
* Tool poisoning: instructions hidden in tool descriptions or input schemas
* Rug pulls: a server changing a tool definition after you approved it
* Secret exfiltration through tool arguments, including simple encodings
* Hidden text: ANSI escape sequences, Unicode tag characters, zero-width and bidi controls

Out of scope:

* A malicious server *binary* (Kairoseki is not a sandbox)
* Client built-in tools that don't use MCP (e.g. Claude Code's `Bash`, `WebFetch`)
* Remote (Streamable HTTP) servers in v0.1
* Server-initiated `sampling/createMessage` and `elicitation/create` requests, which are passed through
  unchanged in v0.1 (your client shows those to you before acting)

## Architecture

```
MCP client ──stdio──▶ kairoseki run ──stdio──▶ real MCP server
 (Claude,              │  engine.py  decisions
  Cursor, …)           │  labels.py  trifecta labels
                       │  detect.py  sanitize / injection / secrets
                       ▼
                 ~/.kairoseki/
                   sessions/<id>.json   shared taint (+ secret fingerprints)
                   pins/<server>.json   tool definition pins
                   approvals/K-*.json   one-time approvals
                   audit.jsonl          every decision
```

The proxy reads newline-delimited JSON-RPC and forwards everything it doesn't need to inspect untouched,
including protocol features it doesn't know about. Only three things are inspected:

| Message | What happens |
| :-- | :-- |
| `tools/list` result | Pin definitions (rug pulls), strip hidden text, neutralize poisoned tools, label tools |
| `tools/call` request | Decide allow / ask / deny |
| `tools/call` and `resources/read` results | Sanitize, redact, fingerprint secrets, update session taint |

## Labels

Each tool gets zero or more labels:

* `private`: returns the user's own data (files, repos, inbox, databases)
* `untrusted`: returns content a third party can write (web, issues, PRs, comments, email)
* `sink`: can move data out (HTTP, email, messages, comments, pull requests, push)
* `destructive`: changes state

Labels come from the policy if you set them, otherwise from heuristics that read the tool name as *verb + object*
(`get_issue` → read + untrusted object; `create_pull_request` → write + public object = sink), its description,
and MCP annotations. Annotations come from the server, which may be malicious, so they can only add labels.

Network verbs (`fetch`, `browse`, `navigate`, `download`) are both `untrusted` and `sink`: the response is
attacker-controlled, and the URL itself is an exfiltration channel.

## Session taint

All proxies started by the same agent share one session file. The session id is the **MCP client process**
(its pid plus its start time, which guards against pid reuse on Linux, macOS and Windows). Kairoseki finds it by
walking up the process tree and skipping its own launch chain: `kairoseki` launchers, `uv`/`uvx`, and processes
running Kairoseki's own Python interpreter. That matters on Windows, where `uv tool install` puts
`kairoseki.exe → python.exe (venv redirector) → python.exe` between the client and every server, so the direct
parent is different for each server. You can force a session with `KAIROSEKI_SESSION`. Updates go through an exclusive lock file and atomic renames, so concurrent proxies
never lose an update. Sessions expire after 12 hours of inactivity.

A session records:

* **untrusted sources**: tools with the `untrusted` label, plus *any* tool whose output looked like an injection
* **private sources**: tools with the `private` label, plus any output that contained a secret
* **secret fingerprints**: 80-bit BLAKE2b hashes of every secret, of its encodings (base64, URL-safe base64,
  hex, URL-encoding, reversed) and of every 12-character fragment of it, indexed by a 20-bit checksum of their first
  8 bytes. Fragments catch a secret split across arguments (`?a=<first half>&b=<second half>`). Structured secrets
  whose parts are shared by many values (JWT headers, PEM armor) are only fingerprinted whole. The secrets
  themselves are never written to disk. A tool call is scanned in one pass, at every offset and with no length
  limit, so padding an argument cannot push a secret out of view. The cost is linear: roughly a second per few
  megabytes of arguments.
* **untrusted shingles**: hashes of 32-character windows of untrusted text, used to notice when an argument
  copies attacker-provided text (reported as an extra reason, and enforced in `strict` mode)
* **private shingles**: the same for private tool output, used to notice private data flowing into a tool that
  shouldn't receive it

## Decision order

1. Policy `deny` → **deny**
2. Tool definition changed since it was pinned → **deny** until `kairoseki pins approve`
3. Tool definition contains injection text → **deny**
4. Arguments contain a known secret fingerprint → **deny**
5. Policy `allow` → **allow**
6. The tool is a `sink`, the session saw untrusted content, and private data is involved (from the session,
   or because the tool reads private data itself, like a shell) → **ask**
7. The session saw untrusted content, and a tool that is neither `private` nor `destructive` (a sink, or a tool
   Kairoseki cannot classify) receives 32+ characters copied from private tool output → **ask**. This catches
   disguised exfiltration through harmless-looking tools of a malicious server.
8. `strict` mode: any `sink` or `destructive` tool after untrusted content → **ask**
9. Otherwise → **allow**

`monitor` mode turns every ask and deny into an allow, but still logs it.

## What fingerprints cannot catch

Fingerprints are exact matching. They catch a secret copied whole, encoded in a common way, or split into pieces
of 12 characters or more. They do **not** catch a secret interleaved character by character, run through a custom
cipher, or described in words. That is a hard limit of matching, not a bug, and it is why the **lethal-trifecta
rule is the real safety net**: it does not need to recognize the data at all, it only needs to know where the
data came from.

So be careful with anything that turns the trifecta rule off:

* `mode: monitor` never blocks.
* A policy `allow:` entry skips the trifecta rule for that tool. Only allow tools that cannot send data out.

## Approvals

| Client | Mechanism |
| :-- | :-- |
| Handshake era with `elicitation` capability | Kairoseki sends its own `elicitation/create` request and waits for the answer |
| 2026-07-28 era with `elicitation` capability | Kairoseki answers with an `input_required` result carrying an HMAC-signed `requestState` bound to the exact tool and arguments. The client retries with the user's answer. |
| No elicitation | The call is refused with an approval id. `kairoseki approve <id>` allows that exact call once, for 10 minutes. |

An approval only counts if the user explicitly ticked "Allow this call once". Accepting the form with the box
unticked is a refusal.

## The attack lab

`kairoseki attack` builds a small world for each scenario (issues, pages, files, an inbox), starts deliberately
vulnerable lab servers, and plays the tool calls a fully hijacked agent would make. Arguments can only reference
what the agent actually *received*, so redaction counts. Success is judged on the attacker's side: did the canary
arrive at the exfiltration tool? Every scenario is also run **without** Kairoseki to prove the attack is real.
