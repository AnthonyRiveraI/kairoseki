# Changelog

## 0.1.2

* Fix false positives from fragment fingerprints: vendor prefixes shared by every key (`sk-ant-api03-` is exactly
  12 characters, `github_pat_`, `sk-proj-`, `xoxb-`...) are no longer fingerprinted as fragments, so another key of
  the same vendor, or docs that mention the prefix, are not mistaken for a leak. Fragments of the random part are
  still caught.

## 0.1.1

Fixes and improvements from real-world testing on Windows.

* **Cross-server taint now works on every OS.** The session is keyed by the MCP client process, found by walking
  the process tree past Kairoseki's own launchers (`kairoseki.exe`, the venv `python.exe` redirector, `uv`/`uvx`,
  re-exec'd framework Pythons on macOS). Before, `uv tool` installs on Windows gave every server its own session,
  so the lethal-trifecta rule could not fire across servers.
* New `kairoseki session --explain` shows the process-tree walk.
* `scan` and `wrap` now see Claude Code *local*-scope servers (`~/.claude.json` → `projects[...].mcpServers`),
  with Windows path normalization. `--all-projects` covers every project.
* `kairoseki status` lists protected vs unprotected servers, shows live sessions first and hides ended ones
  (`--all` to show them). `wrap` ends with the same summary.
* Secrets split into pieces of 12+ characters are recognized (fragment fingerprints), even when a policy `allow:`
  turns the trifecta rule off for that tool.
* Tool labels ignore a server-name prefix (`codegraph_search` → `search`) and know code-intelligence objects
  (symbols, callers, definitions...).
* Secret scanning is one linear pass with no length limit: ~200x faster, and padding an argument past the old
  200k-character cut-off no longer hides a secret or private data.
* No more false positives on `PATH`/`PATHEXT`/`PSModulePath`/`PWD`, drive-letter paths, or tool confirmations like
  "Email sent to bob@acme.com". npm tokens are detected.
* Windows: lock-file and file-replace races between concurrent proxies are handled.
* The injection warning is separated from the tool output by a blank line.
* Docs: Windows upgrade note (close the client first), `server-filesystem` roots, and the limits of fingerprints.

## 0.1.0

First release.

* stdio MCP proxy (`kairoseki run`) for both protocol eras (handshake and 2026-07-28)
* Lethal-trifecta rule with taint shared across servers in one session
* Private-data-flow rule against disguised exfiltration tools
* Secret fingerprints with encoding-aware exfiltration detection, plus redaction of secrets and optional PII
* Poisoned tool detection (injection text, ANSI escapes, invisible Unicode) and rug-pull pinning
* Approvals via MCP elicitation, `input_required` (SEP-2322), or `kairoseki approve`
* `kairoseki scan`, `wrap`, `attack` (9 real-world attacks, 7 everyday tasks), `log`, `status`, `pins`, `init`
