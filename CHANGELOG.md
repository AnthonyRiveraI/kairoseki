# Changelog

## 0.1.0

First release.

* stdio MCP proxy (`kairoseki run`) for both protocol eras (handshake and 2026-07-28)
* Lethal-trifecta rule with taint shared across servers in one session
* Private-data-flow rule against disguised exfiltration tools
* Secret fingerprints with encoding-aware exfiltration detection, plus redaction of secrets and optional PII
* Poisoned tool detection (injection text, ANSI escapes, invisible Unicode) and rug-pull pinning
* Approvals via MCP elicitation, `input_required` (SEP-2322), or `kairoseki approve`
* `kairoseki scan`, `wrap`, `attack` (9 real-world attacks, 7 everyday tasks), `log`, `status`, `pins`, `init`
