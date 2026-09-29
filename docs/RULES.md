# Rule catalog

mcprism ships with ~20 deterministic rules. Every finding is mapped to the
**OWASP Top 10 for Agentic Applications – MCP risks** (MCP01–MCP07). No rule
requires an LLM or an internet connection; everything runs locally.

Severity is contextual and can be raised by additional signals (e.g. a live
token prefix, an Authorization header over plaintext HTTP).

## Static configuration

| Rule | OWASP | Default | What it detects |
|---|---|---|---|
| MCP101 | MCP01 | High (Critical for live tokens) | Long-lived secret/credential embedded in `env` |
| MCP102 | MCP01 | Medium (High with auth header) | Cleartext `http://` transport |
| MCP103 | MCP02 | High | Filesystem server scoped to `/`, a home dir, etc. |
| MCP104 | MCP05 | Critical | Shell that downloads and executes remote code (`curl\|sh`) |
| MCP105 | MCP02 | Medium–Critical | Sandbox/permission checks disabled by flags |
| MCP106 | MCP04 | Medium | Server package not pinned to a version (rug pull) |
| MCP107 | MCP07 | Info | Remote server configured without authentication |

## Tool metadata poisoning

| Rule | OWASP | Default | What it detects |
|---|---|---|---|
| MCP201 | MCP03 | High–Critical | Prompt-injection directives in tool name/description/schema |
| MCP202 | MCP03 | High (Critical for bidi) | Zero-width / bidirectional Unicode |
| MCP203 | MCP03 | Medium–High | Hidden HTML comments/script tags, embedded images/links |
| MCP204 | MCP03 | Medium | Large base64/hex blobs that may conceal payloads |
| MCP205 | MCP03 | Low | Directive language steering model behavior (weak signal) |
| MCP206 | — | Low/Info | Missing description or input schema (usability) |

## Capability modeling

| Rule | OWASP | Default | What it detects |
|---|---|---|---|
| MCP301 | MCP02 | High–Critical | Dangerous capability combinations (shell+network, write+shell, read+network …) |
| MCP302 | MCP05 | High | A tool that executes arbitrary commands |

## Supply chain

| Rule | OWASP | Default | What it detects |
|---|---|---|---|
| MCP402 | MCP04 | Medium | Typosquat look-alike package names |
| MCP403 | MCP04 | High | Code executed directly from a remote URL |
| MCP404 | MCP01 | High | TLS certificate verification disabled via env |

## Connectivity & cross-server

| Rule | OWASP | Default | What it detects |
|---|---|---|---|
| MCP501 | MCP07 | Medium–High | Handshake failures, classified (DNS/TLS/refused/timeout/command missing) |
| MCP601 | MCP03 | Medium | Cross-server tool name collision / shadowing |

## OWASP MCP risk crosswalk

| OWASP | Risk | Covered by |
|---|---|---|
| MCP01 | Token mismanagement & secret exposure | MCP101, MCP102, MCP404 |
| MCP02 | Privilege escalation via scope creep | MCP103, MCP105, MCP301 |
| MCP03 | Tool poisoning (rug pull, schema poisoning, shadowing) | MCP201–MCP206, MCP601 |
| MCP04 | Software supply chain & dependency tampering | MCP106, MCP402, MCP403 |
| MCP05 | Command injection & execution | MCP104, MCP302 |
| MCP07 | Insufficient authentication & authorization | MCP107, MCP501 |

> False-positive handling: secrets referenced as `${VAR}`, obvious placeholders
> (`your-*`, `changeme`), and pinned packages are not flagged.
