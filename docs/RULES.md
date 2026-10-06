# Rule catalog

mcprism ships with 30 deterministic rules. Every finding is mapped to the
OWASP Top 10 for Agentic Applications - MCP risks (MCP01-MCP07). No rule needs
an LLM or an internet connection; everything runs locally.

Severity is contextual and can be raised by other signals, such as a recognized
credential format or an Authorization header over plaintext HTTP. Rules can be
disabled, reweighted or suppressed through policy; see POLICIES.md.

## Static configuration

| Rule | OWASP | Default | What it detects |
|---|---|---|---|
| MCP101 | MCP01 | High (Critical for recognized credentials) | Secret/credential embedded in `env`, with type detection (AWS, Google, GitHub, Slack, Stripe, GitLab, OpenAI, JWT, ...) |
| MCP102 | MCP01 | Medium (High with auth header) | Cleartext `http://` transport |
| MCP103 | MCP02 | High | Filesystem server scoped to `/`, a home dir, etc. |
| MCP104 | MCP05 | Critical | Shell that downloads and executes remote code (`curl\|sh`) |
| MCP105 | MCP02 | Medium–Critical | Sandbox/permission checks disabled by flags |
| MCP106 | MCP04 | Medium | Server package not pinned to a version (rug pull) |
| MCP107 | MCP07 | Info | Remote server configured without authentication |
| MCP108 | MCP01 | Medium | High-entropy value that looks like a generated secret |

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
| MCP303 | MCP02/MCP07 | High (Low for private ranges) | Cloud metadata endpoint (`169.254.169.254`) or private/loopback target |

## Supply chain

| Rule | OWASP | Default | What it detects |
|---|---|---|---|
| MCP402 | MCP04 | Medium | Typosquat look-alike package names |
| MCP403 | MCP04 | High | Code executed directly from a remote URL |
| MCP404 | MCP01 | High | TLS certificate verification disabled via env |

## Source code review

These rules review the server's own JS/TS/Python implementation and trace tool
arguments into sinks. [SAST.md](SAST.md) has vulnerable and fixed code for each.

| Rule | OWASP | Default | What it detects |
|---|---|---|---|
| MCP801 | MCP05 | Critical | Tool input reaches a command/process sink |
| MCP802 | MCP02 | High | Tool input controls a request URL (SSRF) |
| MCP803 | MCP02 | High | Tool input used as a filesystem path without confinement |
| MCP804 | MCP05 | High (Critical with input) | Dynamic code execution (eval/Function/exec) |
| MCP805 | MCP05 | High | Unsafe deserialization (pickle/marshal/yaml.load) |
| MCP806 | MCP01 | High (Medium suspected) | Hardcoded credential in the source |

## Connectivity & cross-server

| Rule | OWASP | Default | What it detects |
|---|---|---|---|
| MCP501 | MCP07 | Medium–High | Handshake failures, classified (DNS/TLS/refused/timeout/command missing) |
| MCP601 | MCP03 | Medium | Cross-server tool name collision / shadowing |

## Policy

| Rule | OWASP | Default | What it detects |
|---|---|---|---|
| MCP700 | MCP07 | High | A package, command or domain matched by a `deny` policy entry |
| MCP701 | MCP02 | High | File/shell capability combined with network when isolation is required |

## OWASP MCP risk crosswalk

| OWASP | Risk | Covered by |
|---|---|---|
| MCP01 | Token mismanagement & secret exposure | MCP101, MCP102, MCP108, MCP404, MCP806 |
| MCP02 | Privilege escalation via scope creep | MCP103, MCP105, MCP301, MCP303, MCP701, MCP802, MCP803 |
| MCP03 | Tool poisoning (rug pull, schema poisoning, shadowing) | MCP201-MCP206, MCP601 |
| MCP04 | Software supply chain & dependency tampering | MCP106, MCP402, MCP403 |
| MCP05 | Command injection & execution | MCP104, MCP302, MCP801, MCP804, MCP805 |
| MCP07 | Insufficient authentication & authorization | MCP107, MCP501, MCP700 |

> False positives: secrets referenced as `${VAR}`, obvious placeholders
> (`your-*`, `changeme`) and pinned packages are not flagged. A high-entropy
> value that is not a secret can be suppressed with a reason; see POLICIES.md.
