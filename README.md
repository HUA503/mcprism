<div align="center">

<img src="assets/logo.svg" width="128" height="128" alt="mcprism logo">

# mcprism

**Vet MCP servers before your AI trusts them.**

A fast, single-binary, zero-configuration security scanner for
[Model Context Protocol](https://modelcontextprotocol.io/) servers —
static config review, live capability enumeration, tool-poisoning detection
and risk grading, fully offline.

[![CI](https://github.com/HUA503/mcprism/actions/workflows/ci.yml/badge.svg)](https://github.com/HUA503/mcprism/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/HUA503/mcprism?color=a6e3a1&label=release)](https://github.com/HUA503/mcprism/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/HUA503/mcprism)](https://goreportcard.com/report/github.com/HUA503/mcprism)
[![Go version](https://img.shields.io/badge/go-1.24-89b4fa?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/github/license/HUA503/mcprism?color=cba6f7)](LICENSE)

</div>

---

MCP lets your AI agent connect to external servers for tools, files and data.
Those servers run commands, read your filesystem and receive your prompts — and
a single malicious or over-privileged one can steal secrets, run arbitrary
commands or hijack the agent through poisoned tool descriptions. **mcprism**
shows you exactly what every MCP server can do and what it can get away with,
the same way `trivy` made vulnerability scanning one command.

<p align="center">
  <img src="assets/comparison.png" alt="Before and after using mcprism" width="100%">
</p>

## Why mcprism

- **One binary, zero runtime dependencies.** No Python venv, no Node modules,
  no LLM API key, no account. Download one file and run it.
- **Zero configuration.** Point it at a file, a URL, or nothing — it
  auto-discovers the MCP configs of the AI tools on your machine.
- **Static *and* dynamic.** It reviews your config *and* performs the MCP
  handshake to enumerate the tools, resources and prompts a server actually
  exposes — without calling any tool.
- **Deterministic & offline.** ~20 rules mapped to the OWASP Top 10 for
  Agentic Applications (MCP01–MCP07); results are reproducible and never leave
  your machine.
- **Built for CI.** A security score (0–100, A–F), `--fail-on`, and
  **SARIF** output you can upload straight to GitHub code scanning.

## Report

<p align="center">
  <img src="assets/screenshot-dynamic.png" alt="mcprism HTML report for a live server" width="86%">
</p>

Batch review across many servers (static mode):

<p align="center">
  <img src="assets/screenshot-static.png" alt="mcprism HTML report across many servers" width="70%">
</p>

## Install

```sh
# One-line installer (Linux / macOS / Windows* via Git Bash)
curl -fsSL https://raw.githubusercontent.com/HUA503/mcprism/main/install.sh | sh
```

```sh
# Go
go install github.com/HUA503/mcprism/cmd/mcprism@latest
```

Or grab a prebuilt binary from the [**releases**](https://github.com/HUA503/mcprism/releases)
page (Linux/macOS/Windows, amd64 & arm64). Homebrew, Scoop and more are on the roadmap.

## Quick start

```sh
# Auto-discover configs for Claude Desktop, Claude Code, Cursor, VS Code, …
mcprism scan

# Scan a specific config file
mcprism scan ~/.claude.json

# Scan a remote server directly
mcprism scan https://mcp.example.com/v1

# Fully offline / static-only (no process spawned, no network connection)
mcprism scan mcp.json --no-dynamic

# Interactive terminal UI
mcprism scan -i

# List a server's capabilities without running the full audit
mcprism inspect mcp.json
```

### Useful flags

| Flag | Description |
|---|---|
| `-f, --format` | `table` (default) · `json` · `sarif` · `md` · `html` |
| `-o, --output` | Write the report to a file |
| `--no-dynamic` | Static analysis only — never spawn a process or connect |
| `--fail-on` | Exit non-zero on `critical` / `high` / `medium` / `low` |
| `--timeout` | Per-server handshake timeout (default `10s`) |
| `-i, --interactive` | Browse findings in a TUI |
| `--transport` | Force `http` (Streamable HTTP) or `sse` (legacy) for URLs |

## What it detects

- **Secrets in config** — live API tokens/keys embedded in `env` (placeholders
  and `${ENV_VAR}` references are not flagged).
- **Cleartext transport & disabled TLS** — `http://` endpoints,
  `NODE_TLS_REJECT_UNAUTHORIZED=0`, etc.
- **Over-broad permissions** — filesystem servers mounted at `/` or your home
  directory; sandbox/permission checks turned off by flags.
- **Tool poisoning** — prompt-injection directives, zero-width/bidirectional
  Unicode, hidden HTML/Markdown, and encoded blobs in tool names, descriptions
  and schemas.
- **Dangerous capability combinations** — e.g. shell execution **+** network
  egress, file read **+** network, file write **+** shell.
- **Supply-chain risk** — unpinned packages (rug pull), typosquat look-alikes,
  and code executed straight from a remote URL (`curl|sh`).
- **Cross-server shadowing** — identical tool names from different servers that
  can mask one another.
- **Connectivity failures**, classified (DNS / TLS / connection refused /
  timeout / command not found).

See the full [**rule catalog**](docs/RULES.md), including the OWASP crosswalk.

## Supported clients & transports

mcprism understands the JSON/JSONC MCP config used by **Claude Desktop**,
**Claude Code**, **Cursor**, **VS Code (GitHub Copilot Chat)**, **Windsurf**,
**Cline**, **Continue** and similar tools — both the `mcpServers` object and
array forms. It speaks all three MCP transports: **stdio**, **Streamable HTTP**,
and the legacy **HTTP+SSE**.

## CI/CD

Block risky MCP servers in your pipeline:

```yaml
- name: Audit MCP servers
  run: |
    curl -fsSL https://raw.githubusercontent.com/HUA503/mcprism/main/install.sh | sh
    mcprism scan mcp.json --no-dynamic --fail-on high
```

Or publish results to GitHub code scanning via SARIF:

```yaml
- name: Scan & upload
  run: mcprism scan mcp.json -f sarif -o mcp.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcp.sarif
```

## How it works

```
discover configs  →  MCP handshake (initialize, tools/resources/prompts list)
                  →  deterministic rules (static · poisoning · capability · supply-chain)
                  →  score & grade (0–100, A–F)
                  →  report (table / json / sarif / md / html)
```

mcprism only **enumerates** capabilities — it never calls a server's tools, so
analysis has no side effects. The bundled demo server (`examples/testserver`)
simulates malicious behavior without performing any.

## Comparison

Based on the public project descriptions (features may change):

| | **mcprism** | mcp-scan | mcp-audit | manual review |
|---|---|---|---|---|
| Language / runtime | Go, single binary | Python | Python/Node | — |
| Zero install / runtime deps | ✅ | ❌ | ❌ | — |
| Static config review | ✅ | ✅ | partial | ❌ |
| Live capability enumeration | ✅ | partial | partial | ❌ |
| Tool-poisoning detection | ✅ | ✅ | partial | ❌ |
| Capability-combination modeling | ✅ | ❌ | ❌ | ❌ |
| SARIF + `--fail-on` for CI | ✅ | ✅ | ❌ | ❌ |
| Fully offline, no LLM | ✅ | ✅ | partial | ✅ |
| Cross-platform | ✅ | partial | partial | — |

## Roadmap

- [ ] More rules & reduced false positives as the MCP spec evolves
- [ ] MCP registry / marketplace scanning
- [ ] Custom, policy-as-code rules and an SBOM export
- [ ] Pre-commit hook and editor integrations
- [ ] Homebrew, Scoop, Nix packages

## Contributing

Issues and PRs are very welcome. A good rule contribution is a high-signal,
deterministic check with low false-positive rate — add it under
`internal/rules`, map it to an OWASP MCP risk, and include a test. Please run
`go vet ./... && go test ./...` before opening a PR.

## License

[MIT](LICENSE) © mcprism contributors.

> **Note:** mcprism is a defensive tool. It reports risk; it does not guarantee
> a server is safe, and a clean report is not a substitute for trusting only
> servers you understand.
