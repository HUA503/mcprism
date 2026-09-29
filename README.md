<div align="center">

<img src="assets/logo.svg" width="128" height="128" alt="mcprism logo">

# mcprism

**Vet MCP servers before your AI trusts them.**

A single-binary security scanner for [Model Context Protocol](https://modelcontextprotocol.io/)
servers: static config review, live capability enumeration, tool-poisoning
detection, policy as code and risk grading. It runs offline.

[![CI](https://github.com/HUA503/mcprism/actions/workflows/ci.yml/badge.svg)](https://github.com/HUA503/mcprism/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/HUA503/mcprism?color=a6e3a1&label=release)](https://github.com/HUA503/mcprism/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/HUA503/mcprism)](https://goreportcard.com/report/github.com/HUA503/mcprism)
[![Go version](https://img.shields.io/badge/go-1.24-89b4fa?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/github/license/HUA503/mcprism?color=cba6f7)](LICENSE)

</div>

---

MCP connects your AI agent to outside servers for tools, files and data. Those
servers run commands, read the filesystem and see your prompts. A malicious or
over-privileged server can steal credentials, run commands, or steer the agent
through the text it returns. mcprism gives you a per-server report and a score
before you let an agent use them, the way you would run `trivy` against an image.

<p align="center">
  <img src="assets/comparison.png" alt="Before and after using mcprism" width="100%">
</p>

## What it does

- One binary. No Python or Node setup, no LLM API key, no account.
- Static and live checks. It reads the config and performs the MCP handshake to
  list tools, resources and prompts. It never calls a tool.
- Policy as code. Turn rules on/off, change severity, allow or deny packages,
  commands and domains, and require network isolation. Built-in profiles give
  you `default`, `strict` and `ci` baselines.
- Accepted-risk register. Suppress findings with a reason and an expiry.
  Suppressed items stay visible in the report, and expired ones come back.
- Deterministic and offline. 24 rules mapped to OWASP MCP01–MCP07; nothing
  leaves your machine.
- Reports for people and machines: table, JSON, Markdown, HTML, SARIF, JUnit
  XML, CycloneDX SBOM and CSV.
- Scan several targets at once: files, directories (recursively), or URLs.

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
# One-line installer (Linux / macOS / Windows via Git Bash)
curl -fsSL https://raw.githubusercontent.com/HUA503/mcprism/main/install.sh | sh
```

```sh
# Go
go install github.com/HUA503/mcprism/cmd/mcprism@latest
```

Or download a binary from the [releases](https://github.com/HUA503/mcprism/releases)
page (Linux/macOS/Windows, amd64 and arm64). Homebrew, Scoop and Nix are on the roadmap.

## Quick start

```sh
# Auto-discover configs for Claude Desktop, Claude Code, Cursor, VS Code, ...
mcprism scan

# A specific config file
mcprism scan ~/.claude.json

# A directory, searched recursively
mcprism scan ./configs

# A remote server
mcprism scan https://mcp.example.com/v1

# Several targets together
mcprism scan a.json b.json ./configs

# Fully offline / static-only (no process spawned, no connection)
mcprism scan mcp.json --no-dynamic

# Enforce a baseline or a custom policy
mcprism scan --profile strict
mcprism scan --policy policy.yml --suppressions suppressions.yml

# Interactive terminal UI
mcprism scan -i

# Reference
mcprism inspect mcp.json     # list a server's tools/resources/prompts
mcprism rules                # list built-in rules
mcprism profiles             # list built-in profiles
```

### Flags

| Flag | Description |
|---|---|
| `-f, --format` | `table` (default) · `json` · `sarif` · `md` · `html` · `junit` · `cyclonedx` · `csv` |
| `-o, --output` | Write the report to a file |
| `-p, --policy` | Path to a policy YAML file |
| `--profile` | Built-in profile: `default` · `strict` · `ci` |
| `--suppressions` | Path to a suppressions YAML file |
| `--no-dynamic` | Static analysis only; never spawn a process or connect |
| `--fail-on` | Exit non-zero on `critical` / `high` / `medium` / `low` |
| `--timeout` | Per-server handshake timeout (default `10s`) |
| `-i, --interactive` | Browse findings in a TUI |
| `--transport` | Force `http` (Streamable HTTP) or `sse` (legacy) for URLs |

## Policy as code

A policy file is a versioned YAML document. It sets the pass/fail conditions,
overrides individual rules, lists allowed and denied packages/commands/domains,
and can require that servers with file or shell access have no network egress.

```yaml
version: "1"
fail:
  on: high
  grade: B
  score: 70
rules:
  MCP106:
    severity: high
allow:
  packages: ["@modelcontextprotocol/*"]
deny:
  commands: [nc, ncat]
  domains: ["*.ngrok.io"]
capabilities:
  requireNetworkIsolation: true
```

A deny match is reported as `MCP700`; a file/shell server with network access
under isolation is reported as `MCP701`. See [`examples/policy.yml`](examples/policy.yml),
[`examples/suppressions.yml`](examples/suppressions.yml) and the
[policy guide](docs/POLICIES.md). For compliance gates and machine output, see
[docs/COMPLIANCE.md](docs/COMPLIANCE.md).

## What it detects

- Secrets in config. Recognized credential formats (AWS, Google, GitHub, Slack,
  Stripe, GitLab, OpenAI, JWT and more) are flagged by type, and high-entropy
  values that look like generated keys are flagged as suspected secrets.
  Placeholders and `${ENV_VAR}` references are not flagged.
- Cleartext transport and disabled TLS (`http://`,
  `NODE_TLS_REJECT_UNAUTHORIZED=0`).
- Over-broad permissions. Filesystem servers mounted at `/` or the home
  directory; sandbox or permission checks turned off.
- Tool poisoning. Injection directives, zero-width/bidirectional Unicode,
  hidden HTML/Markdown and encoded blobs in tool names, descriptions and schemas.
- Dangerous capability combinations, such as shell plus network, file read
  plus network, or file write plus shell.
- Network targets. Cloud metadata endpoints (`169.254.169.254`) and
  private/loopback ranges.
- Supply-chain risk: unpinned packages, typosquat look-alikes, and code run
  straight from a remote URL.
- Policy violations: denied packages/commands/domains and broken network isolation.
- Cross-server tool name collisions, and classified connectivity failures
  (DNS / TLS / refused / timeout / command not found).

The full list with the OWASP crosswalk is in [docs/RULES.md](docs/RULES.md).

## Output formats

| Format | Typical use |
|---|---|
| `table` | Terminal output |
| `json` | Custom tooling |
| `sarif` | GitHub code scanning |
| `md` | Markdown reports / tickets |
| `html` | Shareable standalone report |
| `junit` | Jenkins, GitLab and GitHub test reports |
| `cyclonedx` | SBOM / vulnerability ingestion |
| `csv` | Spreadsheets and GRC workflows |

## Supported clients & transports

mcprism reads the JSON/JSONC MCP config used by Claude Desktop, Claude Code,
Cursor, VS Code (GitHub Copilot Chat), Windsurf, Cline, Continue and similar
tools, in both the `mcpServers` object and array forms. It speaks all three MCP
transports: stdio, Streamable HTTP, and the legacy HTTP+SSE.

## CI/CD

Block risky servers in a pipeline with the `ci` profile:

```yaml
- name: Audit MCP servers
  run: |
    curl -fsSL https://raw.githubusercontent.com/HUA503/mcprism/main/install.sh | sh
    mcprism scan mcp.json --no-dynamic --profile ci
```

Publish to GitHub code scanning via SARIF:

```yaml
- name: Scan & upload
  run: mcprism scan mcp.json -f sarif -o mcp.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcp.sarif
```

JUnit output works with the test report steps in Jenkins and GitLab, and
CycloneDX output can be handed to an SBOM or vulnerability tracker.

## How it works

```
collect targets (discover / files / directories / URLs)
  -> MCP handshake (initialize; list tools, resources, prompts)
  -> deterministic rules (static, poisoning, capability, supply-chain, network)
  -> policy enforcement (overrides, allow/deny, isolation)
  -> suppressions (accepted risk, with reason and expiry)
  -> score & grade, compliance gate
  -> report
```

mcprism only enumerates capabilities, so analysis has no side effects. The
bundled demo server (`examples/testserver`) simulates risky behavior without
performing any of it.

## Comparison

Based on public project descriptions (features may change):

| | **mcprism** | mcp-scan | mcp-audit | manual review |
|---|---|---|---|---|
| Language / runtime | Go, single binary | Python | Python/Node | — |
| Zero install / runtime deps | ✅ | ❌ | ❌ | — |
| Static config review | ✅ | ✅ | partial | ❌ |
| Live capability enumeration | ✅ | partial | partial | ❌ |
| Tool-poisoning detection | ✅ | ✅ | partial | ❌ |
| Capability-combination modeling | ✅ | ❌ | ❌ | ❌ |
| Policy as code (allow/deny/isolation) | ✅ | ❌ | ❌ | ❌ |
| JUnit / CycloneDX / CSV output | ✅ | ❌ | ❌ | ❌ |
| Recursive, multi-target scan | ✅ | partial | ❌ | ❌ |
| SARIF + CI exit codes | ✅ | ✅ | ❌ | ❌ |
| Fully offline, no LLM | ✅ | ✅ | partial | ✅ |
| Cross-platform | ✅ | partial | partial | — |

## Roadmap

- [ ] More rules and fewer false positives as the MCP spec evolves
- [ ] MCP registry / marketplace scanning
- [ ] User-defined rules beyond policy overrides
- [ ] Pre-commit hook and editor integrations
- [ ] Homebrew, Scoop and Nix packages

## Contributing

Issues and PRs are welcome. A good rule contribution is a high-signal,
deterministic check with a low false-positive rate: add it under
`internal/rules`, map it to an OWASP MCP risk, and include a test. Run
`go vet ./... && go test ./...` before opening a PR.

## License

[MIT](LICENSE) © mcprism contributors.

mcprism is a defensive tool. It reports risk; it does not prove a server is
safe, and a clean report is not a reason to trust a server you do not understand.
