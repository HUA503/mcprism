# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
semantic versioning.

## [0.6.1] - 2026-10-08

### Fixed

- SAST no longer treats a bare `filepath.Clean` (Go) or an unrelated
  `resolve`/`startsWith` (JS) as a boundary check. A path is only considered
  confined when the exact variable that reaches a file sink is guarded by
  `HasPrefix` / `.startsWith`. Previously such code was reported clean with a
  100 score even when the tool argument still reached a file read.
- Claude Code `projects` configs no longer overwrite earlier projects: every
  project's `mcpServers` is parsed and results are sorted by server name, so
  repeated runs scan the same servers in a stable order instead of a random
  subset.
- Dynamic enumeration now follows `nextCursor` pagination, so a dangerous tool
  on a later page is no longer missed.
- Enumeration failures are reported instead of hidden: if `tools/list`,
  `resources/list` or `prompts/list` errors, a new MCP502 finding marks the
  review incomplete, and an empty tool list is not read as "no dangerous tools".
- `scan` is static by default: it no longer spawns the target process or
  connects. Live probing is opt-in via `--dynamic` (vet keeps `--probe`), and
  the README, docs and SECURITY notes now say the probe starts the server and
  should be run in a sandbox. `--no-dynamic` is deprecated (no-op).

### Added

- Built-in rules rise from 33 to 34 (MCP502 capability enumeration failed).
- Pagination tests for the protocol client and CLI tests asserting static-by-
  default behavior.

## [0.6.0] - 2026-10-07

### Added

- Poisoning checks now cover resources and prompts, not only tools. MCP201-MCP205
  scan the name, description, URI and MIME type of resources and the name,
  description and arguments of prompt templates.
- InputSchema risk heuristics for connected servers when no source code is
  available:
  - MCP304 free-form command parameter (CWE-78),
  - MCP305 free-form URL parameter, SSRF (CWE-918),
  - MCP306 free-form path parameter (CWE-22).
  Parameters constrained with `enum`, `const` or `pattern` are not flagged.
- Baseline comparison. `--baseline report.json` accepts findings already present
  in a previous `-f json` report; only new findings affect the score and the
  compliance gate. Accepted findings stay listed under suppressed for audit.
  The flag works with both `scan` and `vet`.
- Go SAST. `vet` reads mcp-go servers (`server.AddTool` / `mcp.AddTool`) and
  traces tool arguments into `exec.Command`, `http.Get`/`NewRequest` and
  `os`/`ioutil` file calls, and checks for hardcoded secrets (MCP801/802/803/806).

### Changed

- Built-in rules rise from 30 to 33.
- The demo test server now exposes resources and prompt templates, including
  poisoned examples.

## [0.5.0] - 2026-10-06

### Added

- Source-code review (SAST). `vet` reads a server checkout on disk and traces
  tool arguments an agent can control into dangerous sinks:
  - MCP801 command/process execution (`exec`, `spawn`, `os.system`,
    `subprocess shell=True`),
  - MCP802 SSRF through a controlled request URL (`fetch`, `requests`, `httpx`),
  - MCP803 path traversal through an uncontrolled file path,
  - MCP804 dynamic code execution (`eval`, `Function`, `exec`),
  - MCP805 unsafe deserialization (`pickle`, `marshal`, `yaml.load`),
  - MCP806 hardcoded credentials in the source.
- Source targets: `vet ./path/to/server` reviews a whole tree and
  `vet server.py` reviews one file. No build step or network required.
- Recognizes the JS/TS `McpServer` and low-level `setRequestHandler`, and the
  Python `FastMCP` `@mcp.tool()` and low-level `call_tool` handlers.
- `docs/SAST.md` with vulnerable and fixed code for every rule, plus a source
  review screenshot.

### Notes

- The engine is pattern-based with one level of taint tracking and no
  third-party parser. It targets direct handler-to-sink paths and does not
  cover everything a full data-flow analyzer would.
- Built-in rules rise from 24 to 30.

## [0.4.0] - 2026-10-06

### Added

- `vet` command: audit a server straight from a launch command
  (`vet -- npx -y pkg`), a quoted command string, an http(s) URL, or an
  `npm:`/`pypi:` package shorthand, without adding it to a client config.
- `vet --probe` launches the process or connects to the URL to enumerate
  tools, resources and prompts. `vet` is static by default and has no side
  effects.

### Changed

- `scan` and `vet` run through one shared audit pipeline.

## [0.3.0] - 2026-09-30

### Added

- Overall-risk dashboard at the top of the HTML report: a score ring, the
  worst grade across servers, and the compliance gate result in one block.

### Changed

- The interactive TUI (`-i`) is rebuilt with rounded panels, an active-pane
  border, a selected-row marker, and color-coded grades and severities.
- Panels size to their content instead of filling the terminal.

## [0.2.0] - 2026-09-29

### Added

- Policy as code: versioned YAML for rule toggles, severity overrides,
  allow/deny lists for packages, commands and domains, and network isolation.
- Built-in profiles: `default`, `strict`, `ci`.
- Suppressions: an accepted-risk register with reason and expiry. Expired
  entries stop suppressing, and suppressed findings stay in reports.
- Secret detection by type (AWS, Google, GitHub, Slack, Stripe, GitLab,
  OpenAI, npm, JWT) and Shannon-entropy suspected secrets (`MCP108`).
- Network target checks for cloud metadata endpoints and private/loopback
  ranges (`MCP303`).
- Policy findings `MCP700` (deny match) and `MCP701` (network isolation).
- JUnit XML, CycloneDX 1.5 SBOM and CSV report formats.
- Recursive directory scans and multiple targets per run.
- `rules` and `profiles` commands.
- Chinese README, an architecture guide, a repository social preview and a
  terminal demo GIF.

### Changed

- Secret checks now classify recognized credentials as critical and follow a
  three-tier order: known token, secret-like variable name, high-entropy
  value.
- The HTML report includes the compliance gate and a suppressed section.

## [0.1.0] - 2026-09-29

### Added

- First release.
- Static config review and live capability enumeration over stdio, Streamable
  HTTP and legacy SSE.
- Around 20 rules mapped to OWASP MCP01–MCP07.
- Risk score (0–100) and A–F grades.
- table, JSON, SARIF, Markdown and HTML reports.
- Interactive terminal UI and a bundled demo server.

[0.2.0]: https://github.com/HUA503/mcprism/releases/tag/v0.2.0
[0.1.0]: https://github.com/HUA503/mcprism/releases/tag/v0.1.0
