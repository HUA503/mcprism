# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
semantic versioning.

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
