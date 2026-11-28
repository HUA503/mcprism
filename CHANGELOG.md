# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
semantic versioning.

## [Unreleased]

### Improved

- Recognize Python tool callbacks registered through common `.tool(...)`,
  `.add_tool(...)` and `.register_tool(...)` calls when passed as direct local
  function references.

### Added

- Scan public GitHub repositories with `vet --repo [--ref]` using a bounded,
  temporary source archive; downloaded code is never executed.

### Community

- Add bilingual guidance to issue forms so English- and Chinese-speaking users
  can ask questions, report bugs and suggest features with safer examples.

## [0.43.1] - 2026-11-28

### Improved

- Propagate Python and Go taint through simple tuple/unpacking assignments,
  including Python starred targets and list destructuring.
- Include Go `var` declarations in tuple assignment tracking.

### Documentation

- Clarify that Python/Go expression-level taint may over-report helper calls
  whose return value is actually fixed or safe.

## [0.43.0] - 2026-11-28

### Improved

- Detect Chinese prompt-injection instructions that collect credentials and
  transmit them in a later step or embed them in an outgoing request.

### Added

- Add policy-defined custom regex checks for server settings, collected MCP
  metadata and existing findings, with matched text omitted from reports.

## [0.42.5] - 2026-11-28

### Fixed

- Avoid following Python or Go sink aliases after the local variable is
  reassigned to a different value.

## [0.42.4] - 2026-11-27

### Improved

- Detect additional Chinese priority-forgery and safety-policy-degradation
  phrases in server-controlled metadata.
- Follow simple Python callable aliases to recognized dangerous sinks.
- Follow simple Go process-execution function aliases to command sinks.

## [0.42.3] - 2026-11-27

### Improved

- Follow tool-controlled Rust arguments through explicitly imported, uniquely
  named local helpers in the same Cargo package during directory scans.

## [0.42.2] - 2026-11-27

### Improved

- Expand Chinese prompt-injection signatures for role-play jailbreaks and
  instructions that claim priority over system or developer rules.

## [0.42.1] - 2026-11-27

### Improved

- Follow tainted Go tool arguments through exported helpers imported from
  source packages in the scanned module, within bounded traversal limits.

- Extend the bundled live-probe fixture with safe, fixed prompt and resource
  bodies so users can try `--read-content` end to end.
- Clarify when live probing requests resource data or rendered prompt text.

## [0.42.0] - 2026-11-27

### Added

- Add opt-in `--read-content` probing for bounded prompt and resource text, with
  multilingual injection checks and explicit incomplete-review findings.

## [0.41.0] - 2026-11-27

### Improved

- Scan server-provided instructions for prompt-injection patterns during the
  existing dynamic handshake, using the same offline multilingual rules as
  tool, resource and prompt metadata.

## [0.40.0] - 2026-11-27

### Improved

- Recognize Go process, HTTP and filesystem sinks imported under explicit
  standard-library package aliases, including aliased path guards.

## [0.39.0] - 2026-11-27

### Improved

- Follow Rust MCP tool input into process and filesystem sinks imported under
  direct or grouped standard-library aliases.

## [0.38.0] - 2026-11-27

### Improved

- Follow JavaScript/TypeScript helper calls through statically named namespace
  imports from local modules.

## [0.37.0] - 2026-11-27

### Improved

- Follow Python helper imports through multi-level relative imports inside
  packages with `__init__.py` markers, within the existing SAST resource limits.

## [0.36.0] - 2026-11-27

### Improved

- Recognize JavaScript/TypeScript command and request sinks imported under
  explicit ES module, CommonJS destructuring, and supported module aliases.

## [0.35.0] - 2026-11-27

### Improved

- Recognize Python filesystem paths built through aliased `pathlib.Path`
  imports, alongside the existing command, SSRF and deserialization sink aliases.

## [0.34.0] - 2026-11-27

### Improved

- Recognize Python command, SSRF and unsafe-deserialization sinks when imported
  through explicit module or function aliases.

## [0.33.0] - 2026-11-27

### Improved

- Preserve MCP tool-input taint through simple statically named fields in
  JavaScript/TypeScript, Python and Go, including literal Python dictionary and
  Go map keys.

## [0.32.0] - 2026-11-27

### Added

- Discover JetBrains Air MCP servers from the user config at
  `~/.jetbrains/mcp/mcp.json` and shareable project config at `.air/mcp.json`.

## [0.31.0] - 2026-11-27

### Added

- Discover JetBrains Junie MCP configs from the user home and project, including
  custom user directories set with `JUNIE_HOME`.

## [0.30.1] - 2026-11-27

### Fixed

- Reject control characters and malformed version values in installer inputs
  before constructing release download URLs.

## [0.30.0] - 2026-11-27

### Added

- Pin an installer release with `MC_PRISM_VERSION` on Linux, macOS, and
  Windows; verify the checksum for the selected release before installing.

## [0.29.0] - 2026-11-27

### Added

- Expand offline prompt-injection detection for Simplified and Traditional
  Chinese instructions that ask the model to forget prior rules, nullify safety
  policies, or act while the user is unaware.

## [0.28.0] - 2026-11-27

### Added

- Follow direct named helper calls through statically required CommonJS module
  objects in bounded same-directory modules.

## [0.27.0] - 2026-11-27

### Added

- Follow JavaScript/TypeScript helpers imported through destructured CommonJS
  `require()` bindings from bounded same-directory modules.

## [0.26.0] - 2026-11-27

### Added

- Follow Go tool input through same-package methods when the receiver type is
  recoverable from a same-file declaration, constructor signature or current
  method receiver, including values captured by handler closures.

## [0.25.0] - 2026-11-27

### Added

- Follow Python tool input into helpers called through explicit same-directory
  module imports such as `import helpers as h; h.run(...)`, within the existing
  bounded source traversal limits.
- Detect additional Simplified and Traditional Chinese prompt-injection
  directives that forbid refusals, demand unconditional obedience, bypass
  safety checks or claim elevated privileges.

## [0.24.0] - 2026-11-26

### Added

- Continue Python taint through helper calls and named imports across bounded,
  same-directory modules.
- Detect common Japanese and Korean prompt-injection directives in MCP
  metadata using deterministic offline signatures.

## [0.23.0] - 2026-11-26

### Added

- Detect and analyze `.mts` and `.cts` TypeScript source files in project scans
  and `vet`, and recognize all supported JS/TS and Rust source suffixes when
  discovering standalone source trees and files.
- Continue JS/TS taint through helper calls and named imports across bounded,
  same-directory modules (depth, file-count and source-size limits).
- Follow JS/TS tool arguments into explicitly imported, exported helpers from a
  same-directory module when the helper directly reaches a recognized sink.
- Follow Python tool arguments into explicitly imported helper functions from
  a same-directory module when the helper directly reaches a recognized sink.

## [0.22.0] - 2026-11-26

### Added

- Expand Chinese and Traditional Chinese prompt-injection signatures to cover
  safety-policy overrides, role/mode changes, instruction reclassification and
  hidden-reasoning disclosure.
- Follow Go MCP tool arguments into unique same-package free-function helpers
  across source files.
- Follow Rust `rmcp #[tool]` argument flows through local aliases and unique
  same-file helper functions, including multi-step calls.

## [0.21.0] - 2026-11-26

### Added

- Follow JS/TS tool-input flows through local aliases and unambiguous same-file
  function and block-bodied arrow helpers; ignore commented-out sink examples.
- Scan Rust MCP tool handlers using the official `rmcp` `#[tool]` macro for
  process execution, `reqwest` request URLs, filesystem paths and hardcoded
  secrets.

## [0.20.0] - 2026-11-25

### Added

- Detect common Chinese prompt-injection directives in MCP metadata.
- Propagate tool-input taint through local aliases and same-file helper calls
  in Python and Go source analysis.

## [0.19.0] - 2026-11-25

### Added

- Discover Kiro IDE and CLI MCP configurations from global and project paths,
  honoring the `KIRO_HOME` environment variable.

## [0.18.0] - 2026-11-25

### Added

- Discover Amazon Q Developer MCP servers from global and project config files,
  including the legacy `mcp.json` locations.

## [0.17.0] - 2026-11-25

### Added

- Support Windows runners in the GitHub Action with native PowerShell download,
  checksum verification, and report handling.

## [0.16.0] - 2026-11-25

### Added

- Add `mcprism doctor` to explain automatic MCP config discovery and report
  actionable guidance when `scan` finds no servers.

## [0.15.0] - 2026-11-25

### Added

- Support macOS runners in the GitHub Action, with platform-specific release
  downloads and SHA-256 verification.

## [0.14.0] - 2026-11-25

### Added

- Discover MCP servers from Zed user, project, and agent-profile settings.

## [0.13.0] - 2026-11-25

### Added

- Discover GitHub Copilot CLI MCP servers from user and project configuration.

## [0.12.0] - 2026-11-25

### Added

- Negotiate the stateless MCP 2026-07-28 protocol and fall back to legacy
  handshake-based servers for live capability inspection.

## [0.11.0] - 2026-11-25

### Added

- Add `mcprism demo`, an offline first-run experience using embedded clean and
  vulnerable MCP configs without launching servers or reading user configs.

## [0.10.2] - 2026-11-25

### Added

- Discover Roo Code project MCP configs from `.roo/mcp.json`, including when
  scanning a directory.

## [0.10.1] - 2026-11-25

### Added

- Discover the current Cline CLI MCP settings file and respect the
  `CLINE_MCP_SETTINGS_PATH` override while retaining legacy VS Code extension
  discovery.

## [0.10.0] - 2026-11-25

### Added

- Discover and scan Gemini CLI MCP settings from user, project, and system
  configuration locations.
- Discover and scan OpenCode MCP settings from user, project, and system
  configuration locations, including local command arrays and remote servers.

### Changed

- Explain mcprism's purpose and the `scan` versus `vet` commands more clearly in
  the English and Chinese README introductions.
- Add OpenCode to the localized README quick-start client lists.

## [0.9.2] - 2026-11-25

### Added

- Save and verify privacy-preserving tool inventory locks to detect definition drift.
- The GitHub Action can verify a saved tool inventory lock and fail when tool definitions drift. This opt-in check connects to the target; run it on a dedicated runner without secrets.

- `registry audit --all` follows Registry cursors to audit every matching entry.

### Fixed

- Strip terminal control characters from Registry launch metadata before
  scanning so findings remain safe to render and hidden controls cannot split
  suspicious tokens.

- Atomically replace tool inventory lock files with `--force`, preserving the previous lock if writing the replacement fails.

- Reject MCP list responses that omit or null the item array, so incomplete enumeration cannot look like an empty inventory.

- Reject Registry audit entries missing a name or version so incomplete records
  cannot be reported as fully audited.

## [0.9.1] - 2026-11-24

### Added

- `registry audit --require-complete` fails when results are truncated or a
  configuration cannot be audited, while preserving any generated report.

## [0.9.0] - 2026-11-24

### Added

- Batch static audit of matching official MCP Registry entries with one combined
  report.

## [0.8.9] - 2026-11-24

### Fixed

- Validate MCP Registry search length using non-space Unicode characters.

## [0.8.8] - 2026-11-24

### Added

- Nix flake package for Linux and macOS on x86_64 and aarch64.
- Add a locked nixpkgs input and a fixed hash for Go dependencies.
- Build the Nix package in GitHub Actions.
- Search and statically scan package and remote transports from the official MCP Registry.

## [0.8.7] - 2026-11-24

### Added

- Auto-discover system-managed Codex MCP configuration on Unix and Windows.

## [0.8.6] - 2026-11-24

### Fixed

- Project config discovery now checks all parent directories instead of stopping after six levels.

## [0.8.5] - 2026-11-24

### Added

- Codex CLI / IDE MCP configuration discovery and TOML scanning.
- Add a Codex TOML example for a local server and an authenticated remote server.

## [0.8.4] - 2026-11-24

### Added

- Signed GitHub build provenance for release archives.

## [0.8.3] - 2026-11-24

### Added

- Homebrew formula that builds from source and updates with each stable release.

### Fixed

- The Unix installer warns when its install directory is missing from PATH.

## [0.8.2] - 2026-11-24

### Fixed

- Release binaries report their actual version in the CLI and MCP handshake.

## [0.8.1] - 2026-11-24

### Changed

- Updated Bubbles, Bubble Tea and Lipgloss together to compatible releases.

## [0.8.0] - 2026-11-24

This release makes mcprism easier to install and use in team pipelines, while
improving scan behavior and keeping dependencies and release workflows current.

### Added

- Official GitHub Actions integration. It installs a pinned release after
  verifying SHA-256, scans with the `ci` profile and writes SARIF for code
  scanning.
- Native PowerShell installer with checksum verification, Windows ARM64
  releases, Linux ARMv7 releases and a Scoop bucket.
- Weekly Dependabot updates and a `govulncheck` CI job for reachable Go
  vulnerabilities.
- `scan --project-only` discovers project configs without including global
  client configs.

### Changed

- Batch audits exit with code 1 when findings fail a gate, and command errors
  exit with code 2. Reports remain available when a gate fails.
- Building from source now requires Go 1.25 to use the patched `x/text`
  dependency. Prebuilt releases have no Go runtime requirement.
- GitHub Actions are pinned to verified commit SHAs and use minimal workflow
  permissions.

### Fixed

- Explicit scans keep same-named servers from different projects and report
  each scanned config file once. Recursive scans surface unreadable or
  malformed config files.
- Invalid audit options are rejected before probing. `inspect` requires a
  target with exactly one server.
- Streamable HTTP returns as soon as the matching SSE response arrives instead
  of waiting for the server to close the stream. Notifications do not wait for
  a response body, and stream read errors are preserved.
- HTTP replies must have a successful status and a matching JSON-RPC response
  id. JSON bodies and assembled SSE events are limited to 16 MiB, including
  multiline events in the legacy SSE transport.
- Legacy SSE setup and the initialized notification honor the caller's context;
  notification failures now fail initialization instead of being ignored.
- Native Windows tests run in CI in addition to the Windows cross-build.

### Security

- Legacy SSE endpoint events are confined to the configured server's origin
  before any configured headers are sent. Cross-host, cross-port and HTTPS
  downgrade endpoints are refused; relative endpoints and explicit default
  ports remain supported.
- Literal cloud-metadata and link-local destinations are checked before proxy
  routing as well as at direct socket connection time.
- The reachable `golang.org/x/text` vulnerability is fixed, and CI now checks
  Go dependencies for known reachable vulnerabilities.

## [0.7.0] - 2026-10-12

This release focuses on detection accuracy and on not leaking data while
reporting it. Most of the work came from adversarial review: bypass samples
that scored 100 are now caught, the Windows test build is green again, and
secrets on a command line no longer appear in reports.

### Security

- Reports now mask secrets everywhere they can surface. URL userinfo was
  already redacted; this extends to `--api-key`/`--token`/`--client-secret`
  style arguments, bare `key=value` pairs, `Bearer` headers and known token
  prefixes (AWS, GitHub `ghp_`/`github_pat_`, Slack, GitLab, OpenAI, JWT) in
  the target string and in finding evidence, across all formats. Detection
  still uses the original values, so redaction causes no false negatives.
- Live probing applies an egress guard: redirects are confined to the same
  scheme+host (no HTTPS downgrade, chain capped at three), and dial-out to
  cloud-metadata and link-local targets is refused after DNS resolution,
  covering 169.254.0.0/16, 100.100.100.200 and fe80::/10. Loopback and RFC1918
  intranet servers remain allowed.
- A spawned server gets a restricted environment by default instead of the
  full parent shell; pass `--inherit-env` to restore the old behavior.

### Added

- Built-in rules rise from 34 to 35. New rule MCP807 reports a dynamic
  `require`/import whose module name comes from tool input; it previously
  shared the MCP805 id with unsafe deserialization, which conflated two issues.
- Poisoning detection normalizes metadata with NFKC and folds Cyrillic/Greek
  homoglyphs before matching, so full-width and look-alike spellings of
  injection phrases are caught. It now also flags the Unicode Tags block
  (U+E0000–E007F) and mixed-script tokens.
- New flags `--inherit-env`, `--no-color` and `--ascii`; ASCII glyphs are also
  auto-selected on legacy Windows consoles and `TERM=dumb`, and `NO_COLOR` is
  honored.
- Shared terminal theme under `internal/ui` used by both the table report and
  the TUI.

### Changed

- MCP205 (directive language) is no longer reported for normal API guidance
  such as "Before calling this tool, make sure the file exists". It fires only
  when imperative wording appears together with hidden or confusable text, and
  is informational.
- SARIF `rules[]` are emitted in a fixed id order so output is reproducible.

### Fixed

- The Windows test build failed because a test file carried an implicit
  `_windows` build suffix and an unused variable. The file is renamed so the
  cross-platform rule tests run on every OS, and the dead code is removed. CI
  now cross-checks `GOOS=windows` vet/build.
- A UI test depended on the host terminal's UTF-8 capability and failed on
  legacy Windows conhost; it pins the terminal environment explicitly.
- SAST path confinement is bound to the specific variable reaching the sink in
  Python (matching the JS/Go behavior), so an unrelated `realpath` +
  `startswith` elsewhere in a handler no longer excuses an unguarded `open()`.
- A constant-URL guard no longer accepts string concatenation:
  `fetch("https://" + url)` is reported as SSRF; only a single string literal
  counts as a fixed host.
- `@latest`, `@next`, ranges and wildcards are treated as unpinned versions;
  only an exact `@x.y.z` satisfies the pinning rule.
- Windows shells and paths are detected: `powershell`/`pwsh`/`cmd` and
  `-EncodedCommand`, plus drive roots such as `C:\` and `%USERPROFILE%`.
- Config parsing strips a UTF-8 BOM, tolerates trailing commas, warns on files
  it cannot parse instead of silently skipping them, and honors `projectDir`
  during `scan` so SAST actually runs.
- Streamable HTTP SSE responses are matched by JSON-RPC id instead of taking
  the last message, so interleaved progress notifications no longer hijack a
  result. HTTP clients have bounded timeouts.
- CSV output quotes formula-triggering cells; SARIF includes `startLine` and a
  legal relative artifact URI; CycloneDX adds `bom-ref`/`affects` linkage.
- Spawned stdio process trees are cleaned up as a group (process groups on
  Unix, taskkill on Windows), removing orphaned children.
- Baseline fingerprints include severity and an evidence hash, so a finding
  that changes severity is no longer silently suppressed.
- Source reads are bounded (per-file, total-bytes and walk-depth limits).
- The install script verifies release checksums.

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

[0.31.0]: https://github.com/HUA503/mcprism/compare/v0.30.1...v0.31.0
[0.32.0]: https://github.com/HUA503/mcprism/compare/v0.31.0...v0.32.0
[0.33.0]: https://github.com/HUA503/mcprism/compare/v0.32.0...v0.33.0
[0.34.0]: https://github.com/HUA503/mcprism/compare/v0.33.0...v0.34.0
[0.35.0]: https://github.com/HUA503/mcprism/compare/v0.34.0...v0.35.0
[0.36.0]: https://github.com/HUA503/mcprism/compare/v0.35.0...v0.36.0
[0.37.0]: https://github.com/HUA503/mcprism/compare/v0.36.0...v0.37.0
[0.38.0]: https://github.com/HUA503/mcprism/compare/v0.37.0...v0.38.0
[0.39.0]: https://github.com/HUA503/mcprism/compare/v0.38.0...v0.39.0
[0.41.0]: https://github.com/HUA503/mcprism/compare/v0.40.0...v0.41.0
[0.43.1]: https://github.com/HUA503/mcprism/compare/v0.43.0...v0.43.1
[0.43.0]: https://github.com/HUA503/mcprism/compare/v0.42.5...v0.43.0
[0.42.5]: https://github.com/HUA503/mcprism/compare/v0.42.4...v0.42.5
[0.42.4]: https://github.com/HUA503/mcprism/compare/v0.42.3...v0.42.4
[0.42.3]: https://github.com/HUA503/mcprism/compare/v0.42.2...v0.42.3
[0.42.2]: https://github.com/HUA503/mcprism/compare/v0.42.1...v0.42.2
[0.42.1]: https://github.com/HUA503/mcprism/compare/v0.42.0...v0.42.1
[0.42.0]: https://github.com/HUA503/mcprism/compare/v0.41.0...v0.42.0
[0.40.0]: https://github.com/HUA503/mcprism/compare/v0.39.0...v0.40.0
[0.30.1]: https://github.com/HUA503/mcprism/compare/v0.30.0...v0.30.1
[0.30.0]: https://github.com/HUA503/mcprism/compare/v0.29.0...v0.30.0
[0.29.0]: https://github.com/HUA503/mcprism/compare/v0.28.0...v0.29.0
[0.28.0]: https://github.com/HUA503/mcprism/compare/v0.27.0...v0.28.0
[0.27.0]: https://github.com/HUA503/mcprism/compare/v0.26.0...v0.27.0
[0.26.0]: https://github.com/HUA503/mcprism/compare/v0.25.0...v0.26.0
[0.25.0]: https://github.com/HUA503/mcprism/compare/v0.24.0...v0.25.0
[0.24.0]: https://github.com/HUA503/mcprism/compare/v0.23.0...v0.24.0
[0.23.0]: https://github.com/HUA503/mcprism/compare/v0.22.0...v0.23.0
[0.22.0]: https://github.com/HUA503/mcprism/compare/v0.21.0...v0.22.0
[0.21.0]: https://github.com/HUA503/mcprism/compare/v0.20.0...v0.21.0
[0.20.0]: https://github.com/HUA503/mcprism/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/HUA503/mcprism/compare/v0.18.0...v0.19.0
[0.18.0]: https://github.com/HUA503/mcprism/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/HUA503/mcprism/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/HUA503/mcprism/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/HUA503/mcprism/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/HUA503/mcprism/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/HUA503/mcprism/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/HUA503/mcprism/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/HUA503/mcprism/compare/v0.10.2...v0.11.0
[0.10.2]: https://github.com/HUA503/mcprism/compare/v0.10.1...v0.10.2
[0.10.1]: https://github.com/HUA503/mcprism/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/HUA503/mcprism/compare/v0.9.2...v0.10.0
[0.9.2]: https://github.com/HUA503/mcprism/releases/tag/v0.9.2
[0.9.1]: https://github.com/HUA503/mcprism/releases/tag/v0.9.1
[0.9.0]: https://github.com/HUA503/mcprism/releases/tag/v0.9.0
[0.8.9]: https://github.com/HUA503/mcprism/releases/tag/v0.8.9
[0.8.8]: https://github.com/HUA503/mcprism/releases/tag/v0.8.8
[0.8.7]: https://github.com/HUA503/mcprism/releases/tag/v0.8.7
[0.2.0]: https://github.com/HUA503/mcprism/releases/tag/v0.2.0
[0.1.0]: https://github.com/HUA503/mcprism/releases/tag/v0.1.0


