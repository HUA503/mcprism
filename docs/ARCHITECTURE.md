# Architecture

This document describes how mcprism is put together and how data moves
through a scan. Read it before adding a rule or changing a package.

## Overview

mcprism is a small set of packages with one direction of data flow: configs
become inputs, inputs become results, results become a report. The CLI wires
the packages; the packages do not depend on the CLI.

```
targets -> config -> inputs -> (optional live handshake) -> rules
        -> policy enforcement -> suppressions -> score/compliance -> report
```

## Directory layout

```
cmd/mcprism/        CLI entry point; cobra commands and flag wiring
internal/
  config/           config model, JSON/JSONC parsing, client discovery, directory walk
  protocol/         JSON-RPC client; stdio, Streamable HTTP and SSE transports
  rules/            analysis engine and every built-in check
  policy/           policy as code, built-in profiles, suppressions, enforcement
  report/           aggregation and all output renderers
  tui/              bubbletea terminal UI
examples/           sample configs and a demo server (testserver)
docs/               rule catalog, policy/compliance/architecture guides
assets/             logo, screenshots, comparison image
```

## Packages

### config

`config.Server` is the normalized description of one MCP server: launch command
and args, environment variables, or a remote URL and transport. The package
parses the JSON/JSONC shapes used by the different clients (the `mcpServers`
object and the array form), discovers configs in well-known locations, and can
walk a directory tree looking for config files (`WalkDir`).

### protocol

A minimal MCP JSON-RPC client. `protocol.Dial` picks a transport (stdio,
Streamable HTTP, or legacy SSE), and the client performs `initialize`, then
lists tools, resources and prompts. It does not call tools. Transport details
are isolated per file so adding a transport does not touch the client surface.

### rules

The analysis engine. `Analyze` takes a `rules.Input` (a server plus any data
collected live) and returns a `rules.Result` with findings, inferred
capabilities, score and grade. Each group of checks lives in its own file and
is a function from `Input` to `[]Finding`:

- `static.go` config-level checks
- `secrets.go` typed credential patterns and entropy
- `poisoning.go` tool metadata
- `capability.go` capability inference and combinations
- `supplychain.go` package and remote-code risk
- `network.go` metadata and private-network targets
- `connection.go` handshake failures

`AnalyzeAll` runs many inputs. `Rescore` recomputes score and grade after
findings are changed by policy.

### policy

`policy.Policy` is the parsed YAML. The package loads built-in profiles
(`default`, `strict`, `ci`), applies rule overrides and allow/deny/network
constraints (`Enforce`), applies an accepted-risk register
(`ApplySuppressions`), and produces a `rules.Compliance` verdict
(`Evaluate`).

### report

`report.Build` aggregates results into a `report.Report` with counts and a
summary. Each format has its own renderer (table, JSON, SARIF, Markdown, HTML,
JUnit, CycloneDX, CSV). Renderers take the same `Report`, so adding a format
does not change analysis.

### tui

A bubbletea program for browsing results in a terminal.

## Data flow in detail

1. The CLI collects targets and turns them into `[]config.Server`. With no
   targets it runs discovery; a directory target is walked; a URL target is a
   single remote server.
2. For each server the CLI either builds a static `Input` (`--no-dynamic`) or
   dials the server and records the initialize response and the listed tools,
   resources and prompts.
3. `rules.AnalyzeAll` produces results: capabilities are inferred from the
   package and live metadata, then every check contributes findings.
4. `policy.Enforce` applies overrides, deny matches (`MCP700`) and network
   isolation (`MCP701`), and rescores.
5. `ApplySuppressions` moves accepted, unexpired findings to the suppressed
   list with a reason.
6. `policy.Evaluate` produces the pass/fail verdict from the policy's fail
   conditions.
7. `report.Build` aggregates everything; a renderer writes the chosen format.
8. The exit code reflects the compliance verdict (and `--fail-on`).

## Adding a rule

1. Create or extend a file in `internal/rules`. Write
   `func myRules(in Input) []Finding`.
2. Register it in `Analyze` in `engine.go`.
3. Add an entry to `ruleCatalog` in `catalog.go`.
4. Add tests with a fixture that triggers the rule and one that does not.
5. Update `docs/RULES.md`, including the OWASP mapping.

Keep checks deterministic and local. A rule that needs network calls or an LLM
does not fit the model. Prefer a lower severity over a noisy high.

## Build and test

```sh
go build ./...
go vet ./...
go test ./...
```

Local release build (no publish):

```sh
goreleaser release --snapshot --clean
```
