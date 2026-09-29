# Contributing to mcprism

Thanks for your interest in improving mcprism! It is a community project and
good contributions are very welcome.

## Getting started

You need Go **1.24+**.

```sh
git clone https://github.com/HUA503/mcprism.git
cd mcprism

go build ./...                 # build all packages
go run ./cmd/mcprism scan examples/vulnerable.mcp.json --no-dynamic
go vet ./...                   # static checks
gofmt -l .                     # formatting (should print nothing)
go test ./...                  # unit tests
```

## Project layout

```
cmd/mcprism/            CLI entry point (cobra)
internal/config/        MCP config model, JSON/JSONC parsing, auto-discovery
internal/protocol/      MCP client: JSON-RPC, stdio / Streamable HTTP / SSE
internal/rules/         Analysis engine and rule sets
internal/report/        table / json / sarif / markdown / html renderers
internal/tui/           Interactive terminal UI (bubbletea)
examples/               Demo configs and a simulated malicious server
docs/                   Documentation (rule catalog)
```

## Adding a rule

Good rules are **deterministic, high-signal and low false-positive**. They do
not require an LLM or network access.

1. Add the check to the appropriate file under `internal/rules/` (or a new
   file grouped by concern).
2. Give it a stable `MCP###` id and map it to an OWASP MCP risk where
   possible (see `docs/RULES.md`).
3. Provide a clear `Evidence`, `Description`, `Advice` and, where available,
   `References`.
4. Add a unit test in `internal/rules/rules_test.go` covering both a positive
   and (where relevant) a negative case.
5. Document it in `docs/RULES.md`.

## Commit & PR guidelines

- Use [Conventional Commits](https://www.conventionalcommits.org/), e.g.
  `feat: detect X`, `fix: avoid Y false positive`, `docs: clarify Z`.
- Keep PRs focused and small; one logical change per PR.
- Run `gofmt`, `go vet ./...` and `go test ./...` before submitting.
- Describe *what* and *why*, and link related issues.

## Reporting bugs & security issues

- Bugs and feature requests: open a GitHub issue using the templates.
- Security vulnerabilities: **do not open a public issue** — follow
  [`SECURITY.md`](SECURITY.md).

By contributing, you agree your contributions are licensed under the project's
[MIT license](LICENSE).
