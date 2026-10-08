# Policy as code

mcprism separates detection from enforcement. The built-in rules decide what a
finding is; a policy decides which rules run, how severe they are, what is
allowed or denied, and what makes a run fail. Policies are versioned YAML files
you can keep with the rest of your security configuration and review in pull
requests.

## Loading order

1. A built-in profile (`--profile`) sets the baseline: `default`, `strict` or
   `ci`. With no flag, `default` is used.
2. A policy file (`--policy`) is parsed on top. Use it for anything specific to
   your team.
3. A suppressions file (`--suppressions`) moves accepted findings out of the
   active list without deleting them.
4. A baseline report (`--baseline`) accepts every finding a previous scan
   already had, so a run only reports what changed.

A profile and a policy file can be used together; the file wins where they
overlap.

## Fields

```yaml
version: "1"            # policy schema version, currently "1"
description: ""         # free text, shown in tooling
```

### fail

Sets the gate. A run is non-compliant when any condition is met.

```yaml
fail:
  on: high      # a finding at high or critical exists
  grade: B      # any server grades below B
  score: 70     # any server scores below 70
```

All three are optional. The reason for failure is reported in the compliance
block and in machine-readable output.

### rules

Override a rule by ID.

```yaml
rules:
  MCP106:
    severity: high     # override default severity
  MCP107:
    enabled: false     # turn the rule off
```

Severity values are `critical`, `high`, `medium`, `low` (and `info`). List rule
IDs with `mcprism rules` or see [RULES.md](RULES.md).

### allow and deny

Each list matches `packages`, `commands` and `domains`:

```yaml
allow:
  packages: ["@modelcontextprotocol/*"]
  commands: [node]
  domains: ["*.internal.example.com"]
deny:
  packages: ["*shell*", "*shodan*"]
  commands: [nc, ncat]
  domains: ["*.ngrok.io"]
```

- A `deny` match produces `MCP700` (high) unless the same item matches an
  `allow` entry. Allow entries take precedence, so you can deny a broad pattern
  and carve out the trusted cases.
- Matching:
  - `*` matches anything.
  - `*.example.com` matches `example.com` and any subdomain.
  - `prefix*` matches strings starting with `prefix`.
  - Anything else is an exact, case-insensitive match.
- Packages are taken from the first non-flag token of the launch command (for
  example `@modelcontextprotocol/server-filesystem`). Commands match the
  executable basename. Domains match the host of a remote server URL.

### capabilities

```yaml
capabilities:
  requireNetworkIsolation: true
```

When enabled, a server that can run commands or read/write files and also has
network access produces `MCP701` (high). This targets the common exfiltration
path where a file or shell capability is combined with egress.

## Suppressions

Suppressions are an accepted-risk register, kept in a separate file:

```yaml
suppressions:
  - rule: MCP103
    server: local-files
    location: env.DEBUG
    reason: Read-only access to the project folder is intended.
    expires: "2027-01-01"
```

- `rule` is required; `*` matches every rule. `server` and `location` are
  optional filters.
- `reason` is required. `expires` uses `YYYY-MM-DD` and is optional.
- Suppressed findings move to a separate section of the report with the reason
  and expiry, so the decision is auditable.
- An expired entry no longer suppresses, and the finding returns on the next
  run. This stops accepted risks from being forgotten.

## Baselines

A baseline is a snapshot of accepted findings, used to start scanning a server
that already has problems. Save a JSON report once, then pass it on later runs:

```sh
mcprism scan mcp.json -f json -o baseline.json
mcprism scan mcp.json --baseline baseline.json
```

Findings in the baseline move to the suppressed list with reason
`baseline: <file>` and no longer affect the score or the gate. A finding that is
new, or that moved to another tool or file, stays active. This lets a team fix
issues over time while the build still catches regressions.

A baseline is not the same as a suppressions file. A baseline accepts whatever a
specific past report contained and is regenerated as issues get fixed. A
suppressions file lists individual findings with a reason and usually an expiry.

## Suggested workflow

- Keep a single `policy.yml` per team or environment and commit it.
- Use `--profile strict` on production machines and `--profile ci` in pipelines.
- Treat suppressions as a short-lived list; add an expiry where you can and
  review the suppressed section in the HTML or Markdown report.
- In CI, fail the job on compliance rather than parsing output text. See
  [COMPLIANCE.md](COMPLIANCE.md).

A ready-to-edit policy and suppressions file are in
[`examples/policy.yml`](../examples/policy.yml) and
[`examples/suppressions.yml`](../examples/suppressions.yml).
