# Compliance and machine output

mcprism is built to run unattended. After the rules and policy are applied, a
run produces a compliance verdict and can emit the formats CI systems and
security tools already understand.

## Exit codes

- `0`: the run is compliant (or no gate was configured).
- `1`: the run failed a gate, or `--fail-on` was reached.

There are two ways to set the gate:

- Policy conditions (`fail.on`, `fail.grade`, `fail.score`) produce a compliance
  verdict. This is the recommended path and works with profiles.
- `--fail-on <severity>` exits non-zero when a finding at that severity or
  higher is present. It is a quick override for one-off runs.

The compliance block in JSON output looks like this:

```json
"compliance": {
  "profile": "strict",
  "policy": "policy.yml",
  "pass": false,
  "reason": "a finding at or above high exists"
}
```

## SARIF (GitHub code scanning)

```sh
mcprism scan mcp.json -f sarif -o mcp.sarif
```

```yaml
- name: Scan & upload
  run: mcprism scan mcp.json -f sarif -o mcp.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcp.sarif
```

Findings show up as code scanning alerts with rule IDs and severities.

## JUnit XML

```sh
mcprism scan mcp.json -f junit -o mcprism.xml
```

Each finding is a test case; medium and above are marked as failures. Jenkins,
GitLab and the GitHub test reporter can publish the file directly, so a policy
failure appears alongside test results.

GitLab example:

```yaml
audit:
  script:
    - mcprism scan mcp.json -f junit -o mcprism.xml
  artifacts:
    reports:
      junit: mcprism.xml
```

## CycloneDX SBOM

```sh
mcprism scan mcp.json -f cyclonedx -o bom.json
```

The output is a CycloneDX 1.5 document: each MCP server is a component and
each finding is a vulnerability with a severity rating. Hand it to an SBOM
store or a vulnerability tracker that accepts CycloneDX.

## CSV

```sh
mcprism scan mcp.json -f csv -o findings.csv
```

One row per finding with server, grade, score, rule, severity, OWASP mapping,
location, evidence and advice. It opens in a spreadsheet and imports into most
GRC tools.

## Pipeline example

```yaml
- name: Audit MCP servers
  run: |
    curl -fsSL https://raw.githubusercontent.com/HUA503/mcprism/main/install.sh | sh
    mcprism scan mcp.json --profile ci
```

`scan` is static by default, so a run spawns no processes. The `ci` profile
fails on high and above. To also inventory live servers, pass `--dynamic` (run
it in a sandbox) so mcprism performs the handshake and records the actual tool
surface.

## Notes for auditors

- The HTML and Markdown reports include the active findings, the score and
  grade per server, and a suppressed section that records accepted risks with
  reasons.
- JSON output is the most complete form and includes capabilities, counts and
  the compliance verdict.
- mcprism does not call tools and does not send data anywhere; running it adds
  no traffic to the servers beyond the standard MCP initialization and listing
  requests.
