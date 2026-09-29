# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |
| < 0.1 | ❌ |

## Reporting a vulnerability

Please report suspected security vulnerabilities **privately** using GitHub's
[private vulnerability reporting](https://github.com/HUA503/mcprism/security/advisories/new)
(**Report a vulnerability**) rather than opening a public issue. Include:

- A description of the issue and its impact
- Steps to reproduce (PoC welcome)
- Affected version/commit and environment
- Any suggested remediation

You should receive an initial response within a few days. Please give the
maintainers reasonable time to investigate and release a fix before public
disclosure.

## Security posture of mcprism itself

- mcprism performs **read-only** analysis. It enumerates a server's tools,
  resources and prompts but **never calls them**, so scanning has no side
  effects.
- Static mode (`--no-dynamic`) never spawns a subprocess or opens a network
  connection.
- The bundled `examples/testserver` simulates malicious behavior without
  performing any dangerous action.
- mcprism does not phone home, collect telemetry, or require an account.

## Hardening dependencies

If you find a vulnerable dependency, please report it as above. Release
artifacts are built with `CGO_ENABLED=0` and published with checksums.
