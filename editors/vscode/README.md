# mcprism for VS Code

Run mcprism's static source scan from VS Code and review file findings in the
Problems panel. The extension requires the `mcprism` CLI to be installed; it
does not bundle the scanner. Scans use `mcprism vet --format json` and never
launch the workspace's MCP server.

## Install from a VSIX

Build or download the `mcprism` CLI using the [main installation instructions](../../README.md#install),
then package this extension from this directory with `npx @vscode/vsce package`.
In VS Code, run **Extensions: Install from VSIX...** and select the generated
`mcprism-0.1.0.vsix` file. The extension is not yet published to the VS Code
Marketplace.

## Use

Open an MCP server source workspace, then run **mcprism: Scan Workspace** from
the Command Palette. In a multi-root workspace, each folder is scanned in turn.
Findings with source locations appear in Problems; other findings and scan
details appear in the mcprism output channel.

If the CLI is not on `PATH`, set `mcprism.executablePath` in VS Code settings to
its full path. Static findings are best-effort security signals, not proof that
a server is safe.

## Develop

Open this directory in VS Code and press **F5** to launch an Extension
Development Host. Install the CLI separately and open a supported source tree
in the development host before running the command.
