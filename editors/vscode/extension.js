const path = require('node:path');
const { spawn } = require('node:child_process');
const vscode = require('vscode');

function parseSourceLocation(location) {
  const separator = location.lastIndexOf(':');
  if (separator < 1) return undefined;

  const file = location.slice(0, separator);
  const line = Number.parseInt(location.slice(separator + 1), 10);
  if (!Number.isInteger(line) || line < 1) return undefined;
  return { file, line: line - 1 };
}

function severityFor(value) {
  switch (String(value).toUpperCase()) {
    case 'CRITICAL':
    case 'HIGH':
      return vscode.DiagnosticSeverity.Error;
    case 'MEDIUM':
      return vscode.DiagnosticSeverity.Warning;
    case 'LOW':
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

function activate(context) {
  const diagnostics = vscode.languages.createDiagnosticCollection('mcprism');
  const output = vscode.window.createOutputChannel('mcprism');
  context.subscriptions.push(diagnostics, output);

  context.subscriptions.push(vscode.commands.registerCommand('mcprism.scanWorkspace', async () => {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) {
      vscode.window.showErrorMessage('Open an MCP server workspace before scanning.');
      return;
    }

    const executable = vscode.workspace.getConfiguration('mcprism').get('executablePath', 'mcprism');
    const root = folder.uri.fsPath;
    const status = vscode.window.setStatusBarMessage('mcprism: scanning workspace…');
    output.clear();
    output.appendLine(`Scanning ${root}`);

    try {
      const { stdout, stderr, code } = await new Promise((resolve, reject) => {
        const child = spawn(executable, ['vet', '--format', 'json', root], {
          cwd: root,
          windowsHide: true,
          shell: false,
        });
        let stdout = '';
        let stderr = '';
        child.stdout.setEncoding('utf8').on('data', (chunk) => { stdout += chunk; });
        child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr += chunk; });
        child.once('error', reject);
        child.once('close', (code) => resolve({ stdout, stderr, code }));
      });

      let report;
      try {
        report = JSON.parse(stdout);
      } catch {
        throw new Error(stderr.trim() || `mcprism returned invalid JSON (exit code ${code}).`);
      }

      diagnostics.clear();
      let sourceFindings = 0;
      for (const result of report.results || []) {
        for (const finding of result.findings || []) {
          const parsed = parseSourceLocation(finding.location || '');
          if (!parsed) {
            output.appendLine(`${finding.severity || 'INFO'} ${finding.ruleId || ''} ${finding.location || ''} ${finding.title || ''}`);
            continue;
          }

          const file = path.resolve(root, parsed.file);
          const relative = path.relative(root, file);
          if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
            output.appendLine(`Skipped out-of-workspace location: ${finding.location}`);
            continue;
          }

          const uri = vscode.Uri.file(file);
          const range = new vscode.Range(parsed.line, 0, parsed.line, 0);
          const diagnostic = new vscode.Diagnostic(range, finding.title || finding.description || finding.ruleId, severityFor(finding.severity));
          diagnostic.source = 'mcprism';
          diagnostic.code = finding.ruleId;
          if (finding.evidence) diagnostic.message += `\n${finding.evidence}`;
          const details = [finding.description, finding.advice].filter(Boolean).join('\n\n');
          if (details) diagnostic.relatedInformation = [new vscode.DiagnosticRelatedInformation(new vscode.Location(uri, range), details)];
          const existing = diagnostics.get(uri) || [];
          diagnostics.set(uri, [...existing, diagnostic]);
          sourceFindings++;
        }
      }

      const summary = report.summary || {};
      output.appendLine(`Finished with ${summary.findings ?? sourceFindings} finding(s).`);
      if (stderr.trim()) output.appendLine(stderr.trim());
      vscode.window.showInformationMessage(`mcprism found ${summary.findings ?? sourceFindings} finding(s); ${sourceFindings} shown in Problems.`);
    } catch (error) {
      output.appendLine(String(error));
      vscode.window.showErrorMessage(`mcprism scan failed: ${error.message || error}`);
    } finally {
      status.dispose();
      output.show(true);
    }
  }));
}

function deactivate() {}

module.exports = { activate, deactivate };
