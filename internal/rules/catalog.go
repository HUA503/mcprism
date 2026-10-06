package rules

// CatalogEntry describes a built-in rule at a high level.
type CatalogEntry struct {
	ID              string
	Title           string
	OWASP           string
	DefaultSeverity string
	Category        string
}

// Catalog returns the static list of built-in rules.
func Catalog() []CatalogEntry {
	out := make([]CatalogEntry, len(ruleCatalog))
	copy(out, ruleCatalog)
	return out
}

var ruleCatalog = []CatalogEntry{
	{"MCP101", "Credential embedded in configuration", "MCP01", "high", "static"},
	{"MCP102", "Cleartext HTTP transport", "MCP01", "medium", "static"},
	{"MCP103", "Filesystem granted a broad directory", "MCP02", "high", "static"},
	{"MCP104", "Remote code fetched and executed", "MCP05", "critical", "static"},
	{"MCP105", "Sandbox or permission checks disabled", "MCP02", "medium", "static"},
	{"MCP106", "Server package not pinned", "MCP04", "medium", "static"},
	{"MCP107", "Remote server without authentication", "MCP07", "info", "static"},
	{"MCP108", "High-entropy value that may be a secret", "MCP01", "medium", "static"},

	{"MCP201", "Prompt injection in tool metadata", "MCP03", "high", "poisoning"},
	{"MCP202", "Invisible or bidirectional Unicode", "MCP03", "high", "poisoning"},
	{"MCP203", "Hidden HTML or Markdown", "MCP03", "medium", "poisoning"},
	{"MCP204", "Encoded blob in metadata", "MCP03", "medium", "poisoning"},
	{"MCP205", "Directive language (weak signal)", "MCP03", "low", "poisoning"},
	{"MCP206", "Missing description or schema", "", "low", "poisoning"},

	{"MCP301", "Dangerous capability combination", "MCP02", "high", "capability"},
	{"MCP302", "Tool runs arbitrary commands", "MCP05", "high", "capability"},
	{"MCP303", "Metadata/private-network target", "MCP02", "high", "capability"},

	{"MCP402", "Possible typosquat package", "MCP04", "medium", "supplychain"},
	{"MCP403", "Code run from a remote URL", "MCP04", "high", "supplychain"},
	{"MCP404", "TLS verification disabled", "MCP01", "high", "supplychain"},

	{"MCP801", "Tool input reaches a command/process sink", "MCP05", "critical", "source"},
	{"MCP802", "Tool input reaches a network sink (SSRF)", "MCP02", "high", "source"},
	{"MCP803", "Tool input reaches a filesystem path", "MCP02", "high", "source"},
	{"MCP804", "Unsafe dynamic code execution", "MCP05", "high", "source"},
	{"MCP805", "Unsafe deserialization", "MCP05", "high", "source"},
	{"MCP806", "Hardcoded secret in server source", "MCP01", "high", "source"},

	{"MCP501", "MCP handshake failure", "MCP07", "medium", "connection"},
	{"MCP601", "Cross-server tool name collision", "MCP03", "medium", "cross-server"},

	{"MCP700", "Blocked by policy", "MCP07", "high", "policy"},
	{"MCP701", "Network isolation required by policy", "MCP02", "high", "policy"},
}
