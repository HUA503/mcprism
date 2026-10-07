package rules

import (
	"encoding/json"
	"strings"
	"unicode"
)

// schemaHeuristicRules reviews each connected tool's input schema. When the
// server's own source is not available, the schema still reveals whether an
// agent can feed a free-form command, URL or path into a risky operation.
func schemaHeuristicRules(in Input) []Finding {
	var f []Finding
	for _, t := range in.Tools {
		if len(t.InputSchema) == 0 {
			continue
		}
		var schema struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal(t.InputSchema, &schema); err != nil || len(schema.Properties) == 0 {
			continue
		}
		loc := "tool:" + t.Name

		// Deterministic order keeps reports stable.
		names := make([]string, 0, len(schema.Properties))
		for n := range schema.Properties {
			names = append(names, n)
		}
		// simple sort without importing sort again
		for i := 0; i < len(names); i++ {
			for j := i + 1; j < len(names); j++ {
				if names[j] < names[i] {
					names[i], names[j] = names[j], names[i]
				}
			}
		}

		for _, name := range names {
			var prop struct {
				Type    json.RawMessage `json:"type"`
				Enum    json.RawMessage `json:"enum"`
				Const   json.RawMessage `json:"const"`
				Pattern string          `json:"pattern"`
			}
			if err := json.Unmarshal(schema.Properties[name], &prop); err != nil {
				continue
			}
			if !strings.Contains(string(prop.Type), "string") {
				continue
			}
			// A constrained parameter (fixed set, constant or a regex) is not free-form.
			if len(prop.Enum) > 0 || len(prop.Const) > 0 || strings.TrimSpace(prop.Pattern) != "" {
				continue
			}

			words := splitParamName(name)
			evidence := "parameter '" + name + "' (string, no enum/pattern/const)"
			switch {
			case nameMatches(words, commandParamKeywords):
				f = append(f, Finding{
					RuleID: "MCP304", Title: "Free-form command parameter without validation",
					Severity: SeverityMedium, OWASP: "MCP05", Server: in.Server.Name,
					Location: loc, Evidence: evidence,
					Description: "The tool takes a string parameter named like a command or program, but the schema sets no enum, pattern or constant, so the agent can supply an arbitrary command. Without source review this is a strong sign the tool runs shell commands.",
					Advice:      "Constrain the parameter with an enum of allowed commands, or use fixed commands with an argument array and no shell.",
					References:  []string{"https://cwe.mitre.org/data/definitions/78.html"},
				})
			case nameMatches(words, urlParamKeywords):
				f = append(f, Finding{
					RuleID: "MCP305", Title: "Free-form URL parameter without validation",
					Severity: SeverityMedium, OWASP: "MCP02", Server: in.Server.Name,
					Location: loc, Evidence: evidence,
					Description: "The tool takes a string parameter named like a URL or host, but the schema does not pin a host or a pattern. The agent may point the request at cloud metadata or internal services (SSRF).",
					Advice:      "Pin a constant base URL or use a host allow-list/pattern, and block metadata and private ranges.",
					References:  []string{"https://cwe.mitre.org/data/definitions/918.html"},
				})
			case nameMatches(words, pathParamKeywords):
				f = append(f, Finding{
					RuleID: "MCP306", Title: "Free-form path parameter without validation",
					Severity: SeverityMedium, OWASP: "MCP02", Server: in.Server.Name,
					Location: loc, Evidence: evidence,
					Description: "The tool takes a string parameter named like a file path, but the schema does not confine it to a base directory. Traversal sequences may read or overwrite files outside the intended folder.",
					Advice:      "Confine the path to one base directory and validate the parameter with a pattern that rejects traversal sequences.",
					References:  []string{"https://cwe.mitre.org/data/definitions/22.html"},
				})
			}
		}
	}
	return f
}

var (
	commandParamKeywords = []string{"command", "cmd", "exec", "program", "script", "shell"}
	urlParamKeywords     = []string{"url", "uri", "host", "endpoint", "domain", "webhook", "link", "site", "target"}
	pathParamKeywords    = []string{"path", "file", "dir", "folder"}
)

// splitParamName breaks a parameter name into lowercase words at underscores,
// hyphens and camelCase boundaries, so "filePath" and "target_url" both split.
func splitParamName(s string) []string {
	runes := []rune(s)
	var b strings.Builder
	for i, r := range runes {
		if r == '_' || r == '-' {
			b.WriteByte(' ')
			continue
		}
		if i > 0 && unicode.IsUpper(r) {
			prev := runes[i-1]
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if unicode.IsLower(prev) || (unicode.IsUpper(prev) && nextLower) {
				b.WriteByte(' ')
			}
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return strings.Fields(b.String())
}

// nameMatches reports whether one of the name's words equals or starts with a
// keyword. Prefix matching catches "hostname" and "directory" while avoiding
// "profile" (which only ends with "file").
func nameMatches(words, keywords []string) bool {
	for _, w := range words {
		for _, k := range keywords {
			if w == k || strings.HasPrefix(w, k) {
				return true
			}
		}
	}
	return false
}
