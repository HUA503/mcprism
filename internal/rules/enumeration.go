package rules

import "strings"

// enumerationRules reports incomplete capability listings or requested
// prompt/resource content inspection. Empty results do not prove safety.
func enumerationRules(in Input) []Finding {
	if len(in.EnumErr) == 0 {
		return nil
	}
	var b strings.Builder
	for i, e := range in.EnumErr {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(e)
	}
	return []Finding{{
		RuleID:      "MCP502",
		Title:       "Capability or content review incomplete",
		Severity:    SeverityMedium,
		OWASP:       "MCP07",
		Server:      in.Server.Name,
		Location:    "dynamic enumeration",
		Evidence:    clipEvidence(b.String(), 160),
		Description: "The server did not let mcprism finish listing capabilities or complete explicitly requested prompt/resource content inspection. Partial results do not prove that unreviewed tools or content are safe.",
		Advice:      "Retry the scan. Supply required prompt arguments only through a reviewed, purpose-built workflow; do not rely on a clean result when capability or content review is incomplete.",
	}}
}
