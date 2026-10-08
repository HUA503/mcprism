package rules

import "strings"

// enumerationRules 在连接成功但枚举 tools/resources/prompts 时发生错误时
// 上报。空列表不等于安全：如果枚举没有完成，不能把"没有危险工具"当作结论。
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
		Title:       "Capability enumeration failed or incomplete",
		Severity:    SeverityMedium,
		OWASP:       "MCP07",
		Server:      in.Server.Name,
		Location:    "dynamic enumeration",
		Evidence:    clipEvidence(b.String(), 160),
		Description: "The server did not let mcprism finish listing tools, resources or prompts (error, or pagination that failed). A partial or empty list must not be read as \"no dangerous tools\": a tool hidden on a later page was not reviewed.",
		Advice:      "Retry the scan. If the same list method keeps failing, treat the server as incompletely reviewed and do not rely on a clean result.",
	}}
}
