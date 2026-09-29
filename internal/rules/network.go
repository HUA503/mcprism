package rules

import (
	"net"
	"net/url"
	"strings"
)

// networkTargetRules 检查远程目标是否指向云元数据端点或私有地址段。
func networkTargetRules(in Input) []Finding {
	s := in.Server
	if s.URL == "" {
		return nil
	}
	u, err := url.Parse(s.URL)
	if err != nil {
		return nil
	}
	host := u.Hostname()

	// 云实例元数据端点：典型 SSRF 目标，可换取临时凭据。
	if host == "169.254.169.254" || strings.HasSuffix(host, ".169.254.169.254") {
		return []Finding{{
			RuleID: "MCP303", Title: "MCP server points at a cloud metadata endpoint",
			Severity: SeverityHigh, OWASP: "MCP02", Server: s.Name, Evidence: s.URL,
			Description: "The configured URL is a cloud instance metadata endpoint. If a tool or content fetched by the agent can influence requests to it, it may be abused to obtain temporary credentials (SSRF).",
			Advice:      "Do not point MCP clients at metadata endpoints; require hardened metadata access (e.g. IMDSv2) and apply egress controls.",
			References:  []string{"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"},
		}}
	}

	if ip := net.ParseIP(host); ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
		return []Finding{{
			RuleID: "MCP303", Title: "MCP server target is on a private or loopback range",
			Severity: SeverityLow, OWASP: "MCP07", Server: s.Name, Evidence: s.URL,
			Description: "The server address sits in a private, loopback or link-local range. That is common for internal deployments, but these servers should be inventoried and access-controlled.",
			Advice:      "Authenticate internal servers, document them in the asset inventory, and review egress from MCP clients.",
		}}
	}
	return nil
}
