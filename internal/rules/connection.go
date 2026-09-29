package rules

import "strings"

// connectionRules 在无法完成 MCP 握手时，根据错误类型给出分类与建议。
func connectionRules(in Input) []Finding {
	if in.ConnectErr == nil {
		return nil
	}
	msg := in.ConnectErr.Error()
	l := strings.ToLower(msg)

	var sev Severity
	var title, advice string
	switch {
	case strings.Contains(l, "no such host") || strings.Contains(l, "dns"):
		sev, title = SeverityMedium, "Server could not be resolved (DNS failure)"
		advice = "Check the hostname, your DNS resolver and VPN configuration."
	case strings.Contains(l, "certificate") || strings.Contains(l, "x509") || strings.Contains(l, "tls:"):
		sev, title = SeverityHigh, "TLS handshake or certificate failure"
		advice = "Check certificate validity, the trust store and SNI; do not disable verification."
	case strings.Contains(l, "connection refused"):
		sev, title = SeverityMedium, "Connection refused"
		advice = "Confirm the server is running and listening, and that the port and firewall/security group allow it."
	case strings.Contains(l, "timeout") || strings.Contains(l, "deadline"):
		sev, title = SeverityMedium, "Connection timed out"
		advice = "Check network reachability, firewall/security group, proxy and the server timeout."
	case strings.Contains(l, "no such file") || strings.Contains(l, "executable file not found") || strings.Contains(l, "not found"):
		sev, title = SeverityMedium, "Server command not found"
		advice = "Install the runtime/package, or fix the command and PATH."
	default:
		sev, title = SeverityMedium, "Unable to complete MCP handshake"
		advice = "Review the connection details and the underlying error."
	}

	return []Finding{{
		RuleID: "MCP501", Title: title, Severity: sev, Server: in.Server.Name,
		Evidence:    clipEvidence(msg, 160),
		Description: "The MCP handshake could not be completed, so the server's real capabilities could not be verified.",
		Advice:      advice,
	}}
}
