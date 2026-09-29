package rules

import (
	"strings"

	"github.com/HUA503/mcprism/internal/protocol"
)

func capabilityRules(in Input, c Capabilities) []Finding {
	var f []Finding

	type combo struct {
		cond   bool
		title  string
		sev    Severity
		desc   string
		advice string
	}
	combos := []combo{
		{c.CanShell && c.CanNetwork,
			"Command execution combined with network access", SeverityCritical,
			"The server can both run arbitrary commands and reach the network. A poisoned tool or compromised server can download payloads and exfiltrate data, equivalent to full host compromise.",
			"Run the server in a sandbox without network egress, or split execution and network access across isolated servers."},
		{c.CanWriteFiles && c.CanShell,
			"File write combined with command execution", SeverityCritical,
			"The server can write files and then execute them, allowing it to drop a malicious script, run it and persist on the host.",
			"Make file writes project-scoped and execute commands in a sandbox with approval for every invocation."},
		{c.CanReadFiles && c.CanNetwork,
			"File read combined with network access", SeverityHigh,
			"The server can read files (SSH keys, credentials, source) and send them over the network, enabling data exfiltration.",
			"Restrict file reads to a project directory and deny direct network egress."},
		{c.CanWriteFiles && c.CanNetwork,
			"File write combined with network access", SeverityHigh,
			"The server can fetch remote content and write it to disk, enabling it to tamper with code, configuration or CI scripts.",
			"Limit writes to a project directory and review anything fetched from the network."},
		{c.CanBrowser && c.CanShell,
			"Browser automation combined with command execution", SeverityHigh,
			"The server can drive a browser to attacker-controlled pages and run commands, turning a malicious page or download into host execution.",
			"Run the browser in a sandbox without shell access to the host."},
	}

	for _, cb := range combos {
		if cb.cond {
			f = append(f, Finding{
				RuleID: "MCP301", Title: cb.title, Severity: cb.sev, OWASP: "MCP02",
				Server: in.Server.Name, Description: cb.desc, Advice: cb.advice,
				References: []string{"https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/"},
			})
		}
	}

	// 单个可执行任意命令的工具
	for _, t := range in.Tools {
		if !toolRunsArbitraryCommand(t) {
			continue
		}
		f = append(f, Finding{
			RuleID: "MCP302", Title: "Tool executes arbitrary commands",
			Severity: SeverityHigh, OWASP: "MCP05", Server: in.Server.Name,
			Location: "tool:" + t.Name, Evidence: clipEvidence(t.Description, 120),
			Description: "The tool accepts a free-form command/script string and runs it on the host, which is equivalent to giving the agent shell access.",
			Advice:      "Allow-list the permitted commands, run inside a sandbox, require explicit human approval, and avoid network access from the same server.",
		})
	}
	return f
}

func toolRunsArbitraryCommand(t protocol.Tool) bool {
	text := strings.ToLower(t.Name + " " + t.Description)
	words := []string{
		"run command", "execute command", "shell command", "execute a command",
		"run shell", "execute shell", "run a shell", "subprocess", "terminal",
		"bash -c", "command line", "exec command",
	}
	hits := false
	for _, w := range words {
		if strings.Contains(text, w) {
			hits = true
			break
		}
	}
	if !hits {
		return false
	}
	schema := strings.ToLower(string(t.InputSchema))
	if strings.TrimSpace(schema) == "" || schema == "null" {
		return true // 无 schema 却声称执行命令
	}
	return strings.Contains(schema, "command") || strings.Contains(schema, "\"cmd\"") || strings.Contains(schema, "script")
}
