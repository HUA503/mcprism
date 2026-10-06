package rules

import (
	"path/filepath"
	"strconv"

	"github.com/HUA503/mcprism/internal/sast"
)

// sourceCodeRules reviews the server's own implementation when a source tree
// is present (in.Server.ProjectDir). It converts sast issues into findings so
// they flow through the same scoring, policy and reporting pipeline.
func sourceCodeRules(in Input) []Finding {
	dir := in.Server.ProjectDir
	if dir == "" {
		return nil
	}
	var issues []sast.Issue
	if len(in.Server.ProjectFiles) > 0 {
		for _, f := range in.Server.ProjectFiles {
			issues = append(issues, sast.AnalyzeFile(f)...)
		}
	} else {
		var err error
		issues, err = sast.Analyze(dir)
		if err != nil {
			return nil
		}
	}
	if len(issues) == 0 {
		return nil
	}
	out := make([]Finding, 0, len(issues))
	for _, x := range issues {
		rel := x.File
		if r, e := filepath.Rel(dir, x.File); e == nil {
			rel = r
		}
		out = append(out, Finding{
			RuleID:      x.RuleID,
			Title:       x.Title,
			Severity:    Severity(x.Severity),
			OWASP:       srcOWASP[x.RuleID],
			Server:      in.Server.Name,
			Location:    rel + ":" + strconv.Itoa(x.Line),
			Evidence:    x.Code,
			Description: srcDescription[x.RuleID],
			Advice:      x.Advice,
			References:  srcReferences[x.RuleID],
		})
	}
	return out
}

var srcOWASP = map[string]string{
	"MCP801": "MCP05",
	"MCP802": "MCP02",
	"MCP803": "MCP02",
	"MCP804": "MCP05",
	"MCP805": "MCP05",
	"MCP806": "MCP01",
}

var srcDescription = map[string]string{
	"MCP801": "A tool handler passes an argument the agent controls into a process sink (child_process exec/spawn, os.system, subprocess with shell=True). A prompt-injected or malicious agent can choose or alter the command and run arbitrary code on the host.",
	"MCP802": "A tool handler uses an agent-controlled argument as the URL for an outbound request (fetch, requests, httpx). This enables server-side request forgery against cloud metadata endpoints and internal services.",
	"MCP803": "A tool handler uses an agent-controlled argument as a filesystem path without confining it to a base directory. Traversal sequences can read or overwrite files outside the intended folder.",
	"MCP804": "A tool handler evaluates agent-controlled input as code (eval, Function, exec). Running attacker-influenced code gives the agent execution inside the server process.",
	"MCP805": "A tool handler deserializes agent-controlled data with an unsafe loader (pickle, marshal, yaml.load without SafeLoader). Crafted data can lead to code execution or object injection.",
	"MCP806": "The server source contains a hardcoded credential. Anyone with the source or the built artifact can extract it and reuse it.",
}

var srcReferences = map[string][]string{
	"MCP801": {"https://cwe.mitre.org/data/definitions/78.html"},
	"MCP802": {"https://cwe.mitre.org/data/definitions/918.html"},
	"MCP803": {"https://cwe.mitre.org/data/definitions/22.html"},
	"MCP804": {"https://cwe.mitre.org/data/definitions/94.html"},
	"MCP805": {"https://cwe.mitre.org/data/definitions/502.html"},
	"MCP806": {"https://cwe.mitre.org/data/definitions/798.html"},
}
