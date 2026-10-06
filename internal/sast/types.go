// Package sast performs source-code review of MCP server implementations.
//
// The rest of mcprism reasons about configuration and runtime metadata. SAST
// looks at the server's own code and traces data that an agent can control
// (tool arguments) into dangerous sinks: process execution, outbound network
// calls and filesystem paths. It covers JavaScript/TypeScript and Python, the
// languages behind most MCP servers.
package sast

// Severity is the severity of a source-code finding.
type Severity string

// Severity levels, matching the rules package.
const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// Issue is a single problem found in server source code.
type Issue struct {
	RuleID   string   `json:"ruleId"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Code     string   `json:"code,omitempty"`
	Advice   string   `json:"advice"`
}

// srcLine is a numbered source line.
type srcLine struct {
	num  int
	text string
}
