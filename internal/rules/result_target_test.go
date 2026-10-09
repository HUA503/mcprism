package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/HUA503/mcprism/internal/config"
)

// The serialized result must identify what was scanned (command/url/source),
// otherwise machine-readable reports cannot be archived or reproduced.
func TestResultJSONIncludesTarget(t *testing.T) {
	srv := &config.Server{
		Name:      "fs",
		Transport: config.TransportStdio,
		Command:   "npx",
		Args:      []string{"-y", "@modelcontextprotocol/server-filesystem", "/"},
		Source:    "/home/me/.config/mcp.json",
		Client:    "claude-desktop",
	}
	r := Analyze(Input{Server: srv})
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, want := range []string{`"server":"fs"`, "npx", "server-filesystem", "/home/me/.config/mcp.json", "claude-desktop", `"transport":"stdio"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("JSON output missing %q:\n%s", want, out)
		}
	}
}

// Credentials embedded in a URL userinfo must not leak into the report.
func TestResultJSONRedactsURLCredentials(t *testing.T) {
	srv := &config.Server{
		Name:      "remote",
		Transport: config.TransportHTTP,
		URL:       "https://tok:secret@host.example/mcp",
	}
	r := Analyze(Input{Server: srv})
	b, _ := json.Marshal(r)
	out := string(b)
	if strings.Contains(out, "secret") {
		t.Fatalf("report leaked URL password:\n%s", out)
	}
	if !strings.Contains(out, "tok:***@host.example") {
		t.Fatalf("expected redacted userinfo in target, got:\n%s", out)
	}
}
