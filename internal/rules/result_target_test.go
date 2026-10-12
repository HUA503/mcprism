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

// Secrets passed as command-line args and inside a nested URL must be masked.
func TestResultJSONRedactsArgSecrets(t *testing.T) {
	srv := &config.Server{
		Name:      "leaky",
		Transport: config.TransportStdio,
		Command:   "node",
		Args: []string{
			"server.js",
			"--api-key=sk-live-VERYSECRETTOKEN1234567890",
			"--url=https://user:s3cr3t@db.example.com/mcp",
			"--token", "ghp_01234567890123456789012345678901234567",
			"--safe-flag=keep-me",
		},
	}
	r := Analyze(Input{Server: srv})
	b, _ := json.Marshal(r)
	out := string(b)
	for _, leak := range []string{
		"sk-live-VERYSECRETTOKEN1234567890",
		"s3cr3t",
		"ghp_01234567890123456789012345678901234567",
	} {
		if strings.Contains(out, leak) {
			t.Fatalf("report leaked credential %q:\n%s", leak, out)
		}
	}
	for _, keep := range []string{"--api-key=***", "user:***@db.example.com", "--token", "***", "--safe-flag=keep-me", "server.js"} {
		if !strings.Contains(out, keep) {
			t.Fatalf("expected report to retain %q:\n%s", keep, out)
		}
	}
}

func TestRedactSecretsShapes(t *testing.T) {
	cases := map[string]string{
		"Authorization: Bearer abcdef1234567890XY": "Bearer ***",
		"token=abcd1234efgh5678":                   "token=***",
		"client_secret: ABCDEFGHIJ123456":          "client_secret: ***",
		"curl https://api.example.com":             "curl https://api.example.com", // no secret, unchanged
	}
	for in, want := range cases {
		got := redactSecrets(in)
		if !strings.Contains(got, want) {
			t.Errorf("redactSecrets(%q) = %q, want substring %q", in, got, want)
		}
	}
}
