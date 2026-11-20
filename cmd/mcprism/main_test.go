package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/HUA503/mcprism/internal/report"
)

// captureStdout runs fn while capturing everything the process writes to
// os.Stdout (audit renders to os.Stdout, not the cobra writer).
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	w, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(w.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// runScan executes scanCmd with captured output.
func runScan(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var err error
	out := captureStdout(t, func() {
		cmd := scanCmd()
		cmd.SetArgs(args)
		cmd.SilenceErrors = true
		err = cmd.Execute()
	})
	return out, err
}

func writeServerConfig(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "servers.json")
	cfg := `{
		"mcpServers": {
			"ghost": {
				"command": "mcprism-does-not-exist-xyz",
				"args": ["serve"]
			}
		}
	}`
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Default scan must be static: it must not spawn the target process, so a
// server whose binary is missing must not produce a handshake/connection error.
// This is the reviewer's point 4: dynamic probing must be opt-in.
func TestScanIsStaticByDefault(t *testing.T) {
	cfg := writeServerConfig(t, t.TempDir())
	out, err := runScan(t, cfg)
	if err != nil {
		t.Fatalf("scan errored: %v\n%s", err, out)
	}
	if strings.Contains(out, "MCP501") || strings.Contains(out, "handshake") {
		t.Fatalf("static scan must not attempt to spawn the server (got a connection/handshake finding):\n%s", out)
	}
}

// With --dynamic the same config attempts to launch the missing binary and
// records the handshake failure instead of hiding it.
func TestScanDynamicAttemptsProbe(t *testing.T) {
	cfg := writeServerConfig(t, t.TempDir())
	out, err := runScan(t, "--dynamic", cfg)
	if err != nil {
		t.Fatalf("scan errored: %v\n%s", err, out)
	}
	if !strings.Contains(out, "MCP501") {
		t.Fatalf("expected MCP501 handshake failure for a missing binary under --dynamic:\n%s", out)
	}
}

func TestScanKeepsSameNameInDifferentProjects(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "shared.mcp.json")
	data := `{"projects":{
		"/z":{"mcpServers":{"shared":{"command":"echo","args":["z"]}}},
		"/a":{"mcpServers":{"shared":{"command":"echo","args":["a"]}}}
	}}`
	if err := os.WriteFile(cfg, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runScan(t, "-f", "json", cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	var got report.Report
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.ScannedFiles) != 1 || len(got.Results) != 2 {
		t.Fatalf("want one file and two servers, got %d files and %d servers", len(got.ScannedFiles), len(got.Results))
	}
	if got.Results[0].Target != "echo a" || got.Results[1].Target != "echo z" {
		t.Fatalf("unexpected server order: %q, %q", got.Results[0].Target, got.Results[1].Target)
	}
}

func TestScanRejectsInvalidDirectoryConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "broken.mcp.json")
	if err := os.WriteFile(cfg, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runScan(t, dir)
	if err == nil || !strings.Contains(err.Error(), cfg) || out != "" {
		t.Fatalf("want a config error with the file path, got output %q, error %v", out, err)
	}
}

func TestScanProjectOnlySkipsGlobalConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	project := t.TempDir()
	globalConfig := filepath.Join(home, ".claude.json")
	projectConfig := filepath.Join(project, ".mcp.json")
	data := []byte(`{"mcpServers":{"notes":{"command":"echo","args":["notes"]}}}`)
	for _, path := range []string{globalConfig, projectConfig} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, projectOnly := range []bool{false, true} {
		args := []string{"--project", project, "-f", "json"}
		if projectOnly {
			args = append(args, "--project-only")
		}
		out, err := runScan(t, args...)
		if err != nil {
			t.Fatal(err)
		}
		var got report.Report
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(got.ScannedFiles, projectConfig) || slices.Contains(got.ScannedFiles, globalConfig) == projectOnly {
			t.Fatalf("unexpected files with project-only=%t: %v", projectOnly, got.ScannedFiles)
		}
	}
}

func TestScanRejectsInvalidFlags(t *testing.T) {
	cfg := writeServerConfig(t, t.TempDir())
	for _, tc := range []struct {
		flag string
		want string
	}{
		{"--fail-on=hgh", "invalid --fail-on"},
		{"--format=yaml", "unknown format"},
		{"--timeout=0s", "--timeout must be positive"},
		{"--transport=typo", "invalid --transport"},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			out, err := runScan(t, tc.flag, cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) || out != "" {
				t.Fatalf("want %q without a report, got output %q, error %v", tc.want, out, err)
			}
		})
	}
}

func TestFailedAuditStillProducesJSON(t *testing.T) {
	out, err := runScan(t, "-f", "json", filepath.Join("..", "..", "examples", "vulnerable.mcp.json"))
	if !errors.Is(err, errAuditFailed) || !json.Valid([]byte(out)) {
		t.Fatalf("want a failed audit with valid JSON, got valid JSON %t, error %v", json.Valid([]byte(out)), err)
	}
}

func TestInspectRequiresOneServer(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "empty.mcp.json")
	if err := os.WriteFile(cfg, []byte(`{"mcpServers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := rootCmd()
	cmd.SetArgs([]string{"inspect", cfg})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "found 0") {
		t.Fatalf("want an error for an empty config, got %v", err)
	}
}
