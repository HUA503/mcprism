package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStdout runs fn while capturing everything the process writes to
// os.Stdout (audit renders to os.Stdout, not the cobra writer).
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	_ = w.Close()
	var b bytes.Buffer
	_, _ = io.Copy(&b, r)
	return b.String()
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
