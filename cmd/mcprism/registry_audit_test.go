package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/HUA503/mcprism/internal/registry"
)

func TestRegistryAuditRequireComplete(t *testing.T) {
	entry := registry.Entry{Server: registry.ServerDetail{
		Name: "example/server", Version: "1.0.0",
		Remotes: []registry.Transport{{Type: "streamable-http", URL: "https://example.com/mcp"}},
	}}
	cases := []struct {
		name        string
		more        bool
		unsupported bool
		missingName bool
		require     bool
		wantError   bool
	}{
		{name: "complete", require: true},
		{name: "additional page", more: true, require: true, wantError: true},
		{name: "unsupported transport", unsupported: true, require: true, wantError: true},
		{name: "missing identity", missingName: true, require: true, wantError: true},
		{name: "optional gate", more: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := entry
			if tc.unsupported {
				e.Server.Remotes = append(append([]registry.Transport(nil), e.Server.Remotes...), registry.Transport{Type: "unknown"})
			}
			cmd := registryAuditCmdWithSearch(func(context.Context, string, int) ([]registry.Entry, bool, error) {
				if tc.missingName {
					bad := e
					bad.Server.Name = ""
					return []registry.Entry{e, bad}, tc.more, nil
				}
				return []registry.Entry{e}, tc.more, nil
			})
			output := filepath.Join(t.TempDir(), "report.json")
			args := []string{"filesystem", "--format", "json", "--output", output}
			if tc.require {
				args = append(args, "--require-complete")
			}
			cmd.SetArgs(args)
			err := cmd.Execute()
			if (err != nil) != tc.wantError {
				t.Fatalf("Execute() error = %v, want error %v", err, tc.wantError)
			}
			if _, err := os.Stat(output); err != nil {
				t.Fatalf("report was not written: %v", err)
			}
		})
	}
}
