package sast

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeSastFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A bare filepath.Clean is not a boundary check and must not silence MCP803.
func TestGoCleanIsNotConfined(t *testing.T) {
	p := writeSastFile(t, t.TempDir(), "clean.go", `package main

s.AddTool(mcp.NewTool("read_file", mcp.String("file", mcp.Required())),
	func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		p := req.RequireString("file")
		q := filepath.Clean(p)
		_ = q
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(string(data)), nil
	})
`)
	if ids := ruleIDSet(AnalyzeFile(p)); !ids["MCP803"] {
		t.Fatalf("expected MCP803 for filepath.Clean without a HasPrefix guard, got %v", ids)
	}
}

// A HasPrefix guard on the exact variable that reaches the sink is confined.
func TestGoCleanConfinedByHasPrefix(t *testing.T) {
	p := writeSastFile(t, t.TempDir(), "safe.go", `package main

s.AddTool(mcp.NewTool("read_file", mcp.String("name", mcp.Required())),
	func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name := req.RequireString("name")
		base := "/var/data"
		full := filepath.Join(base, name)
		if !strings.HasPrefix(full, base) {
			return nil, os.ErrPermission
		}
		data, err := os.ReadFile(full)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(string(data)), nil
	})
`)
	if ids := ruleIDSet(AnalyzeFile(p)); ids["MCP803"] {
		t.Fatalf("did not expect MCP803 for a HasPrefix-guarded path, got %v", ids)
	}
}

// An unrelated resolve/startsWith must not silence MCP803 for a directly-read
// controllable path.
func TestJSUnrelatedResolveDoesNotConfine(t *testing.T) {
	p := writeSastFile(t, t.TempDir(), "unrelated.js", `const { z } = require("zod");
server.tool("read", { path: z.string() }, async ({ path }) => {
  const x = path.resolve("/tmp");
  if (x.startsWith("/a")) {}
  fs.readFile(path, (e, d) => {});
});
`)
	if ids := ruleIDSet(AnalyzeFile(p)); !ids["MCP803"] {
		t.Fatalf("expected MCP803 for a controllable path with unrelated resolve/startsWith, got %v", ids)
	}
}

// A startsWith guard on the exact variable that reaches the sink is confined.
func TestJSConfinedByStartsWith(t *testing.T) {
	p := writeSastFile(t, t.TempDir(), "safe.js", `const { z } = require("zod");
server.tool("read", { name: z.string() }, async ({ name }) => {
  const base = "/var/data";
  const full = path.resolve(base, name);
  if (!full.startsWith(base)) throw new Error("out");
  fs.readFileSync(full);
});
`)
	if ids := ruleIDSet(AnalyzeFile(p)); ids["MCP803"] {
		t.Fatalf("did not expect MCP803 for a startsWith-guarded path, got %v", ids)
	}
}
