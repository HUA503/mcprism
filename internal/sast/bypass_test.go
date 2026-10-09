package sast

import "testing"

// Regression tests for the adversarial audit findings: a boundary guard on a
// different variable must not silence a file-path finding, and a string
// literal used in concatenation must not be treated as a constant SSRF target.

// A startswith guard on `safe` must not silence open(name) where `name` is the
// unguarded, controllable argument.
func TestPythonGuardOnOtherVarDoesNotConfine(t *testing.T) {
	p := writeSastFile(t, t.TempDir(), "bypass.py", `import os
@mcp.tool()
def read_thing(name: str, ok: str):
    base = os.path.realpath("/srv/data")
    safe = os.path.realpath(os.path.join(base, ok))
    if safe.startswith(base):
        pass
    with open(name) as f:
        return f.read()
`)
	if ids := ruleIDSet(AnalyzeFile(p)); !ids["MCP803"] {
		t.Fatalf("expected MCP803 for open(name) guarded only on another var, got %v", ids)
	}
}

// open() on the exact startswith-guarded variable stays quiet.
func TestPythonConfinedByStartswith(t *testing.T) {
	p := writeSastFile(t, t.TempDir(), "safe.py", `import os
@mcp.tool()
def read_thing(ok: str):
    base = "/srv/data"
    safe = os.path.realpath(os.path.join(base, ok))
    if not safe.startswith(base):
        raise Exception("out")
    with open(safe) as f:
        return f.read()
`)
	if ids := ruleIDSet(AnalyzeFile(p)); ids["MCP803"] {
		t.Fatalf("did not expect MCP803 for open() on the startswith-guarded var, got %v", ids)
	}
}

// fetch("https://" + url) is attacker-controlled, not a constant target.
func TestJSConstURLConcatNotConstant(t *testing.T) {
	p := writeSastFile(t, t.TempDir(), "ssrf.js", `const { z } = require("zod");
server.tool("get", { url: z.string() }, async ({ url }) => {
  return fetch("https://" + url);
});
`)
	if ids := ruleIDSet(AnalyzeFile(p)); !ids["MCP802"] {
		t.Fatalf("expected MCP802 for fetch(\"https://\" + url), got %v", ids)
	}
}

// A template literal with interpolation is attacker-controlled.
func TestJSTemplateURLInterpolationNotConstant(t *testing.T) {
	p := writeSastFile(t, t.TempDir(), "ssrf2.js", `const { z } = require("zod");
server.tool("get", { host: z.string() }, async ({ host }) => {
  return fetch(`+"`https://${host}/x`"+`);
});
`)
	if ids := ruleIDSet(AnalyzeFile(p)); !ids["MCP802"] {
		t.Fatalf("expected MCP802 for an interpolated template URL, got %v", ids)
	}
}

// A single full string literal URL is a constant target and stays quiet.
func TestJSConstURLLiteralQuiet(t *testing.T) {
	p := writeSastFile(t, t.TempDir(), "fixed.js", `server.tool("get", {}, async () => {
  return fetch("https://api.example.com/v1/thing");
});
`)
	if ids := ruleIDSet(AnalyzeFile(p)); ids["MCP802"] {
		t.Fatalf("did not expect MCP802 for a constant literal URL, got %v", ids)
	}
}

// requests.get("https://" + url) in Python is attacker-controlled.
func TestPythonConstURLConcatNotConstant(t *testing.T) {
	p := writeSastFile(t, t.TempDir(), "ssrf.py", `import requests
@mcp.tool()
def get(url: str):
    return requests.get("https://" + url)
`)
	if ids := ruleIDSet(AnalyzeFile(p)); !ids["MCP802"] {
		t.Fatalf("expected MCP802 for requests.get(\"https://\" + url), got %v", ids)
	}
}

// http.Get("https://" + u) in Go is attacker-controlled.
func TestGoConstURLConcatNotConstant(t *testing.T) {
	p := writeSastFile(t, t.TempDir(), "ssrf.go", `package main

s.AddTool(mcp.NewTool("get", mcp.String("u", mcp.Required())),
	func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		u := req.RequireString("u")
		resp, err := http.Get("https://" + u)
		if err != nil {
			return nil, err
		}
		_ = resp
		return nil, nil
	})
`)
	if ids := ruleIDSet(AnalyzeFile(p)); !ids["MCP802"] {
		t.Fatalf("expected MCP802 for http.Get(\"https://\" + u), got %v", ids)
	}
}
