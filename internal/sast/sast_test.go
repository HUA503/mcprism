package sast

import (
	"os"
	"testing"
)

func ruleIDSet(iss []Issue) map[string]bool {
	m := map[string]bool{}
	for _, x := range iss {
		m[x.RuleID] = true
	}
	return m
}

func TestVulnerableJS(t *testing.T) {
	ids := ruleIDSet(AnalyzeFile("testdata/vuln.js"))
	for _, want := range []string{"MCP801", "MCP802", "MCP803", "MCP804", "MCP806"} {
		if !ids[want] {
			t.Errorf("vuln.js: expected finding %s, got %v", want, ids)
		}
	}
}

func TestSafeJS(t *testing.T) {
	if iss := AnalyzeFile("testdata/safe.js"); len(iss) != 0 {
		t.Errorf("safe.js: expected no findings, got %d: %v", len(iss), iss)
	}
}

func TestVulnerablePython(t *testing.T) {
	ids := ruleIDSet(AnalyzeFile("testdata/vuln.py"))
	for _, want := range []string{"MCP801", "MCP802", "MCP803", "MCP804", "MCP805", "MCP806"} {
		if !ids[want] {
			t.Errorf("vuln.py: expected finding %s, got %v", want, ids)
		}
	}
}

func TestSafePython(t *testing.T) {
	if iss := AnalyzeFile("testdata/safe.py"); len(iss) != 0 {
		t.Errorf("safe.py: expected no findings, got %d: %v", len(iss), iss)
	}
}

func TestVulnerableGo(t *testing.T) {
	ids := ruleIDSet(AnalyzeFile("testdata/vuln.go"))
	for _, want := range []string{"MCP801", "MCP802", "MCP803", "MCP806"} {
		if !ids[want] {
			t.Errorf("vuln.go: expected finding %s, got %v", want, ids)
		}
	}
}

func TestSafeGo(t *testing.T) {
	if iss := AnalyzeFile("testdata/safe.go"); len(iss) != 0 {
		t.Errorf("safe.go: expected no findings, got %d: %v", len(iss), iss)
	}
}

func TestAnalyzeTree(t *testing.T) {
	iss, err := Analyze("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(iss) != 17 {
		t.Errorf("expected 17 findings across the tree, got %d", len(iss))
	}
}

func TestUnsupportedFile(t *testing.T) {
	if iss := AnalyzeFile("testdata/vuln.js"); len(iss) == 0 {
		t.Error("sanity: vuln.js should report")
	}
}

func TestIsSourceProject(t *testing.T) {
	if !IsSourceProject("testdata") {
		t.Error("testdata is a source project")
	}
}

// Dynamic require of an agent-controlled module name is MCP807, distinct from
// the unsafe-deserialization rule MCP805.
func TestDynamicRequireIsMCP807(t *testing.T) {
	src := `server.tool("load", {name: z.string()}, async ({name}) => {
  const mod = require(name)
  return mod.x
})
`
	dir := t.TempDir()
	p := dir + "/dyn.js"
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	ids := ruleIDSet(analyzeJS(p))
	if !ids["MCP807"] {
		t.Fatalf("expected MCP807 for dynamic require, got %v", ids)
	}
	if ids["MCP805"] {
		t.Fatalf("dynamic require must not be reported as MCP805, got %v", ids)
	}
}
