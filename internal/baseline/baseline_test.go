package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/HUA503/mcprism/internal/rules"
)

const sampleReport = `{"results":[{"findings":[
  {"ruleId":"MCP201","server":"s1","location":"tool:evil"},
  {"ruleId":"MCP304","server":"s1","location":"tool:t"}
]}]}`

func writeBaseline(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad(t *testing.T) {
	p := writeBaseline(t, sampleReport)
	base, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(base) != 2 {
		t.Fatalf("expected 2 baseline keys, got %d: %v", len(base), base)
	}
	if !base[Key("s1", "MCP201", "tool:evil")] {
		t.Error("missing expected baseline key for MCP201")
	}
}

func TestLoadRejectsNonJSON(t *testing.T) {
	p := writeBaseline(t, "not a report")
	if _, err := Load(p); err == nil {
		t.Fatal("expected an error for a non-JSON baseline")
	}
}

func TestApply(t *testing.T) {
	p := writeBaseline(t, sampleReport)
	base, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	r := &rules.Result{Findings: []rules.Finding{
		{Server: "s1", RuleID: "MCP201", Location: "tool:evil"}, // accepted
		{Server: "s1", RuleID: "MCP305", Location: "tool:new"},  // new
	}}
	Apply([]*rules.Result{r}, base, p)

	if len(r.Findings) != 1 || r.Findings[0].RuleID != "MCP305" {
		t.Errorf("expected only the new MCP305 to stay active, got %+v", r.Findings)
	}
	if len(r.Suppressed) != 1 || r.Suppressed[0].Finding.RuleID != "MCP201" {
		t.Fatalf("expected MCP201 to be suppressed, got %+v", r.Suppressed)
	}
}
