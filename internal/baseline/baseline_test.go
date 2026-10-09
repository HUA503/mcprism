package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/HUA503/mcprism/internal/rules"
)

const sampleReport = `{"results":[{"findings":[
  {"ruleId":"MCP201","server":"s1","location":"tool:evil","severity":"HIGH","evidence":"evil desc"},
  {"ruleId":"MCP304","server":"s1","location":"tool:t","severity":"MEDIUM","evidence":"schema"}
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
	if !base[Key("s1", "MCP201", "tool:evil", "HIGH", "evil desc")] {
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
		{Server: "s1", RuleID: "MCP201", Location: "tool:evil", Severity: rules.SeverityHigh, Evidence: "evil desc"}, // accepted
		{Server: "s1", RuleID: "MCP305", Location: "tool:new"},                                                       // new
	}}
	Apply([]*rules.Result{r}, base, p)

	if len(r.Findings) != 1 || r.Findings[0].RuleID != "MCP305" {
		t.Errorf("expected only the new MCP305 to stay active, got %+v", r.Findings)
	}
	if len(r.Suppressed) != 1 || r.Suppressed[0].Finding.RuleID != "MCP201" {
		t.Fatalf("expected MCP201 to be suppressed, got %+v", r.Suppressed)
	}
}

// A finding whose severity was upgraded after the baseline was taken must be
// reported again instead of remaining silently accepted.
func TestApplySeverityUpgradeReReports(t *testing.T) {
	p := writeBaseline(t, sampleReport)
	base, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	r := &rules.Result{Findings: []rules.Finding{
		{Server: "s1", RuleID: "MCP201", Location: "tool:evil", Severity: rules.SeverityCritical, Evidence: "evil desc"},
	}}
	Apply([]*rules.Result{r}, base, p)
	if len(r.Findings) != 1 {
		t.Fatalf("upgraded finding must stay active, got %d active / %d suppressed", len(r.Findings), len(r.Suppressed))
	}
}

// Two instances of the same rule with an empty location but different evidence
// must not collapse into one accepted finding.
func TestKeyDistinguishesEvidence(t *testing.T) {
	a := Key("s", "MCP101", "", "HIGH", "token A")
	b := Key("s", "MCP101", "", "HIGH", "token B")
	if a == b {
		t.Fatal("findings with different evidence must have different keys")
	}
	// Whitespace/case only differences are treated as the same evidence.
	if Key("s", "MCP101", "", "HIGH", "same  thing") != Key("s", "MCP101", "", "HIGH", "same thing") {
		t.Fatal("normalized evidence should hash equally")
	}
}
