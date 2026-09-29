package policy

import (
	"testing"
	"time"

	"github.com/HUA503/mcprism/internal/config"
	"github.com/HUA503/mcprism/internal/rules"
)

func mkResult(name, command string, caps rules.Capabilities, findings ...rules.Finding) *rules.Result {
	return &rules.Result{
		Server:       &config.Server{Name: name, Command: command},
		Capabilities: caps,
		Findings:     findings,
	}
}

func hasRule(r *rules.Result, id string) bool {
	for _, f := range r.Findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestParse(t *testing.T) {
	p, err := Parse([]byte(`
version: "1"
fail:
  on: high
rules:
  MCP106:
    severity: high
deny:
  commands: [nc]
`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Fail.On != "high" {
		t.Fatalf("got fail.on %q", p.Fail.On)
	}
	if p.Rules["MCP106"].Severity != "high" {
		t.Fatal("rule severity not parsed")
	}
	if len(p.Deny.Commands) != 1 || p.Deny.Commands[0] != "nc" {
		t.Fatal("deny commands not parsed")
	}
}

func TestBuiltin(t *testing.T) {
	for _, n := range ListProfiles() {
		if _, err := Builtin(n); err != nil {
			t.Fatalf("builtin %s: %v", n, err)
		}
	}
	if _, err := Builtin("nope"); err == nil {
		t.Fatal("expected error for unknown profile")
	}
}

func TestEnforceRuleOverrides(t *testing.T) {
	p, _ := Parse([]byte(`
rules:
  MCP101:
    enabled: false
  MCP106:
    severity: critical
`))
	r := mkResult("s", "", rules.Capabilities{},
		rules.Finding{RuleID: "MCP101", Severity: rules.SeverityHigh},
		rules.Finding{RuleID: "MCP106", Severity: rules.SeverityMedium},
	)
	Enforce([]*rules.Result{r}, p)
	if len(r.Findings) != 1 || r.Findings[0].RuleID != "MCP106" {
		t.Fatalf("MCP101 should be disabled, got %+v", r.Findings)
	}
	if r.Findings[0].Severity != rules.SeverityCritical {
		t.Fatalf("severity override failed, got %s", r.Findings[0].Severity)
	}
}

func TestEnforceDeny(t *testing.T) {
	p, _ := Parse([]byte(`deny: {commands: [nc]}`))
	r := mkResult("x", "nc", rules.Capabilities{})
	Enforce([]*rules.Result{r}, p)
	if !hasRule(r, "MCP700") {
		t.Fatal("deny should produce MCP700")
	}
}

func TestEnforceAllowWins(t *testing.T) {
	p, _ := Parse([]byte(`
allow: {commands: [nc]}
deny: {commands: [nc]}
`))
	r := mkResult("x", "nc", rules.Capabilities{})
	Enforce([]*rules.Result{r}, p)
	if hasRule(r, "MCP700") {
		t.Fatal("allow entry should prevent MCP700")
	}
}

func TestEnforceIsolation(t *testing.T) {
	p, _ := Parse([]byte(`capabilities: {requireNetworkIsolation: true}`))
	bad := mkResult("bad", "", rules.Capabilities{CanShell: true, CanNetwork: true})
	Enforce([]*rules.Result{bad}, p)
	if !hasRule(bad, "MCP701") {
		t.Fatal("shell+network under isolation should produce MCP701")
	}
	ok := mkResult("ok", "", rules.Capabilities{CanShell: true})
	Enforce([]*rules.Result{ok}, p)
	if hasRule(ok, "MCP701") {
		t.Fatal("shell without network should not produce MCP701")
	}
}

func TestSuppressions(t *testing.T) {
	sups := []Suppression{
		{Rule: "MCP101", Server: "x", Reason: "accepted", Expires: "2099-01-01"},
		{Rule: "MCP102", Reason: "old acceptance", Expires: "2000-01-01"},
	}
	r := &rules.Result{
		Server: &config.Server{Name: "x"},
		Findings: []rules.Finding{
			{RuleID: "MCP101", Severity: rules.SeverityHigh},
			{RuleID: "MCP102", Severity: rules.SeverityMedium},
		},
	}
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	ApplySuppressions([]*rules.Result{r}, sups, now)
	if len(r.Findings) != 1 || r.Findings[0].RuleID != "MCP102" {
		t.Fatalf("expired suppression should return MCP102, got %+v", r.Findings)
	}
	if len(r.Suppressed) != 1 || r.Suppressed[0].Reason != "accepted" {
		t.Fatalf("MCP101 should be suppressed with reason, got %+v", r.Suppressed)
	}
}

func TestEvaluate(t *testing.T) {
	p, _ := Parse([]byte(`fail: {on: high}`))
	bad := mkResult("bad", "", rules.Capabilities{}, rules.Finding{RuleID: "MCP101", Severity: rules.SeverityHigh})
	if c := Evaluate([]*rules.Result{bad}, p, "strict", "p.yml"); c.Pass {
		t.Fatal("high finding should fail the gate")
	}
	good := mkResult("good", "", rules.Capabilities{})
	if c := Evaluate([]*rules.Result{good}, p, "strict", "p.yml"); !c.Pass {
		t.Fatal("clean result should pass the gate")
	}
}
