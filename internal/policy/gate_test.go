package policy

import (
	"testing"

	"github.com/HUA503/mcprism/internal/config"
	"github.com/HUA503/mcprism/internal/rules"
)

// The default profile must fail the gate on a critical finding so a bare
// `mcprism scan` never exits 0 for a known-RCE server.
func TestDefaultProfileFailsOnCritical(t *testing.T) {
	pol, err := Builtin("default")
	if err != nil {
		t.Fatal(err)
	}
	r := &rules.Result{Findings: []rules.Finding{{Severity: rules.SeverityCritical}}}
	c := Evaluate([]*rules.Result{r}, pol, "default", "")
	if c.Pass {
		t.Fatal("default profile must fail when a critical finding exists")
	}
}

// Medium and below still pass under the default profile (strict/ci opt in to
// fail-on-high).
func TestDefaultProfilePassesOnMedium(t *testing.T) {
	pol, err := Builtin("default")
	if err != nil {
		t.Fatal(err)
	}
	r := &rules.Result{Findings: []rules.Finding{{Severity: rules.SeverityMedium}}}
	c := Evaluate([]*rules.Result{r}, pol, "default", "")
	if !c.Pass {
		t.Fatalf("default profile should pass medium findings, reason=%q", c.Reason)
	}
}

// Deny commands must match Windows-style paths and extensions.
func TestDenyCommandWindowsPath(t *testing.T) {
	pol := &Policy{}
	pol.Deny.Commands = []string{"npx.cmd"}
	r := &rules.Result{Server: &config.Server{Name: "w", Command: `C:\Program Files\nodejs\npx.cmd`}}
	hit, _ := matchDeny(r, pol)
	if !hit {
		t.Fatal("expected deny to match C:\\...\\npx.cmd")
	}
}
