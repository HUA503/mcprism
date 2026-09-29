package rules

import (
	"strings"
	"testing"

	"github.com/HUA503/mcprism/internal/config"
)

func TestDetectKnownToken(t *testing.T) {
	cases := []struct {
		v    string
		want bool
	}{
		{"AKIAIOSFODNN7EXAMPLE", true},
		{"ghp_" + strings.Repeat("A", 36), true},
		{"xoxb-" + strings.Repeat("a", 24), true},
		{"eyJhbGci.eyJzdWI.SflKxw", true},
		{"just-a-normal-value", false},
		{"", false},
	}
	for _, c := range cases {
		_, got := detectKnownToken(c.v)
		if got != c.want {
			t.Errorf("detectKnownToken(%q) = %v, want %v", c.v, got, c.want)
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	if shannonEntropy("") != 0 {
		t.Fatal("empty string entropy should be 0")
	}
	uniform := shannonEntropy("aaaaaaaaaa")
	mixed := shannonEntropy("aA1!bB2@cC3#dD4$")
	if mixed <= uniform {
		t.Fatalf("mixed entropy %v should exceed uniform %v", mixed, uniform)
	}
}

func TestMetadataTargetRule(t *testing.T) {
	in := Input{Server: &config.Server{Name: "m", URL: "http://169.254.169.254/latest/meta-data"}}
	r := Analyze(in)
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "MCP303" {
			found = true
			if f.Severity != SeverityHigh {
				t.Fatalf("metadata MCP303 should be high, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected MCP303 for the metadata endpoint")
	}
}

func TestPrivateTargetRule(t *testing.T) {
	in := Input{Server: &config.Server{Name: "p", URL: "http://192.168.10.5/mcp"}}
	r := Analyze(in)
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "MCP303" {
			found = true
			if f.Severity != SeverityLow {
				t.Fatalf("private MCP303 should be low, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected MCP303 for the private range")
	}
}
