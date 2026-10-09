package report

import (
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/HUA503/mcprism/internal/config"
	"github.com/HUA503/mcprism/internal/rules"
)

func sampleReport() *Report {
	srv := &config.Server{Name: "srv", Transport: config.TransportStdio, Command: "npx", Args: []string{"x"}, Source: "/p/mcp.json"}
	res := &rules.Result{
		Server:     srv,
		ServerName: "srv",
		Findings: []rules.Finding{
			{RuleID: "MCP803", Title: "path", Severity: rules.SeverityHigh, Location: "src/tool.js:42", Evidence: "open(name)", Advice: "confine it"},
			{RuleID: "MCP101", Title: "cred", Severity: rules.SeverityCritical, Location: "env.TOKEN", Evidence: "=CMD|'calc'!A1", Advice: "move it"},
		},
	}
	return &Report{Tool: "mcprism", Version: "test", Results: []*rules.Result{res}}
}

// SARIF must carry a legal relative artifact URI and a startLine region for
// source-code findings.
func TestSARIFLineRegionAndURI(t *testing.T) {
	b, err := RenderSARIF(sampleReport())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	run := doc["runs"].([]any)[0].(map[string]any)
	results := run["results"].([]any)
	var foundLine bool
	for _, rr := range results {
		r0 := rr.(map[string]any)
		loc := r0["locations"].([]any)[0].(map[string]any)
		phys := loc["physicalLocation"].(map[string]any)
		art := phys["artifactLocation"].(map[string]any)
		uri := art["uri"].(string)
		if strings.Contains(uri, " ") || strings.ContainsAny(uri, "()") {
			t.Fatalf("uri %q is not a legal relative URI", uri)
		}
		if region, ok := phys["region"].(map[string]any); ok {
			if uri == "src/tool.js" && region["startLine"].(float64) == 42 {
				foundLine = true
			}
		}
	}
	if !foundLine {
		t.Fatalf("did not find src/tool.js with startLine 42:\n%s", b)
	}
}

// Cells beginning with a formula trigger character must be quoted as text.
func TestCSVFormulaInjection(t *testing.T) {
	b, err := RenderCSV(sampleReport())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(b))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	var evidence string
	for _, row := range rows[1:] {
		if row[3] == "MCP101" {
			evidence = row[7]
		}
	}
	if !strings.HasPrefix(evidence, "'=CMD") {
		t.Fatalf("expected leading apostrophe before formula cell, got %q", evidence)
	}
}

// CycloneDX vulnerabilities must reference their component via bom-ref/affects.
func TestCycloneDXAffectsRef(t *testing.T) {
	b, err := RenderCycloneDX(sampleReport())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	comp := doc["components"].([]any)[0].(map[string]any)
	ref, ok := comp["bom-ref"].(string)
	if !ok || ref == "" {
		t.Fatalf("component missing bom-ref: %v", comp)
	}
	vulns := doc["vulnerabilities"].([]any)
	if len(vulns) != 2 {
		t.Fatalf("want 2 vulnerabilities, got %d", len(vulns))
	}
	for _, vv := range vulns {
		v := vv.(map[string]any)
		aff := v["affects"].([]any)[0].(map[string]any)
		if aff["ref"] != ref {
			t.Fatalf("affects.ref %v != component bom-ref %q", aff["ref"], ref)
		}
		if strings.HasPrefix(v["id"].(string), "MCP803") {
			t.Fatalf("rule id must not be used as the vulnerability id: %v", v["id"])
		}
		rating := v["ratings"].([]any)[0].(map[string]any)
		if rating["method"] != "Other" {
			t.Fatalf("rating method should be Other, got %v", rating["method"])
		}
		props := v["properties"].([]any)
		if len(props) == 0 {
			t.Fatal("vulnerability should carry the mcprism ruleId in properties")
		}
	}
}
