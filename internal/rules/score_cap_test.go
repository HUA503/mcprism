package rules

import "testing"

// A single critical finding (e.g. remote code execution) must land in the F
// band, not score 75/C like a weighted-average would produce.
func TestCriticalVetoCapsToF(t *testing.T) {
	r := &Result{Findings: []Finding{{Severity: SeverityCritical}}}
	Rescore(r)
	if r.Score > 50 || r.Grade != "F" {
		t.Fatalf("critical must cap score to <=50 and grade F, got score=%d grade=%s", r.Score, r.Grade)
	}
}

func TestHighCapsToD(t *testing.T) {
	r := &Result{Findings: []Finding{{Severity: SeverityHigh}}}
	Rescore(r)
	if r.Score > 69 || r.Grade != "D" {
		t.Fatalf("a lone high must cap to <=69/D, got score=%d grade=%s", r.Score, r.Grade)
	}
}

func TestCleanServerStaysA(t *testing.T) {
	r := &Result{}
	Rescore(r)
	if r.Score != 100 || r.Grade != "A" {
		t.Fatalf("clean server should be 100/A, got score=%d grade=%s", r.Score, r.Grade)
	}
}
