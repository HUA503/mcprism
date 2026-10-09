package sast

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A file larger than the per-file cap must be skipped entirely even if it
// contains a sink that would otherwise be reported.
func TestOversizedFileSkipped(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big.js")
	padding := strings.Repeat("// padding line to exceed size limit\n", 70000) // ~2.6 MiB
	if err := os.WriteFile(big, []byte(padding+"eval(userInput)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if issues := AnalyzeFile(big); len(issues) != 0 {
		t.Fatalf("oversized file must be skipped, got %d issues", len(issues))
	}
}

func TestDepthOf(t *testing.T) {
	cases := map[string]int{"": 0, ".": 0, "a": 1, "a/b": 2, "a/b/c": 3}
	for rel, want := range cases {
		if got := depthOf(rel); got != want {
			t.Errorf("depthOf(%q)=%d want %d", rel, got, want)
		}
	}
}
