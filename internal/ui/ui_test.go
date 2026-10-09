package ui

import (
	"strings"
	"testing"

	"github.com/HUA503/mcprism/internal/rules"
)

func TestInitASCII(t *testing.T) {
	Init(false, true)
	if !ASCII() {
		t.Fatal("expected ASCII mode after forcing --ascii")
	}
	if got := Sym("bullet"); got != "*" {
		t.Fatalf("bullet = %q, want *", got)
	}
	if got := Sym("check"); got != "[x]" {
		t.Fatalf("check = %q, want [x]", got)
	}
	if strings.ContainsAny(HBar(5), "─") {
		t.Fatalf("ASCII rule must use '-', got %q", HBar(5))
	}
}

func TestInitNoColorFromEnv(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	Init(false, false)
	if ColorEnabled() {
		t.Fatal("NO_COLOR should disable color")
	}
	// NO_COLOR must not force ASCII glyphs: the two are independent.
	if ASCII() {
		t.Fatal("NO_COLOR alone must not switch to ASCII glyphs")
	}
}

func TestInitDumbTermIsASCII(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "dumb")
	t.Setenv("WT_SESSION", "")
	Init(false, false)
	if !ASCII() {
		t.Fatal("TERM=dumb should fall back to ASCII glyphs")
	}
}

func TestTruncWords(t *testing.T) {
	s := "Run the server in a sandbox without network egress"
	got := TruncWords(s, 24)
	if len([]rune(got)) > 24 {
		t.Fatalf("result exceeds width: %q (%d)", got, len([]rune(got)))
	}
	if !strings.HasSuffix(got, Sym("hellip")) {
		t.Fatalf("expected ellipsis suffix, got %q", got)
	}
	// Should not cut in the middle of a word when a boundary is available.
	trimmed := strings.TrimSuffix(got, Sym("hellip"))
	if !strings.HasSuffix(trimmed, " ") && strings.Contains(s[:min(len(s), 24)], " ") {
		// Last rune should be the end of a word, not a word fragment.
		tail := strings.TrimRight(trimmed, " ")
		if !strings.HasPrefix(s, tail+" ") && s != tail {
			t.Fatalf("truncated mid-word: %q", got)
		}
	}
	if TruncWords("short", 80) != "short" {
		t.Fatal("short string should be returned unchanged")
	}
}

func TestSevAndGradeRendering(t *testing.T) {
	if !strings.Contains(SevTag(rules.SeverityCritical), "CRIT") {
		t.Fatal("critical tag should contain CRIT")
	}
	if !strings.Contains(GradeBadge("F"), "F") {
		t.Fatal("grade badge should contain F")
	}
	caps := rules.Capabilities{CanShell: true, CanNetwork: true}
	chips := CapChips(caps)
	if !strings.Contains(chips, "SHELL") || !strings.Contains(chips, "NET") {
		t.Fatalf("chips missing capabilities: %q", chips)
	}
	if strings.Contains(CapChips(rules.Capabilities{}), "SHELL") {
		t.Fatal("empty capabilities should not render SHELL")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
