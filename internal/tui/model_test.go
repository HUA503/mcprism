package tui

import (
	"strings"
	"testing"

	"github.com/HUA503/mcprism/internal/config"
	"github.com/HUA503/mcprism/internal/rules"
	tea "github.com/charmbracelet/bubbletea"
)

func mkResults() []*rules.Result {
	return []*rules.Result{
		{
			Server:    &config.Server{Name: "evil-shell"},
			Connected: false,
			Grade:     "F",
			Findings: []rules.Finding{
				{RuleID: "MCP104", Title: "Remote code fetched and executed", Severity: rules.SeverityCritical, Evidence: "curl|sh"},
				{RuleID: "MCP803", Title: "Path traversal via file read", Severity: rules.SeverityHigh, Evidence: "open(name)"},
			},
		},
		{
			Server:    &config.Server{Name: "clean"},
			Connected: true,
			Grade:     "A",
		},
	}
}

func sized(m model, w, h int) model {
	n, _ := m.Update(tea.WindowSizeMsg{Width: w, Height: h})
	return n.(model)
}

func TestVisibleFindingsFilter(t *testing.T) {
	m := model{results: mkResults(), sSel: 0}
	if got := len(m.visibleFindings()); got != 2 {
		t.Fatalf("unfiltered = %d, want 2", got)
	}
	m.search = "path"
	if got := len(m.visibleFindings()); got != 1 || m.visibleFindings()[0].RuleID != "MCP803" {
		t.Fatalf("filter 'path' should leave only MCP803, got %v", m.visibleFindings())
	}
	m.search = "zzz"
	if len(m.visibleFindings()) != 0 {
		t.Fatal("non-matching query should return no findings")
	}
}

func TestSearchKeypress(t *testing.T) {
	m := sized(model{results: mkResults(), pane: 1}, 100, 30)

	n, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = n.(model)
	if !m.searching {
		t.Fatal("'/' should enter search mode")
	}
	for _, r := range []rune("path") {
		n, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		m = n.(model)
	}
	if m.search != "path" {
		t.Fatalf("search = %q, want path", m.search)
	}
	n, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = n.(model)
	if m.searching {
		t.Fatal("enter should leave search input mode")
	}
	if len(m.visibleFindings()) != 1 {
		t.Fatal("filter should still apply after enter")
	}

	// Esc clears the query.
	n, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = n.(model)
	n, _ = m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	m = n.(model)
	if m.search != "" || m.searching {
		t.Fatal("esc in search should clear query and exit input")
	}
}

func TestNarrowViewSingleColumn(t *testing.T) {
	// 50 columns is below the two-column threshold.
	m := sized(model{results: mkResults(), pane: 0}, 50, 28)
	v := m.View()
	if !strings.Contains(v, "SERVERS") {
		t.Fatal("narrow pane=0 should show the servers panel")
	}
	if strings.Contains(v, "FINDINGS") {
		t.Fatal("narrow pane=0 should not render the findings column")
	}

	m.pane = 1
	v = m.View()
	if !strings.Contains(v, "FINDINGS") {
		t.Fatal("narrow pane=1 should show the findings panel full width")
	}
}

func TestWideViewTwoColumns(t *testing.T) {
	m := sized(model{results: mkResults(), pane: 0}, 100, 30)
	v := m.View()
	if !strings.Contains(v, "SERVERS") || !strings.Contains(v, "FINDINGS") {
		t.Fatal("wide view should render both columns")
	}
}

func TestDetailBoundsWithFilter(t *testing.T) {
	m := sized(model{results: mkResults(), pane: 2, fSel: 99}, 100, 30)
	m.search = "path" // only one finding remains; fSel 99 is out of range
	// Must not panic despite the stale selection.
	_ = m.detailText()
	_ = m.detailBox()
}

func TestMoveClampsSelection(t *testing.T) {
	m := model{results: mkResults(), pane: 0, sSel: 0}
	for i := 0; i < 10; i++ {
		m = m.moved(1)
	}
	if m.sSel != len(m.results)-1 {
		t.Fatalf("sSel should clamp to last server, got %d", m.sSel)
	}
}
