package ui

import (
	"os"
	"strings"

	"github.com/HUA503/mcprism/internal/rules"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
)

// Catppuccin Mocha palette, shared by the table report and TUI.
var (
	Subtle = lipgloss.Color("#6c7086")
	Text   = lipgloss.Color("#cdd6f4")
	Crit   = lipgloss.Color("#f38ba8")
	High   = lipgloss.Color("#fab387")
	Med    = lipgloss.Color("#f9e2af")
	Low    = lipgloss.Color("#89b4fa")
	Info   = lipgloss.Color("#a6adc8")
	Green  = lipgloss.Color("#a6e3a1")
	Purple = lipgloss.Color("#cba6f7")
	Cyan   = lipgloss.Color("#94e2d5")

	// TUI panel colors.
	Sel    = lipgloss.Color("#313244")
	Border = lipgloss.Color("#45475a")
	Accent = lipgloss.Color("#89b4fa")
)

// TermWidth returns the terminal width, falling back to 100 when not a TTY.
func TermWidth() int {
	w, _, err := term.GetSize(os.Stdout.Fd())
	if err != nil || w < 60 {
		return 100
	}
	return w
}

// Trunc hard-truncates a string to n cells, using the active ellipsis glyph.
func Trunc(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= n {
		return s
	}
	ell := Sym("hellip")
	budget := n - len([]rune(ell))
	if budget < 1 {
		budget = 1
	}
	r := []rune(s)
	if len(r) <= budget {
		return s
	}
	return string(r[:budget]) + ell
}

// TruncWords truncates at a word boundary when possible, so advice is not cut
// mid-word. It only breaks inside a token when the token itself is too long.
func TruncWords(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= n {
		return s
	}
	ell := Sym("hellip")
	budget := n - len([]rune(ell))
	if budget < 1 {
		budget = 1
	}
	r := []rune(s)
	if len(r) <= budget {
		return s
	}
	head := string(r[:budget])
	if i := strings.LastIndexByte(head, ' '); i > budget/2 {
		head = head[:i]
	}
	return strings.TrimRight(head, " ,;:-") + ell
}

// SevColor maps a severity to its palette color.
func SevColor(s rules.Severity) lipgloss.Color {
	switch s {
	case rules.SeverityCritical:
		return Crit
	case rules.SeverityHigh:
		return High
	case rules.SeverityMedium:
		return Med
	case rules.SeverityLow:
		return Low
	}
	return Info
}

// SevTag renders a fixed-width, colored severity label.
func SevTag(s rules.Severity) string {
	t := map[rules.Severity]string{
		rules.SeverityCritical: "CRIT", rules.SeverityHigh: "HIGH",
		rules.SeverityMedium: "MED", rules.SeverityLow: "LOW", rules.SeverityInfo: "INFO",
	}[s]
	return lipgloss.NewStyle().Foreground(SevColor(s)).Bold(true).Width(4).Render(t)
}

// GradeBadge renders the letter grade with its color.
func GradeBadge(g string) string {
	c := map[string]lipgloss.Color{
		"A": Green, "B": Cyan, "C": Med, "D": High, "F": Crit,
	}[g]
	return lipgloss.NewStyle().Foreground(c).Bold(true).Padding(0, 1).Render(g)
}

// CapChips renders the active capability chips.
func CapChips(c rules.Capabilities) string {
	type chip struct {
		on   bool
		text string
		col  lipgloss.Color
	}
	chips := []chip{
		{c.CanShell, "SHELL", Crit},
		{c.CanWriteFiles, "WRITE", High},
		{c.CanReadFiles, "READ", Low},
		{c.CanNetwork, "NET", Purple},
		{c.CanAccessDB, "DB", Med},
		{c.CanBrowser, "BROWSER", Cyan},
		{c.CanSendEmail, "MAIL", High},
	}
	var parts []string
	for _, ch := range chips {
		if !ch.on {
			continue
		}
		parts = append(parts, lipgloss.NewStyle().Foreground(ch.col).Render(ch.text))
	}
	if len(parts) == 0 {
		return lipgloss.NewStyle().Foreground(Subtle).Render("none")
	}
	sep := lipgloss.NewStyle().Foreground(Subtle).Render(" " + Sym("middot") + " ")
	return strings.Join(parts, sep)
}
