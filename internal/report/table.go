package report

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
	"github.com/HUA503/mcprism/internal/rules"
)

// Catppuccin Mocha 调色板
var (
	colSubtle = lipgloss.Color("#6c7086")
	colText   = lipgloss.Color("#cdd6f4")
	colCrit   = lipgloss.Color("#f38ba8")
	colHigh   = lipgloss.Color("#fab387")
	colMed    = lipgloss.Color("#f9e2af")
	colLow    = lipgloss.Color("#89b4fa")
	colInfo   = lipgloss.Color("#a6adc8")
	colGreen  = lipgloss.Color("#a6e3a1")
	colPurple = lipgloss.Color("#cba6f7")
	colCyan   = lipgloss.Color("#94e2d5")
)

func termWidth() int {
	w, _, err := term.GetSize(os.Stdout.Fd())
	if err != nil || w < 60 {
		return 100
	}
	return w
}

func truncW(s string, n int) string {
	if lipgloss.Width(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func sevColor(s rules.Severity) lipgloss.Color {
	switch s {
	case rules.SeverityCritical:
		return colCrit
	case rules.SeverityHigh:
		return colHigh
	case rules.SeverityMedium:
		return colMed
	case rules.SeverityLow:
		return colLow
	}
	return colInfo
}

func sevTag(s rules.Severity) string {
	t := map[rules.Severity]string{
		rules.SeverityCritical: "CRIT", rules.SeverityHigh: "HIGH",
		rules.SeverityMedium: "MED", rules.SeverityLow: "LOW", rules.SeverityInfo: "INFO",
	}[s]
	return lipgloss.NewStyle().Foreground(sevColor(s)).Bold(true).Width(4).Render(t)
}

func gradeBadge(g string) string {
	c := map[string]lipgloss.Color{
		"A": colGreen, "B": colCyan, "C": colMed, "D": colHigh, "F": colCrit,
	}[g]
	return lipgloss.NewStyle().Foreground(c).Bold(true).Padding(0, 1).Render(g)
}

func capChips(c rules.Capabilities) string {
	type chip struct {
		on   bool
		text string
		col  lipgloss.Color
	}
	chips := []chip{
		{c.CanShell, "SHELL", colCrit},
		{c.CanWriteFiles, "WRITE", colHigh},
		{c.CanReadFiles, "READ", colLow},
		{c.CanNetwork, "NET", colPurple},
		{c.CanAccessDB, "DB", colMed},
		{c.CanBrowser, "BROWSER", colCyan},
		{c.CanSendEmail, "MAIL", colHigh},
	}
	var parts []string
	for _, ch := range chips {
		if !ch.on {
			continue
		}
		parts = append(parts, lipgloss.NewStyle().Foreground(ch.col).Render(ch.text))
	}
	if len(parts) == 0 {
		return lipgloss.NewStyle().Foreground(colSubtle).Render("none")
	}
	return strings.Join(parts, lipgloss.NewStyle().Foreground(colSubtle).Render(" · "))
}

// RenderTable 渲染终端表格报告。
func RenderTable(r *Report) string {
	width := termWidth()
	var b strings.Builder

	title := lipgloss.NewStyle().Foreground(colText).Bold(true).Render("◆ mcprism")
	sub := lipgloss.NewStyle().Foreground(colSubtle).Render(fmt.Sprintf("v%s · %s", r.Version, r.GeneratedAt))
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, title, "   ", sub) + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colSubtle).Render(strings.Repeat("─", min(width, 100))) + "\n")

	for _, res := range r.Results {
		s := res.Server
		// header
		var conn string
		switch {
		case res.Connected:
			conn = lipgloss.NewStyle().Foreground(colGreen).Render("● connected")
		case res.Probed:
			conn = lipgloss.NewStyle().Foreground(colCrit).Render("○ unreachable")
		default:
			conn = lipgloss.NewStyle().Foreground(colSubtle).Render("◌ static only")
		}
		header := fmt.Sprintf("%s %s  %s", gradeBadge(res.Grade),
			lipgloss.NewStyle().Foreground(colText).Bold(true).Render(s.Name), conn)
		b.WriteString(header + "\n")

		meta := truncW(s.Target(), width-8)
		b.WriteString("  " + lipgloss.NewStyle().Foreground(colSubtle).Render(meta) + "\n")
		if s.Source != "" {
			b.WriteString("  " + lipgloss.NewStyle().Foreground(colSubtle).Render(s.Client+" · "+s.Source) + "\n")
		}
		b.WriteString("  " + lipgloss.NewStyle().Foreground(colSubtle).Render("capabilities: ") + capChips(res.Capabilities) + "\n")

		if len(res.Findings) == 0 {
			b.WriteString("  " + lipgloss.NewStyle().Foreground(colGreen).Render("✓ No issues detected") + "\n\n")
			continue
		}

		// findings
		for _, f := range res.Findings {
			line := fmt.Sprintf("  %s %s  %s", sevTag(f.Severity),
				lipgloss.NewStyle().Foreground(colSubtle).Render(f.RuleID),
				truncW(f.Title, width-22))
			b.WriteString(line + "\n")
			if f.Location != "" {
				b.WriteString("      " + lipgloss.NewStyle().Foreground(colSubtle).Render(truncW("↳ "+f.Location, width-8)) + "\n")
			}
			if f.Evidence != "" && (f.Severity == rules.SeverityCritical || f.Severity == rules.SeverityHigh) {
				b.WriteString("      " + lipgloss.NewStyle().Foreground(sevColor(f.Severity)).Render(truncW(f.Evidence, width-8)) + "\n")
			}
			b.WriteString("      " + lipgloss.NewStyle().Foreground(colGreen).Render(truncW("→ "+f.Advice, width-8)) + "\n")
		}
		b.WriteString("\n")
	}

	// summary bar
	sum := r.Summary
	coloredCounts := strings.Join([]string{
		lipgloss.NewStyle().Foreground(colCrit).Bold(true).Render(fmt.Sprintf("%d CRIT", sum.Critical)),
		lipgloss.NewStyle().Foreground(colHigh).Bold(true).Render(fmt.Sprintf("%d HIGH", sum.High)),
		lipgloss.NewStyle().Foreground(colMed).Render(fmt.Sprintf("%d MED", sum.Medium)),
		lipgloss.NewStyle().Foreground(colLow).Render(fmt.Sprintf("%d LOW", sum.Low)),
	}, "  ")
	b.WriteString(lipgloss.NewStyle().Foreground(colSubtle).Render(strings.Repeat("─", min(width, 100))) + "\n")
	b.WriteString(fmt.Sprintf("%s · %s · %s\n",
		lipgloss.NewStyle().Foreground(colText).Render(fmt.Sprintf("%d servers (%d reachable)", sum.Servers, sum.Connected)),
		lipgloss.NewStyle().Foreground(colText).Render(fmt.Sprintf("%d tools", sum.Tools)),
		lipgloss.NewStyle().Foreground(colText).Render(fmt.Sprintf("%d findings", sum.Findings))))
	b.WriteString(coloredCounts + "\n")
	return b.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
