package report

import (
	"fmt"
	"strings"

	"github.com/HUA503/mcprism/internal/rules"
	"github.com/HUA503/mcprism/internal/ui"
	"github.com/charmbracelet/lipgloss"
)

// RenderTable 渲染终端表格报告。颜色与字形由 internal/ui 按终端能力选择，
// 在不支持 UTF-8 的控制台（如旧版 Windows conhost）上自动回退 ASCII。
func RenderTable(r *Report) string {
	width := ui.TermWidth()
	ruleWidth := min(width, 100)
	var b strings.Builder

	title := lipgloss.NewStyle().Foreground(ui.Text).Bold(true).Render(ui.Sym("diamond") + " mcprism")
	sub := lipgloss.NewStyle().Foreground(ui.Subtle).Render(fmt.Sprintf("v%s %s %s", r.Version, ui.Sym("middot"), r.GeneratedAt))
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, title, "   ", sub) + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(ui.Subtle).Render(ui.HBar(ruleWidth)) + "\n")

	for _, res := range r.Results {
		s := res.Server
		var conn string
		switch {
		case res.Connected:
			conn = lipgloss.NewStyle().Foreground(ui.Green).Render(ui.Sym("bullet") + " connected")
		case res.Probed:
			conn = lipgloss.NewStyle().Foreground(ui.Crit).Render(ui.Sym("circle") + " unreachable")
		default:
			conn = lipgloss.NewStyle().Foreground(ui.Subtle).Render(ui.Sym("dotted") + " static only")
		}
		header := fmt.Sprintf("%s %s  %s", ui.GradeBadge(res.Grade),
			lipgloss.NewStyle().Foreground(ui.Text).Bold(true).Render(s.Name), conn)
		b.WriteString(header + "\n")

		meta := ui.TruncWords(s.Target(), width-8)
		b.WriteString("  " + lipgloss.NewStyle().Foreground(ui.Subtle).Render(meta) + "\n")
		if s.Source != "" {
			b.WriteString("  " + lipgloss.NewStyle().Foreground(ui.Subtle).Render(s.Client+" "+ui.Sym("middot")+" "+s.Source) + "\n")
		}
		b.WriteString("  " + lipgloss.NewStyle().Foreground(ui.Subtle).Render("capabilities: ") + ui.CapChips(res.Capabilities) + "\n")

		if len(res.Findings) == 0 {
			b.WriteString("  " + lipgloss.NewStyle().Foreground(ui.Green).Render(ui.Sym("check")+" No issues detected") + "\n\n")
			continue
		}

		for _, f := range res.Findings {
			line := fmt.Sprintf("  %s %s  %s", ui.SevTag(f.Severity),
				lipgloss.NewStyle().Foreground(ui.Subtle).Render(f.RuleID),
				ui.TruncWords(f.Title, width-22))
			b.WriteString(line + "\n")
			if f.Location != "" {
				b.WriteString("      " + lipgloss.NewStyle().Foreground(ui.Subtle).Render(ui.Trunc(ui.Sym("branch")+" "+f.Location, width-8)) + "\n")
			}
			if f.Evidence != "" && (f.Severity == rules.SeverityCritical || f.Severity == rules.SeverityHigh) {
				b.WriteString("      " + lipgloss.NewStyle().Foreground(ui.SevColor(f.Severity)).Render(ui.TruncWords(f.Evidence, width-8)) + "\n")
			}
			b.WriteString("      " + lipgloss.NewStyle().Foreground(ui.Green).Render(ui.TruncWords(ui.Sym("advice")+" "+f.Advice, width-8)) + "\n")
		}
		b.WriteString("\n")
	}

	sum := r.Summary
	coloredCounts := strings.Join([]string{
		lipgloss.NewStyle().Foreground(ui.Crit).Bold(true).Render(fmt.Sprintf("%d CRIT", sum.Critical)),
		lipgloss.NewStyle().Foreground(ui.High).Bold(true).Render(fmt.Sprintf("%d HIGH", sum.High)),
		lipgloss.NewStyle().Foreground(ui.Med).Render(fmt.Sprintf("%d MED", sum.Medium)),
		lipgloss.NewStyle().Foreground(ui.Low).Render(fmt.Sprintf("%d LOW", sum.Low)),
	}, "  ")
	b.WriteString(lipgloss.NewStyle().Foreground(ui.Subtle).Render(ui.HBar(ruleWidth)) + "\n")
	b.WriteString(fmt.Sprintf("%s %s %s %s %s %s\n",
		lipgloss.NewStyle().Foreground(ui.Text).Render(fmt.Sprintf("%d servers (%d reachable)", sum.Servers, sum.Connected)),
		ui.Sym("middot"),
		lipgloss.NewStyle().Foreground(ui.Text).Render(fmt.Sprintf("%d tools", sum.Tools)),
		ui.Sym("middot"),
		lipgloss.NewStyle().Foreground(ui.Text).Render(fmt.Sprintf("%d findings", sum.Findings)),
		""))
	b.WriteString(coloredCounts + "\n")
	return b.String()
}
