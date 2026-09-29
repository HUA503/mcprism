// Package tui 提供 mcprism 的交互式终端界面：浏览所有 server、其能力与安全发现，
// 并下钻查看每条发现的证据、解释、修复建议与参考资料。
package tui

import (
	"fmt"
	"strings"

	"github.com/HUA503/mcprism/internal/rules"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	colSubtle = lipgloss.Color("#6c7086")
	colText   = lipgloss.Color("#cdd6f4")
	colCrit   = lipgloss.Color("#f38ba8")
	colHigh   = lipgloss.Color("#fab387")
	colMed    = lipgloss.Color("#f9e2af")
	colLow    = lipgloss.Color("#89b4fa")
	colInfo   = lipgloss.Color("#a6adc8")
	colGreen  = lipgloss.Color("#a6e3a1")
	colCyan   = lipgloss.Color("#94e2d5")
	colSel    = lipgloss.Color("#45475a")
)

const leftWidth = 32

type model struct {
	results  []*rules.Result
	sSel     int
	fSel     int
	pane     int // 0=server 列表, 1=finding 列表, 2=详情
	w, h     int
	viewport viewport.Model
}

// Run 启动交互式 TUI。
func Run(results []*rules.Result) error {
	if len(results) == 0 {
		return fmt.Errorf("no servers to display")
	}
	m := model{results: results}
	m.viewport = viewport.New(80, 24)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		m.viewport.Width = msg.Width
		m.viewport.Height = msg.Height - 2
		return m, nil
	case tea.KeyMsg:
		if m.pane == 2 {
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "esc":
				m.pane = 1
				return m, nil
			}
			var cmd tea.Cmd
			m.viewport, cmd = m.viewport.Update(msg)
			return m, cmd
		}
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "esc":
			if m.pane == 1 {
				m.pane = 0
			}
			return m, nil
		case "tab":
			if m.pane == 0 {
				m.pane = 1
			} else {
				m.pane = 0
			}
			return m, nil
		case "enter":
			if m.pane == 0 {
				m.pane = 1
				m.fSel = 0
			} else if len(m.results[m.sSel].Findings) > 0 {
				m.pane = 2
				m.viewport.SetContent(m.detailText())
				m.viewport.GotoTop()
			}
			return m, nil
		case "up", "k":
			m = m.moved(-1)
			return m, nil
		case "down", "j":
			m = m.moved(1)
			return m, nil
		}
	}
	return m, nil
}

func (m model) moved(d int) model {
	if m.pane == 0 {
		m.sSel = clamp(m.sSel+d, 0, len(m.results)-1)
		m.fSel = 0
	} else if m.pane == 1 {
		n := len(m.results[m.sSel].Findings)
		if n > 0 {
			m.fSel = clamp(m.fSel+d, 0, n-1)
		}
	}
	return m
}

func (m model) View() string {
	if m.pane == 2 {
		return m.titleBar() + "\n" + m.viewport.View() + "\n" + m.detailHelp()
	}
	left := m.serverPane()
	right := m.findingPane()
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	return m.titleBar() + "\n" + body + "\n" + m.helpBar()
}

func (m model) titleBar() string {
	return lipgloss.NewStyle().Foreground(colText).Bold(true).Render("◆ mcprism") +
		"  " + lipgloss.NewStyle().Foreground(colSubtle).Render("interactive security review")
}

func (m model) helpBar() string {
	return lipgloss.NewStyle().Foreground(colSubtle).Render("↑↓/j,k navigate · tab switch pane · enter details · esc back · q quit")
}

func (m model) detailHelp() string {
	return lipgloss.NewStyle().Foreground(colSubtle).Render("↑↓/j,k scroll · esc back · q quit")
}

func (m model) serverPane() string {
	var rows []string
	for i, r := range m.results {
		gc := gradeColor(r.Grade)
		g := lipgloss.NewStyle().Foreground(gc).Bold(true).Render(r.Grade)
		dotC := colGreen
		conn := "●"
		if !r.Connected {
			dotC = colCrit
			conn = "○"
		}
		dot := lipgloss.NewStyle().Foreground(dotC).Render(conn)
		line := fmt.Sprintf("%s %s %s", g, dot, trunc(r.Server.Name, leftWidth-7))
		st := lipgloss.NewStyle().Width(leftWidth).PaddingLeft(1)
		if i == m.sSel && m.pane == 0 {
			st = st.Background(colSel)
		}
		rows = append(rows, st.Render(line))
	}
	header := lipgloss.NewStyle().Foreground(colSubtle).PaddingLeft(1).Render("SERVERS")
	return header + "\n" + strings.Join(rows, "\n")
}

func (m model) findingPane() string {
	rw := m.w - leftWidth
	if rw < 40 {
		rw = 40
	}
	res := m.results[m.sSel]
	header := lipgloss.NewStyle().Foreground(colSubtle).PaddingLeft(1).
		Render(fmt.Sprintf("FINDINGS · %s (%d)", res.Server.Name, len(res.Findings)))

	if len(res.Findings) == 0 {
		ok := lipgloss.NewStyle().Foreground(colGreen).PaddingLeft(1).Render("✓ No issues detected")
		return header + "\n" + ok
	}

	fSel := m.fSel
	if fSel >= len(res.Findings) {
		fSel = len(res.Findings) - 1
	}

	var rows []string
	for i, f := range res.Findings {
		c := sevColor(f.Severity)
		tag := lipgloss.NewStyle().Foreground(c).Bold(true).Render(shortSev(f.Severity))
		rid := lipgloss.NewStyle().Foreground(colSubtle).Render(f.RuleID)
		line := fmt.Sprintf("%s %s %s", tag, rid, trunc(f.Title, rw-19))
		st := lipgloss.NewStyle().Width(rw).PaddingLeft(1)
		if i == fSel && m.pane == 1 {
			st = st.Background(colSel)
		}
		rows = append(rows, st.Render(line))
	}
	return header + "\n" + strings.Join(rows, "\n")
}

func (m model) detailText() string {
	f := m.results[m.sSel].Findings[m.fSel]
	c := sevColor(f.Severity)
	var b strings.Builder
	b.WriteString(lipgloss.NewStyle().Foreground(c).Bold(true).
		Render(fmt.Sprintf("%s · %s", f.Severity, f.RuleID)) + "\n\n")
	b.WriteString(lipgloss.NewStyle().Bold(true).Render(f.Title) + "\n\n")

	section := func(label, val string) {
		if strings.TrimSpace(val) == "" {
			return
		}
		b.WriteString(lipgloss.NewStyle().Foreground(colSubtle).Render(strings.ToUpper(label)) + "\n")
		b.WriteString(val + "\n\n")
	}
	section("Server", f.Server)
	section("OWASP mapping", f.OWASP)
	section("Location", f.Location)
	section("Description", f.Description)
	section("Evidence", f.Evidence)
	section("Advice", f.Advice)
	if len(f.References) > 0 {
		section("References", strings.Join(f.References, "\n"))
	}
	return b.String()
}

// ---------- helpers ----------

func gradeColor(g string) lipgloss.Color {
	return map[string]lipgloss.Color{
		"A": colGreen, "B": colCyan, "C": colMed, "D": colHigh, "F": colCrit,
	}[g]
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

func shortSev(s rules.Severity) string {
	return map[rules.Severity]string{
		rules.SeverityCritical: "CRIT", rules.SeverityHigh: "HIGH",
		rules.SeverityMedium: "MED", rules.SeverityLow: "LOW", rules.SeverityInfo: "INFO",
	}[s]
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n < 1 {
		return ""
	}
	return string(r[:n-1]) + "…"
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
