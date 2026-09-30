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
	colSel    = lipgloss.Color("#313244")
	colBorder = lipgloss.Color("#45475a")
	colAccent = lipgloss.Color("#89b4fa")
)

const leftOuter = 30 // 左侧面板外框宽度（含边框与内边距）

type seg struct {
	t    string
	c    lipgloss.Color
	bold bool
}

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
		m.viewport.Width = m.w - 4
		m.viewport.Height = m.h - 5
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
	if m.w < 40 || m.h < 10 {
		return "starting…"
	}
	if m.pane == 2 {
		return m.titleBar() + "\n" + m.detailBox() + "\n" + m.helpBar(true)
	}
	leftBody := m.serverContent()
	res := m.results[m.sSel]
	rightBody := m.findingContent(res)
	inner := lipgloss.Height(leftBody)
	if h := lipgloss.Height(rightBody); h > inner {
		inner = h
	}
	outerH := inner + 3 // title line plus border
	if cap := m.h - 2; outerH > cap {
		outerH = cap
	}
	left := box(leftBody, fmt.Sprintf("SERVERS · %d", len(m.results)), leftOuter, outerH, m.pane == 0)
	rightW := m.w - leftOuter
	right := box(rightBody, fmt.Sprintf("FINDINGS · %s · %d", res.Server.Name, len(res.Findings)), rightW, outerH, m.pane == 1)
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	return m.titleBar() + "\n" + body + "\n" + m.helpBar(false)
}

func box(body, title string, w, h int, active bool) string {
	border := colBorder
	titleC := colSubtle
	if active {
		border = colAccent
		titleC = colAccent
	}
	titleLine := lipgloss.NewStyle().Foreground(titleC).Bold(true).Render(title)
	content := titleLine + "\n" + body
	return lipgloss.NewStyle().
		Width(w).Height(h).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border).
		Padding(0, 1).
		Render(content)
}

func (m model) titleBar() string {
	left := lipgloss.NewStyle().Foreground(colText).Bold(true).Render("◆ mcprism") +
		" " + lipgloss.NewStyle().Foreground(colSubtle).Render("interactive security review")
	right := lipgloss.NewStyle().Foreground(colSubtle).Render(fmt.Sprintf("%d servers", len(m.results)))
	return lipgloss.JoinHorizontal(lipgloss.Top, lipgloss.NewStyle().Width(m.w-12).Render(left), right)
}

func (m model) helpBar(detail bool) string {
	var keys string
	if detail {
		keys = "↑↓/j,k scroll · esc back · q quit"
	} else {
		keys = "↑↓/j,k navigate · tab switch pane · enter details · esc back · q quit"
	}
	return lipgloss.NewStyle().Width(m.w).Foreground(colSubtle).Render(keys)
}

func (m model) detailBox() string {
	f := m.results[m.sSel].Findings[m.fSel]
	title := fmt.Sprintf("%s · %s", shortSev(f.Severity), f.RuleID)
	return box(m.viewport.View(), title, m.w, m.h-2, true)
}

func (m model) serverContent() string {
	innerW := leftOuter - 4
	maxRows := m.h
	s, e := window(len(m.results), m.sSel, maxRows)
	var rows []string
	for i := s; i < e; i++ {
		r := m.results[i]
		selected := i == m.sSel && m.pane == 0
		dotC, conn := colGreen, "●"
		if !r.Connected {
			dotC, conn = colCrit, "○"
		}
		rows = append(rows, renderRow(innerW, selected,
			selPrefix(selected),
			seg{r.Grade, gradeColor(r.Grade), true},
			seg{" ", colText, false},
			seg{conn, dotC, false},
			seg{" ", colText, false},
			seg{trunc(r.Server.Name, innerW-7), colText, false},
		))
	}
	return strings.Join(rows, "\n")
}

func (m model) findingContent(res *rules.Result) string {
	innerW := m.w - leftOuter - 4
	if len(res.Findings) == 0 {
		return lipgloss.NewStyle().Foreground(colGreen).Render("✓ No issues detected")
	}
	fSel := m.fSel
	if fSel >= len(res.Findings) {
		fSel = len(res.Findings) - 1
	}
	maxRows := m.h
	s, e := window(len(res.Findings), fSel, maxRows)
	var rows []string
	for i := s; i < e; i++ {
		f := res.Findings[i]
		selected := i == fSel && m.pane == 1
		rows = append(rows, renderRow(innerW, selected,
			selPrefix(selected),
			seg{shortSev(f.Severity), sevColor(f.Severity), true},
			seg{" ", colText, false},
			seg{f.RuleID, colSubtle, false},
			seg{" ", colText, false},
			seg{trunc(f.Title, innerW-14), colText, false},
		))
	}
	return strings.Join(rows, "\n")
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

// ---------- rendering helpers ----------

func selPrefix(selected bool) seg {
	if selected {
		return seg{"▸ ", colAccent, true}
	}
	return seg{"  ", colText, false}
}

func renderRow(width int, selected bool, parts ...seg) string {
	var bg lipgloss.Color
	if selected {
		bg = colSel
	}
	var b strings.Builder
	for _, p := range parts {
		st := lipgloss.NewStyle().Foreground(p.c)
		if p.bold {
			st = st.Bold(true)
		}
		if selected {
			st = st.Background(bg)
		}
		b.WriteString(st.Render(p.t))
	}
	if pad := width - lipgloss.Width(b.String()); pad > 0 {
		st := lipgloss.NewStyle()
		if selected {
			st = st.Background(bg)
		}
		b.WriteString(st.Render(strings.Repeat(" ", pad)))
	}
	return b.String()
}

// window 返回在最多 max 行的窗口中应显示的 [start,end) 行范围，并保证 sel 可见。
func window(n, sel, max int) (int, int) {
	if n <= max {
		return 0, n
	}
	start := sel - max/2
	if start < 0 {
		start = 0
	}
	if start > n-max {
		start = n - max
	}
	return start, start + max
}

// ---------- color / text helpers ----------

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
