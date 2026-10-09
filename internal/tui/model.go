// Package tui 提供 mcprism 的交互式终端界面：浏览所有 server、其能力与安全发现，
// 并下钻查看每条发现的证据、解释、修复建议与参考资料。
package tui

import (
	"fmt"
	"strings"

	"github.com/HUA503/mcprism/internal/rules"
	"github.com/HUA503/mcprism/internal/ui"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	leftOuter = 30 // 左侧面板外框宽度（含边框与内边距）
	twoColMin = 70 // 低于此宽度改用单列布局，避免右栏被挤到不可读
)

type seg struct {
	t    string
	c    lipgloss.Color
	bold bool
}

type model struct {
	results   []*rules.Result
	sSel      int
	fSel      int
	pane      int // 0=server 列表, 1=finding 列表, 2=详情
	w, h      int
	searching bool
	search    string
	viewport  viewport.Model
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
		m.viewport.Height = m.h - 6
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

		// Finding search input.
		if m.searching {
			switch msg.String() {
			case "esc":
				m.searching, m.search = false, ""
				m.fSel = 0
				return m, nil
			case "enter":
				m.searching = false
				m.fSel = 0
				return m, nil
			case "backspace":
				if len(m.search) > 0 {
					m.search = m.search[:len(m.search)-1]
					m.fSel = 0
				}
				return m, nil
			default:
				if len(msg.String()) == 1 {
					m.search += msg.String()
					m.fSel = 0
					return m, nil
				}
			}
			return m, nil
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
		case "/":
			if m.pane == 1 {
				m.searching = true
			}
			return m, nil
		case "enter":
			if m.pane == 0 {
				m.pane = 1
				m.fSel = 0
			} else if len(m.visibleFindings()) > 0 {
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
		n := len(m.visibleFindings())
		if n > 0 {
			m.fSel = clamp(m.fSel+d, 0, n-1)
		}
	}
	return m
}

// visibleFindings returns the current server's findings, filtered by the search
// query across rule id, title, evidence and severity.
func (m model) visibleFindings() []rules.Finding {
	all := m.results[m.sSel].Findings
	q := strings.ToLower(strings.TrimSpace(m.search))
	if q == "" {
		return all
	}
	out := make([]rules.Finding, 0, len(all))
	for _, f := range all {
		hay := strings.ToLower(f.RuleID + " " + f.Title + " " + f.Evidence + " " + string(f.Severity))
		if strings.Contains(hay, q) {
			out = append(out, f)
		}
	}
	return out
}

func (m model) View() string {
	if m.w < 40 || m.h < 10 {
		return "starting" + ui.Sym("hellip")
	}
	if m.pane == 2 {
		return m.titleBar() + "\n" + m.detailBox() + "\n" + m.helpBar(true)
	}

	res := m.results[m.sSel]
	leftBody := m.serverContent()
	rightBody := m.findingContent(res)
	inner := lipgloss.Height(leftBody)
	if h := lipgloss.Height(rightBody); h > inner {
		inner = h
	}
	outerH := inner + 3 // title line plus border
	if cap := m.h - 2; outerH > cap {
		outerH = cap
	}

	leftTitle := fmt.Sprintf("SERVERS %s %d", ui.Sym("middot"), len(m.results))
	rightTitle := fmt.Sprintf("FINDINGS %s %s %s %d", ui.Sym("middot"), res.Server.Name, ui.Sym("middot"), len(m.visibleFindings()))

	// Narrow terminals: show only the active pane at full width instead of
	// crushing the findings column.
	if m.w < twoColMin {
		if m.pane == 0 {
			return m.titleBar() + "\n" + box(leftBody, leftTitle, m.w, outerH, true) + "\n" + m.helpBar(false)
		}
		return m.titleBar() + "\n" + box(rightBody, rightTitle, m.w, outerH, true) + "\n" + m.helpBar(false)
	}

	left := box(leftBody, leftTitle, leftOuter, outerH, m.pane == 0)
	rightW := m.w - leftOuter
	right := box(rightBody, rightTitle, rightW, outerH, m.pane == 1)
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	return m.titleBar() + "\n" + body + "\n" + m.helpBar(false)
}

func box(body, title string, w, h int, active bool) string {
	border := ui.Border
	titleC := ui.Subtle
	if active {
		border = ui.Accent
		titleC = ui.Accent
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
	left := lipgloss.NewStyle().Foreground(ui.Text).Bold(true).Render(ui.Sym("diamond")+" mcprism") +
		" " + lipgloss.NewStyle().Foreground(ui.Subtle).Render("interactive security review")
	right := lipgloss.NewStyle().Foreground(ui.Subtle).Render(fmt.Sprintf("%d servers", len(m.results)))
	gap := m.w - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	return left + strings.Repeat(" ", gap) + right
}

func (m model) helpBar(detail bool) string {
	var keys string
	switch {
	case m.searching:
		keys = "search: " + m.search + "_  " + ui.Sym("middot") + " enter apply " + ui.Sym("middot") + " esc clear"
	case detail:
		keys = "up/down or j,k scroll " + ui.Sym("middot") + " esc back " + ui.Sym("middot") + " q quit"
	default:
		keys = "up/down or j,k navigate " + ui.Sym("middot") + " tab switch " + ui.Sym("middot") +
			" / filter findings " + ui.Sym("middot") + " enter details " + ui.Sym("middot") + " esc back " + ui.Sym("middot") + " q quit"
	}
	return lipgloss.NewStyle().Width(m.w).Foreground(ui.Subtle).Render(keys)
}

func (m model) detailBox() string {
	list := m.visibleFindings()
	idx := clamp(m.fSel, 0, len(list)-1)
	f := list[idx]
	title := fmt.Sprintf("%s %s %s", shortSev(f.Severity), ui.Sym("middot"), f.RuleID)
	return box(m.viewport.View(), title, m.w, m.h-3, true)
}

func (m model) serverContent() string {
	innerW := leftOuter - 4
	if m.w < twoColMin {
		innerW = m.w - 4
	}
	maxRows := m.h
	s, e := window(len(m.results), m.sSel, maxRows)
	var rows []string
	for i := s; i < e; i++ {
		r := m.results[i]
		selected := i == m.sSel && m.pane == 0
		dotC, conn := ui.Green, ui.Sym("bullet")
		if !r.Connected {
			dotC, conn = ui.Crit, ui.Sym("circle")
		}
		rows = append(rows, renderRow(innerW, selected,
			selPrefix(selected),
			seg{r.Grade, gradeColor(r.Grade), true},
			seg{" ", ui.Text, false},
			seg{conn, dotC, false},
			seg{" ", ui.Text, false},
			seg{ui.Trunc(r.Server.Name, innerW-7), ui.Text, false},
		))
	}
	return strings.Join(rows, "\n")
}

func (m model) findingContent(res *rules.Result) string {
	innerW := m.w - leftOuter - 4
	if m.w < twoColMin {
		innerW = m.w - 4
	}
	list := m.visibleFindings()
	if len(list) == 0 {
		msg := ui.Sym("check") + " No issues detected"
		if strings.TrimSpace(m.search) != "" {
			msg = "no findings match " + ui.Trunc(m.search, 24)
		}
		return lipgloss.NewStyle().Foreground(ui.Green).Render(msg)
	}
	fSel := m.fSel
	if fSel >= len(list) {
		fSel = len(list) - 1
	}
	maxRows := m.h
	s, e := window(len(list), fSel, maxRows)
	var rows []string
	for i := s; i < e; i++ {
		f := list[i]
		selected := i == fSel && m.pane == 1
		rows = append(rows, renderRow(innerW, selected,
			selPrefix(selected),
			seg{shortSev(f.Severity), ui.SevColor(f.Severity), true},
			seg{" ", ui.Text, false},
			seg{f.RuleID, ui.Subtle, false},
			seg{" ", ui.Text, false},
			seg{ui.Trunc(f.Title, innerW-14), ui.Text, false},
		))
	}
	return strings.Join(rows, "\n")
}

func (m model) detailText() string {
	list := m.visibleFindings()
	idx := clamp(m.fSel, 0, len(list)-1)
	f := list[idx]
	c := ui.SevColor(f.Severity)
	var b strings.Builder
	b.WriteString(lipgloss.NewStyle().Foreground(c).Bold(true).
		Render(fmt.Sprintf("%s %s %s", f.Severity, ui.Sym("middot"), f.RuleID)) + "\n\n")
	b.WriteString(lipgloss.NewStyle().Bold(true).Render(f.Title) + "\n\n")

	section := func(label, val string) {
		if strings.TrimSpace(val) == "" {
			return
		}
		b.WriteString(lipgloss.NewStyle().Foreground(ui.Subtle).Render(strings.ToUpper(label)) + "\n")
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
		return seg{ui.Sym("pointer") + " ", ui.Accent, true}
	}
	return seg{"  ", ui.Text, false}
}

func renderRow(width int, selected bool, parts ...seg) string {
	var bg lipgloss.Color
	if selected {
		bg = ui.Sel
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
		"A": ui.Green, "B": ui.Cyan, "C": ui.Med, "D": ui.High, "F": ui.Crit,
	}[g]
}

func shortSev(s rules.Severity) string {
	return map[rules.Severity]string{
		rules.SeverityCritical: "CRIT", rules.SeverityHigh: "HIGH",
		rules.SeverityMedium: "MED", rules.SeverityLow: "LOW", rules.SeverityInfo: "INFO",
	}[s]
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
