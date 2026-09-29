package report

import (
	"fmt"
	"html"
	"strings"

	"github.com/HUA503/mcprism/internal/rules"
)

func sevHex(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical:
		return "#f38ba8"
	case rules.SeverityHigh:
		return "#fab387"
	case rules.SeverityMedium:
		return "#f9e2af"
	case rules.SeverityLow:
		return "#89b4fa"
	}
	return "#a6adc8"
}

func gradeHex(g string) string {
	return map[string]string{
		"A": "#a6e3a1", "B": "#94e2d5", "C": "#f9e2af", "D": "#fab387", "F": "#f38ba8",
	}[g]
}

// RenderHTML 渲染独立、可分享的 HTML 报告（内联样式，无外部依赖）。
func RenderHTML(r *Report) string {
	esc := html.EscapeString
	var b strings.Builder

	b.WriteString(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mcprism security report</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#1e1e2e;color:#cdd6f4;font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.prism-bar{height:5px;background:linear-gradient(90deg,#f38ba8,#fab387,#f9e2af,#a6e3a1,#94e2d5,#89b4fa,#cba6f7)}
main{max-width:1080px;margin:0 auto;padding:28px 24px 60px}
h1{font-size:26px;margin:0 0 2px}
h1 .dim,.dim{color:#6c7086;font-weight:400}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:22px 0 30px}
.card{background:#313244;border-radius:12px;padding:14px 18px;min-width:110px}
.card .num{font-size:26px;font-weight:700}
.card .label{color:#a6adc8;font-size:13px}
.card.crit .num{color:#f38ba8}.card.high .num{color:#fab387}
.card.med .num{color:#f9e2af}.card.low .num{color:#89b4fa}
.server{background:#28283a;border:1px solid #313244;border-radius:14px;padding:18px 20px;margin:0 0 18px}
.server-head{display:flex;align-items:center;gap:14px;margin-bottom:8px}
.grade{display:inline-flex;align-items:center;justify-content:center;width:40px;height:40px;border-radius:10px;font-weight:800;font-size:20px;background:#11111b}
.sname{font-size:18px;font-weight:700}
.conn-ok{color:#a6e3a1;font-size:13px}.conn-bad{color:#f38ba8;font-size:13px}
.meta{font-size:13px;margin:2px 0;word-break:break-all}
.meta .dim{display:inline-block;min-width:64px}
.chips{margin:10px 0 4px}
.chip{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;margin:0 6px 6px 0;background:#11111b}
table{width:100%;border-collapse:collapse;margin-top:10px;font-size:13.5px}
th{text-align:left;color:#a6adc8;font-weight:600;padding:8px 10px;border-bottom:1px solid #45475a}
td{padding:8px 10px;border-bottom:1px solid #313244;vertical-align:top}
tr.sev td:first-child{font-weight:700}
.rule{color:#6c7086;white-space:nowrap}
.advice{color:#a6e3a1}
.evidence{color:#f9e2af;font-size:12.5px}
.ok{color:#a6e3a1}
</style></head><body><div class="prism-bar"></div><main>`)

	b.WriteString(`<h1>◆ mcprism <span class="dim">security report</span></h1>`)
	b.WriteString(fmt.Sprintf(`<p class="dim">v%s · %s</p>`, esc(r.Version), esc(r.GeneratedAt)))

	s := r.Summary
	b.WriteString(`<section class="cards">`)
	stat := func(cls, num, label string) {
		b.WriteString(fmt.Sprintf(`<div class="card %s"><div class="num">%s</div><div class="label">%s</div></div>`, cls, num, label))
	}
	stat("", fmt.Sprint(s.Servers), "servers")
	stat("", fmt.Sprint(s.Connected), "reachable")
	stat("", fmt.Sprint(s.Tools), "tools")
	stat("crit", fmt.Sprint(s.Critical), "critical")
	stat("high", fmt.Sprint(s.High), "high")
	stat("med", fmt.Sprint(s.Medium), "medium")
	stat("low", fmt.Sprint(s.Low), "low")
	b.WriteString(`</section>`)

	for _, res := range r.Results {
		srv := res.Server
		b.WriteString(`<section class="server">`)
		var conn string
		switch {
		case res.Connected:
			conn = `<span class="conn-ok">● connected</span>`
		case res.Probed:
			conn = `<span class="conn-bad">○ unreachable</span>`
		default:
			conn = `<span class="dim">◌ static only</span>`
		}
		b.WriteString(fmt.Sprintf(`<div class="server-head"><span class="grade" style="color:%s">%s</span>
<div><div class="sname">%s</div>%s</div></div>`, gradeHex(res.Grade), res.Grade, esc(srv.Name), conn))
		b.WriteString(fmt.Sprintf(`<div class="meta"><span class="dim">target</span> %s</div>`, esc(srv.Target())))
		if srv.Source != "" {
			b.WriteString(fmt.Sprintf(`<div class="meta"><span class="dim">source</span> %s (%s)</div>`, esc(srv.Source), esc(srv.Client)))
		}
		// chips
		b.WriteString(`<div class="chips">`)
		addChip := func(t string, c string) {
			b.WriteString(fmt.Sprintf(`<span class="chip" style="color:%s">%s</span>`, c, t))
		}
		if res.Capabilities.CanShell {
			addChip("SHELL", "#f38ba8")
		}
		if res.Capabilities.CanWriteFiles {
			addChip("WRITE", "#fab387")
		}
		if res.Capabilities.CanReadFiles {
			addChip("READ", "#89b4fa")
		}
		if res.Capabilities.CanNetwork {
			addChip("NETWORK", "#cba6f7")
		}
		if res.Capabilities.CanAccessDB {
			addChip("DATABASE", "#f9e2af")
		}
		if res.Capabilities.CanBrowser {
			addChip("BROWSER", "#94e2d5")
		}
		if res.Capabilities.CanSendEmail {
			addChip("EMAIL", "#fab387")
		}
		b.WriteString(`</div>`)

		if len(res.Findings) == 0 {
			b.WriteString(`<p class="ok">✓ No issues detected</p></section>`)
			continue
		}
		b.WriteString(`<table><thead><tr><th>Severity</th><th>Rule</th><th>Title</th><th>Location</th><th>Evidence</th><th>Advice</th></tr></thead><tbody>`)
		for _, f := range res.Findings {
			b.WriteString(fmt.Sprintf(`<tr class="sev" style="box-shadow:inset 3px 0 0 %s"><td style="color:%s">%s</td>
<td class="rule">%s</td><td>%s</td><td>%s</td><td class="evidence">%s</td><td class="advice">%s</td></tr>`,
				sevHex(f.Severity), sevHex(f.Severity), f.Severity, f.RuleID,
				esc(f.Title), esc(f.Location), esc(f.Evidence), esc(f.Advice)))
		}
		b.WriteString(`</tbody></table></section>`)
	}

	b.WriteString(`</main></body></html>`)
	return b.String()
}
