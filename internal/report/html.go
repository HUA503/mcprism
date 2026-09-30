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

func gradeRank(g string) int {
	return map[string]int{"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}[g]
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
.gate-pass{color:#a6e3a1}.gate-fail{color:#f38ba8}
.card.gate .num{font-size:20px;padding-top:3px}
.sup{margin-top:12px;border-top:1px dashed #45475a;padding-top:10px}
.sup summary{cursor:pointer;color:#a6adc8;font-size:13px}
.sup table{font-size:12.5px}
.sup .reason{color:#cba6f7}
.overview{display:flex;align-items:center;gap:26px;background:#28283a;border:1px solid #313244;border-radius:16px;padding:20px 24px;margin:20px 0 16px;flex-wrap:wrap}
.ring{--pct:100;--ring:#a6e3a1;flex:0 0 auto;width:128px;height:128px;border-radius:50%;background:conic-gradient(var(--ring) calc(var(--pct)*1%),#313244 0);display:flex;align-items:center;justify-content:center}
.ring-hole{width:94px;height:94px;border-radius:50%;background:#1e1e2e;display:flex;flex-direction:column;align-items:center;justify-content:center}
.ring-grade{font-size:36px;font-weight:800;line-height:1}
.ring-score{font-size:12px;color:#a6adc8;margin-top:3px}
.ov-body{flex:1;min-width:230px}
.ov-label{color:#6c7086;font-size:12px;letter-spacing:.6px;margin-bottom:7px}
.ov-line{font-size:14px;margin:3px 0;color:#cdd6f4}
.ov-gate{text-align:center;padding:12px 22px;border-radius:12px;background:#11111b;min-width:108px}
.gate-word{font-size:26px;font-weight:800;line-height:1}
.gate-profile{font-size:12px;color:#a6adc8;margin-top:4px}
.ov-gate.pass .gate-word{color:#a6e3a1}.ov-gate.fail .gate-word{color:#f38ba8}
</style></head><body><div class="prism-bar"></div><main>`)

	b.WriteString(`<h1>◆ mcprism <span class="dim">security report</span></h1>`)
	b.WriteString(fmt.Sprintf(`<p class="dim">v%s · %s</p>`, esc(r.Version), esc(r.GeneratedAt)))

	// 总体风险取最差 grade 与最低分：安全由短板决定。
	overallGrade, overallScore := "A", 100
	for _, res := range r.Results {
		if gradeRank(res.Grade) < gradeRank(overallGrade) {
			overallGrade = res.Grade
		}
		if res.Score < overallScore {
			overallScore = res.Score
		}
	}
	s := r.Summary
	b.WriteString(`<section class="overview">`)
	b.WriteString(fmt.Sprintf(`<div class="ring" style="--pct:%d;--ring:%s"><div class="ring-hole"><span class="ring-grade">%s</span><span class="ring-score">%d / 100</span></div></div>`,
		overallScore, gradeHex(overallGrade), overallGrade, overallScore))
	b.WriteString(fmt.Sprintf(`<div class="ov-body"><div class="ov-label">OVERALL RISK</div>
<div class="ov-line">%d servers · %d reachable · %d tools</div>
<div class="ov-line">%d findings · %d critical · %d high · %d medium · %d low</div></div>`,
		s.Servers, s.Connected, s.Tools, s.Findings, s.Critical, s.High, s.Medium, s.Low))
	if r.Compliance != nil {
		pass, word := "pass", "PASS"
		if !r.Compliance.Pass {
			pass, word = "fail", "FAIL"
		}
		b.WriteString(fmt.Sprintf(`<div class="ov-gate %s"><div class="gate-word">%s</div><div class="gate-profile">gate: %s</div></div>`,
			pass, word, esc(r.Compliance.Profile)))
	}
	b.WriteString(`</section>`)

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
	if s.Suppressed > 0 {
		stat("", fmt.Sprint(s.Suppressed), "suppressed")
	}
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
			b.WriteString(`<p class="ok">✓ No issues detected</p>`)
		} else {
			b.WriteString(`<table><thead><tr><th>Severity</th><th>Rule</th><th>Title</th><th>Location</th><th>Evidence</th><th>Advice</th></tr></thead><tbody>`)
			for _, f := range res.Findings {
				b.WriteString(fmt.Sprintf(`<tr class="sev" style="box-shadow:inset 3px 0 0 %s"><td style="color:%s">%s</td>
<td class="rule">%s</td><td>%s</td><td>%s</td><td class="evidence">%s</td><td class="advice">%s</td></tr>`,
					sevHex(f.Severity), sevHex(f.Severity), f.Severity, f.RuleID,
					esc(f.Title), esc(f.Location), esc(f.Evidence), esc(f.Advice)))
			}
			b.WriteString(`</tbody></table>`)
		}
		b.WriteString(renderSuppressedHTML(res))
		b.WriteString(`</section>`)
	}

	b.WriteString(`</main></body></html>`)
	return b.String()
}

func renderSuppressedHTML(res *rules.Result) string {
	if len(res.Suppressed) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf(`<details class="sup" open><summary>Suppressed (accepted risk) · %d</summary><table><tbody>`, len(res.Suppressed)))
	for _, s := range res.Suppressed {
		exp := s.Expires
		if exp == "" {
			exp = "no expiry"
		}
		b.WriteString(fmt.Sprintf(`<tr><td class="rule">%s</td><td>%s</td><td class="reason">%s <span class="dim">(%s)</span></td></tr>`,
			s.Finding.RuleID, html.EscapeString(s.Finding.Title), html.EscapeString(s.Reason), html.EscapeString(exp)))
	}
	b.WriteString(`</tbody></table></details>`)
	return b.String()
}
