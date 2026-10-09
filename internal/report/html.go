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
		return "var(--sev-crit)"
	case rules.SeverityHigh:
		return "var(--sev-high)"
	case rules.SeverityMedium:
		return "var(--sev-med)"
	case rules.SeverityLow:
		return "var(--sev-low)"
	}
	return "var(--sev-info)"
}

func gradeHex(g string) string {
	return map[string]string{
		"A": "var(--g-A)", "B": "var(--g-B)", "C": "var(--g-C)", "D": "var(--g-D)", "F": "var(--g-F)",
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
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; script-src 'none'; base-uri 'none'; form-action 'none'">
<title>mcprism security report</title>
<style>
:root{color-scheme:dark;
--bg:#1e1e2e;--panel:#28283a;--card:#313244;--ink:#11111b;--text:#cdd6f4;--muted:#a6adc8;--subtle:#6c7086;--border:#45475a;--line:#313244;
--sev-crit:#f38ba8;--sev-high:#fab387;--sev-med:#f9e2af;--sev-low:#89b4fa;--sev-info:#a6adc8;
--g-A:#a6e3a1;--g-B:#94e2d5;--g-C:#f9e2af;--g-D:#fab387;--g-F:#f38ba8;
--ok:#a6e3a1;--advice:#a6e3a1;--evidence:#f9e2af;--reason:#cba6f7}
@media (prefers-color-scheme:light){:root{
color-scheme:light;
--bg:#f4f5fa;--panel:#ffffff;--card:#eceef5;--ink:#e3e6f0;--text:#1e1e2e;--muted:#555a6b;--subtle:#7b8094;--border:#d3d7e3;--line:#e4e7f0;
--sev-crit:#d20f39;--sev-high:#c25700;--sev-med:#9a6b00;--sev-low:#1e66f5;--sev-info:#5c5f77;
--g-A:#2f8a25;--g-B:#0f8fa8;--g-C:#9a6b00;--g-D:#c25700;--g-F:#d20f39;
--ok:#2f8a25;--advice:#2f7a4d;--evidence:#8a5a00;--reason:#8844b0}}
:root:has(#lightmode:checked){
color-scheme:light;
--bg:#f4f5fa;--panel:#ffffff;--card:#eceef5;--ink:#e3e6f0;--text:#1e1e2e;--muted:#555a6b;--subtle:#7b8094;--border:#d3d7e3;--line:#e4e7f0;
--sev-crit:#d20f39;--sev-high:#c25700;--sev-med:#9a6b00;--sev-low:#1e66f5;--sev-info:#5c5f77;
--g-A:#2f8a25;--g-B:#0f8fa8;--g-C:#9a6b00;--g-D:#c25700;--g-F:#d20f39;
--ok:#2f8a25;--advice:#2f7a4d;--evidence:#8a5a00;--reason:#8844b0}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.prism-bar{height:5px;background:linear-gradient(90deg,#f38ba8,#fab387,#f9e2af,#a6e3a1,#94e2d5,#89b4fa,#cba6f7)}
.theme{position:absolute;top:14px;right:22px;font-size:12.5px;color:var(--muted);display:flex;align-items:center;gap:6px;cursor:pointer;user-select:none}
main{max-width:1080px;margin:0 auto;padding:28px 24px 60px}
h1{font-size:26px;margin:0 0 2px}
h1 .dim,.dim{color:var(--subtle);font-weight:400}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:22px 0 30px}
.card{background:var(--card);border-radius:12px;padding:14px 18px;min-width:110px}
.card .num{font-size:26px;font-weight:700}
.card .label{color:var(--muted);font-size:13px}
.card.crit .num{color:var(--sev-crit)}.card.high .num{color:var(--sev-high)}
.card.med .num{color:var(--sev-med)}.card.low .num{color:var(--sev-low)}
.server{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin:0 0 18px}
.server-head{display:flex;align-items:center;gap:14px;margin-bottom:8px}
.grade{display:inline-flex;align-items:center;justify-content:center;width:40px;height:40px;border-radius:10px;font-weight:800;font-size:20px;background:var(--ink)}
.sname{font-size:18px;font-weight:700}
.conn-ok{color:var(--ok);font-size:13px}.conn-bad{color:var(--sev-crit);font-size:13px}
.meta{font-size:13px;margin:2px 0;word-break:break-all}
.meta .dim{display:inline-block;min-width:64px}
.chips{margin:10px 0 4px}
.chip{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;margin:0 6px 6px 0;background:var(--ink)}
table{width:100%;border-collapse:collapse;margin-top:10px;font-size:13.5px}
th{text-align:left;color:var(--muted);font-weight:600;padding:8px 10px;border-bottom:1px solid var(--border)}
td{padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
tr.sev td:first-child{font-weight:700}
.rule{color:var(--subtle);white-space:nowrap}
.advice{color:var(--advice)}
.evidence{color:var(--evidence);font-size:12.5px}
.ok{color:var(--ok)}
.gate-pass{color:var(--ok)}.gate-fail{color:var(--sev-crit)}
.card.gate .num{font-size:20px;padding-top:3px}
.loc-line{display:inline-block;min-width:20px;padding:0 6px;margin-left:6px;border-radius:6px;background:var(--ink);color:var(--muted);font-variant-numeric:tabular-nums;text-align:center}
.sup{margin-top:12px;border-top:1px dashed var(--border);padding-top:10px}
.sup summary{cursor:pointer;color:var(--muted);font-size:13px}
.sup table{font-size:12.5px}
.sup .reason{color:var(--reason)}
.overview{display:flex;align-items:center;gap:26px;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px 24px;margin:20px 0 16px;flex-wrap:wrap}
.ring{--pct:100;--ring:var(--ok);flex:0 0 auto;width:128px;height:128px;border-radius:50%;background:conic-gradient(var(--ring) calc(var(--pct)*1%),var(--card) 0);display:flex;align-items:center;justify-content:center}
.ring-hole{width:94px;height:94px;border-radius:50%;background:var(--bg);display:flex;flex-direction:column;align-items:center;justify-content:center}
.ring-grade{font-size:36px;font-weight:800;line-height:1}
.ring-score{font-size:12px;color:var(--muted);margin-top:3px}
.ov-body{flex:1;min-width:230px}
.ov-label{color:var(--subtle);font-size:12px;letter-spacing:.6px;margin-bottom:7px}
.ov-line{font-size:14px;margin:3px 0;color:var(--text)}
.ov-gate{text-align:center;padding:12px 22px;border-radius:12px;background:var(--ink);min-width:108px}
.gate-word{font-size:26px;font-weight:800;line-height:1}
.gate-profile{font-size:12px;color:var(--muted);margin-top:4px}
.ov-gate.pass .gate-word{color:var(--ok)}.ov-gate.fail .gate-word{color:var(--sev-crit)}
@media print{
.prism-bar,.theme{display:none}
body{background:#fff;color:#000;font-size:12px}
.server,.card,.overview,.ov-gate,.ring-hole{background:#fff;border-color:#999;break-inside:avoid}
.server,.overview{border:1px solid #999}
.grade,.chip,.card,.loc-line{background:#eee}
a{color:#000;text-decoration:none}
main{max-width:none;padding:0}
}
</style></head><body><div class="prism-bar"></div>
<label class="theme" for="lightmode"><input type="checkbox" id="lightmode"> Light mode</label>
<main>`)

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

	for si, res := range r.Results {
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
			addChip("SHELL", "var(--sev-crit)")
		}
		if res.Capabilities.CanWriteFiles {
			addChip("WRITE", "var(--sev-high)")
		}
		if res.Capabilities.CanReadFiles {
			addChip("READ", "var(--sev-low)")
		}
		if res.Capabilities.CanNetwork {
			addChip("NETWORK", "var(--reason)")
		}
		if res.Capabilities.CanAccessDB {
			addChip("DATABASE", "var(--sev-med)")
		}
		if res.Capabilities.CanBrowser {
			addChip("BROWSER", "var(--g-B)")
		}
		if res.Capabilities.CanSendEmail {
			addChip("EMAIL", "var(--sev-high)")
		}
		b.WriteString(`</div>`)

		if len(res.Findings) == 0 {
			b.WriteString(`<p class="ok">✓ No issues detected</p>`)
		} else {
			b.WriteString(`<table><thead><tr><th>Severity</th><th>Rule</th><th>Title</th><th>Location</th><th>Evidence</th><th>Advice</th></tr></thead><tbody>`)
			for i, f := range res.Findings {
				b.WriteString(fmt.Sprintf(`<tr class="sev" id="finding-%d-%d" style="box-shadow:inset 3px 0 0 %s"><td style="color:%s">%s</td>
<td class="rule">%s</td><td>%s</td><td>%s</td><td class="evidence">%s</td><td class="advice">%s</td></tr>`,
					si, i, sevHex(f.Severity), sevHex(f.Severity), f.Severity,
					f.RuleID, esc(f.Title), htmlLocation(f.Location), esc(f.Evidence), esc(f.Advice)))
			}
			b.WriteString(`</tbody></table>`)
		}
		b.WriteString(renderSuppressedHTML(res))
		b.WriteString(`</section>`)
	}

	b.WriteString(`</main></body></html>`)
	return b.String()
}

// htmlLocation renders a "path:line" source location as the file path plus a
// monospaced line-number badge. Locations without a parseable line fall back
// to the escaped raw text.
func htmlLocation(loc string) string {
	if strings.TrimSpace(loc) == "" {
		return ""
	}
	if file, line, ok := parseFileLine(loc); ok {
		return fmt.Sprintf(`%s<span class="loc-line">L%d</span>`, html.EscapeString(file), line)
	}
	return html.EscapeString(loc)
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
