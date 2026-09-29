package report

import (
	"fmt"
	"strings"

	"github.com/HUA503/mcprism/internal/rules"
)

func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if s == "" {
		return "—"
	}
	return s
}

func capList(c rules.Capabilities) string {
	var out []string
	if c.CanShell {
		out = append(out, "shell")
	}
	if c.CanWriteFiles {
		out = append(out, "write-files")
	}
	if c.CanReadFiles {
		out = append(out, "read-files")
	}
	if c.CanNetwork {
		out = append(out, "network")
	}
	if c.CanAccessDB {
		out = append(out, "database")
	}
	if c.CanBrowser {
		out = append(out, "browser")
	}
	if c.CanSendEmail {
		out = append(out, "email")
	}
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, ", ")
}

// RenderMarkdown 渲染可提交到仓库 / issue 的 Markdown 报告。
func RenderMarkdown(r *Report) string {
	var b strings.Builder
	b.WriteString("# mcprism security report\n\n")
	b.WriteString(fmt.Sprintf("> Generated at **%s** · mcprism `v%s`\n\n", r.GeneratedAt, r.Version))

	s := r.Summary
	b.WriteString("## Summary\n\n")
	b.WriteString("| Servers | Reachable | Tools | Findings | CRIT | HIGH | MED | LOW |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")
	b.WriteString(fmt.Sprintf("| %d | %d | %d | %d | %d | %d | %d | %d |\n\n",
		s.Servers, s.Connected, s.Tools, s.Findings, s.Critical, s.High, s.Medium, s.Low))

	for _, res := range r.Results {
		srv := res.Server
		b.WriteString(fmt.Sprintf("## %s  `grade %s`\n\n", srv.Name, res.Grade))
		b.WriteString(fmt.Sprintf("- **Target:** `%s`\n", mdCell(srv.Target())))
		if srv.Source != "" {
			b.WriteString(fmt.Sprintf("- **Source:** `%s` (%s)\n", srv.Source, srv.Client))
		}
		b.WriteString(fmt.Sprintf("- **Connected:** %v\n", res.Connected))
		b.WriteString(fmt.Sprintf("- **Capabilities:** %s\n\n", capList(res.Capabilities)))

		if len(res.Findings) == 0 {
			b.WriteString("No issues detected.\n\n")
			continue
		}
		b.WriteString("| Severity | Rule | Title | Location | Evidence | Advice |\n")
		b.WriteString("|---|---|---|---|---|---|\n")
		for _, f := range res.Findings {
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n",
				f.Severity, f.RuleID, mdCell(f.Title), mdCell(f.Location),
				mdCell(f.Evidence), mdCell(f.Advice)))
		}
		b.WriteString("\n")
	}
	return b.String()
}
