package policy

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/HUA503/mcprism/internal/rules"
)

// Enforce 对引擎结果应用策略：规则开关/严重级覆盖、deny 清单命中、
// 网络隔离约束，然后重算分数。建议顺序：Analyze → Enforce →
// ApplySuppressions → Rescore。
func Enforce(results []*rules.Result, p *Policy) []*rules.Result {
	if p == nil {
		return results
	}
	for _, r := range results {
		// 1. 规则覆盖
		if len(p.Rules) > 0 {
			kept := r.Findings[:0]
			for _, fnd := range r.Findings {
				ov, has := p.Rules[fnd.RuleID]
				if has && ov.Enabled != nil && !*ov.Enabled {
					continue
				}
				if has && ov.Severity != "" {
					fnd.Severity = normalizeSeverity(ov.Severity)
				}
				kept = append(kept, fnd)
			}
			r.Findings = kept
		}

		// 2. deny 清单（allow 优先）
		if hit, pat := matchDeny(r, p); hit {
			r.Findings = append(r.Findings, rules.Finding{
				RuleID: "MCP700", Title: "Blocked by policy",
				Severity: rules.SeverityHigh, OWASP: "MCP07",
				Server: r.Server.Name, Evidence: pat,
				Description: "The server matches a deny entry in the configured policy.",
				Advice:      "Remove the server, or change the policy if this is intended; list trusted entries under allow.",
			})
		}

		// 3. 网络隔离
		if p.Capabilities.RequireNetworkIsolation && r.Capabilities.CanNetwork &&
			(r.Capabilities.CanShell || r.Capabilities.CanWriteFiles || r.Capabilities.CanReadFiles) {
			r.Findings = append(r.Findings, rules.Finding{
				RuleID: "MCP701", Title: "Data/execution capability combined with network (policy)",
				Severity: rules.SeverityHigh, OWASP: "MCP02", Server: r.Server.Name,
				Description: "The policy requires network isolation for servers that run commands or read/write files, but this server also has network access.",
				Advice:      "Run the server without network egress, or split the capabilities across isolated servers.",
			})
		}
		rules.Rescore(r)
	}
	return results
}

func matchDeny(r *rules.Result, p *Policy) (bool, string) {
	srv := r.Server
	target := strings.ToLower(srv.Target())
	pkg := packageName(target)

	host := ""
	if u, err := url.Parse(srv.URL); err == nil {
		host = strings.ToLower(u.Hostname())
	}
	for _, d := range p.Deny.Packages {
		if wildcardMatch(d, pkg) && !anyMatch(p.Allow.Packages, pkg) {
			return true, "deny package: " + d
		}
	}
	base := strings.ToLower(path.Base(srv.Command))
	for _, d := range p.Deny.Commands {
		if wildcardMatch(d, base) && !anyMatch(p.Allow.Commands, base) {
			return true, "deny command: " + d
		}
	}
	if host != "" {
		for _, d := range p.Deny.Domains {
			d = strings.ToLower(d)
			if wildcardMatch(d, host) && !anyMatch(p.Allow.Domains, host) {
				return true, "deny domain: " + d
			}
		}
	}
	return false, ""
}

// Evaluate 根据策略的 fail 条件给出整体合规结论。
func Evaluate(results []*rules.Result, p *Policy, profile, policyPath string) rules.Compliance {
	c := rules.Compliance{Profile: profile, Policy: policyPath, Pass: true}
	if c.Profile == "" {
		c.Profile = "default"
	}

	maxSev := 0
	minScore := 100
	worstGrade := "A"
	for _, r := range results {
		for _, fnd := range r.Findings {
			if rank(fnd.Severity) > maxSev {
				maxSev = rank(fnd.Severity)
			}
		}
		if r.Score < minScore {
			minScore = r.Score
		}
		if gradeRank(r.Grade) < gradeRank(worstGrade) {
			worstGrade = r.Grade
		}
	}

	if p != nil {
		if p.Fail.On != "" && maxSev >= rank(normalizeSeverity(p.Fail.On)) {
			c.Pass = false
			c.Reason = fmt.Sprintf("a finding at or above %s exists", p.Fail.On)
		}
		if c.Pass && p.Fail.Score > 0 && minScore < p.Fail.Score {
			c.Pass = false
			c.Reason = fmt.Sprintf("minimum score %d required, lowest is %d", p.Fail.Score, minScore)
		}
		if c.Pass && p.Fail.Grade != "" && gradeRank(worstGrade) < gradeRank(p.Fail.Grade) {
			c.Pass = false
			c.Reason = fmt.Sprintf("minimum grade %s required, worst is %s", p.Fail.Grade, worstGrade)
		}
	}
	return c
}

// ---------- helpers ----------

func anyMatch(patterns []string, s string) bool {
	for _, p := range patterns {
		if wildcardMatch(p, s) {
			return true
		}
	}
	return false
}

func wildcardMatch(pattern, s string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	s = strings.ToLower(s)
	if pattern == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		root := pattern[2:]
		return s == root || strings.HasSuffix(s, "."+root)
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(s, pattern[:len(pattern)-1])
	}
	return s == pattern
}

func packageName(target string) string {
	for _, f := range strings.Fields(target) {
		if strings.HasPrefix(f, "-") {
			continue
		}
		if strings.ContainsAny(f, `/\`) && !strings.HasPrefix(f, "@") {
			continue
		}
		return f
	}
	return ""
}

func rank(s rules.Severity) int {
	switch s {
	case rules.SeverityCritical:
		return 4
	case rules.SeverityHigh:
		return 3
	case rules.SeverityMedium:
		return 2
	case rules.SeverityLow:
		return 1
	}
	return 0
}

func normalizeSeverity(s string) rules.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL", "CRIT":
		return rules.SeverityCritical
	case "HIGH":
		return rules.SeverityHigh
	case "MEDIUM", "MED":
		return rules.SeverityMedium
	case "LOW":
		return rules.SeverityLow
	}
	return rules.SeverityInfo
}

func gradeRank(g string) int {
	if len(g) == 0 {
		return 0
	}
	v := 5 - int(g[0]-'A')
	if v < 0 {
		return 0
	}
	if v > 5 {
		return 5
	}
	return v
}
