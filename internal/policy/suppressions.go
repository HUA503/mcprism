package policy

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/HUA503/mcprism/internal/rules"
)

// Suppression 是一条带理由和到期日的风险抑制。
type Suppression struct {
	Rule     string `yaml:"rule"`
	Server   string `yaml:"server"`
	Location string `yaml:"location"`
	Reason   string `yaml:"reason"`
	Expires  string `yaml:"expires"`
}

// SuppressionFile 是抑制清单文件。
type SuppressionFile struct {
	Suppressions []Suppression `yaml:"suppressions"`
}

// LoadSuppressions 读取抑制清单。
func LoadSuppressions(path string) ([]Suppression, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sf SuppressionFile
	if err := yaml.Unmarshal(data, &sf); err != nil {
		return nil, err
	}
	return sf.Suppressions, nil
}

// ApplySuppressions 从结果中移除匹配且未过期的发现，转入 Suppressed 以便审计。
func ApplySuppressions(results []*rules.Result, sups []Suppression, now time.Time) []*rules.Result {
	for _, r := range results {
		kept := r.Findings[:0]
		for _, fnd := range r.Findings {
			if s, ok := matchSuppression(fnd, r.Server.Name, sups, now); ok {
				r.Suppressed = append(r.Suppressed, rules.SuppressedFinding{
					Finding: fnd, Reason: s.Reason, Expires: s.Expires,
				})
				continue
			}
			kept = append(kept, fnd)
		}
		r.Findings = kept
	}
	return results
}

func matchSuppression(f rules.Finding, server string, sups []Suppression, now time.Time) (Suppression, bool) {
	for _, s := range sups {
		if s.Rule != f.RuleID && s.Rule != "*" {
			continue
		}
		if s.Server != "" && s.Server != server {
			continue
		}
		if s.Location != "" && s.Location != f.Location {
			continue
		}
		if s.Expires != "" {
			if exp, err := time.Parse("2006-01-02", s.Expires); err == nil && now.After(exp) {
				continue // 已过期，不抑制
			}
		}
		return s, true
	}
	return Suppression{}, false
}
