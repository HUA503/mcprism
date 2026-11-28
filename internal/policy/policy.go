// Package policy 实现策略即代码：用版本化的 YAML 文件集中管理内置规则
// 开关与严重级覆盖、自定义检查、允许/拒绝清单、能力约束和合规失败条件，
// 并提供内置基线与可审计的风险抑制。
package policy

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// RuleOverride 覆盖某条规则的默认行为。Enabled 用指针以区分“未设置”。
type RuleOverride struct {
	Enabled  *bool  `yaml:"enabled"`
	Severity string `yaml:"severity"`
}

// CustomRule adds a team-defined regex check to the versioned policy.
type CustomRule struct {
	ID          string `yaml:"id"`
	Title       string `yaml:"title"`
	Severity    string `yaml:"severity"`
	Field       string `yaml:"field"`
	Pattern     string `yaml:"pattern"`
	Description string `yaml:"description"`
	Advice      string `yaml:"advice"`
}

// MatchList 是允许/拒绝清单，支持 "*" 与 "*.domain"、"prefix*" 形式。
type MatchList struct {
	Packages []string `yaml:"packages"`
	Commands []string `yaml:"commands"`
	Domains  []string `yaml:"domains"`
}

// CapabilityPolicy 约束能力组合与网络隔离。
type CapabilityPolicy struct {
	RequireNetworkIsolation bool     `yaml:"requireNetworkIsolation"`
	Forbid                  []string `yaml:"forbid"`
}

// FailPolicy 定义合规失败条件。
type FailPolicy struct {
	Grade string `yaml:"grade"`
	Score int    `yaml:"score"`
	On    string `yaml:"on"`
}

// Policy 是完整的策略文件。
type Policy struct {
	Version      string                  `yaml:"version"`
	Description  string                  `yaml:"description"`
	Fail         FailPolicy              `yaml:"fail"`
	Rules        map[string]RuleOverride `yaml:"rules"`
	CustomRules  []CustomRule            `yaml:"customRules"`
	Allow        MatchList               `yaml:"allow"`
	Deny         MatchList               `yaml:"deny"`
	Capabilities CapabilityPolicy        `yaml:"capabilities"`
}

// Load 从文件读取策略。
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse 解析策略字节。
func Parse(data []byte) (*Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if p.Version == "" {
		p.Version = "1"
	}
	if err := validateCustomRules(p.CustomRules); err != nil {
		return nil, err
	}
	return &p, nil
}

var customRuleIDRe = regexp.MustCompile(`^CUSTOM-[A-Z0-9][A-Z0-9_-]{0,31}$`)

var customRuleFields = map[string]bool{
	"server.name": true, "server.command": true, "server.args": true,
	"server.url": true, "server.target": true, "server.transport": true,
	"server.cwd": true, "server.header_key": true,
	"server.source": true, "server.client": true, "server.env_key": true,
	"tool.name": true, "tool.title": true, "tool.description": true,
	"tool.schema": true, "resource.name": true, "resource.description": true,
	"prompt.name": true, "prompt.description": true, "content.text": true,
	"finding.rule": true, "finding.title": true, "finding.severity": true,
	"finding.location": true, "finding.evidence": true,
}

func validateCustomRules(customRules []CustomRule) error {
	if len(customRules) > 100 {
		return fmt.Errorf("policy has %d custom rules; maximum is 100", len(customRules))
	}
	seen := map[string]bool{}
	for i, rule := range customRules {
		prefix := fmt.Sprintf("customRules[%d]", i)
		if !customRuleIDRe.MatchString(rule.ID) {
			return fmt.Errorf("%s.id must use CUSTOM- followed by 1-32 uppercase letters, digits, _ or -", prefix)
		}
		if seen[rule.ID] {
			return fmt.Errorf("%s.id %q is duplicated", prefix, rule.ID)
		}
		seen[rule.ID] = true
		if strings.TrimSpace(rule.Title) == "" || strings.TrimSpace(rule.Description) == "" || strings.TrimSpace(rule.Advice) == "" {
			return fmt.Errorf("%s requires title, description, and advice", prefix)
		}
		switch strings.ToLower(strings.TrimSpace(rule.Severity)) {
		case "critical", "high", "medium", "low", "info":
		default:
			return fmt.Errorf("%s.severity must be critical, high, medium, low, or info", prefix)
		}
		if !customRuleFields[rule.Field] {
			return fmt.Errorf("%s.field %q is unsupported", prefix, rule.Field)
		}
		if len(rule.Pattern) == 0 || len(rule.Pattern) > 2048 {
			return fmt.Errorf("%s.pattern must contain 1-2048 bytes", prefix)
		}
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return fmt.Errorf("%s.pattern: %w", prefix, err)
		}
	}
	return nil
}

// Empty 返回不做任何覆盖的默认策略。
func Empty() *Policy {
	return &Policy{Version: "1"}
}
