// Package policy 实现策略即代码：用版本化的 YAML 文件集中管理规则开关、
// 严重级覆盖、允许/拒绝清单、能力约束和合规失败条件，并提供内置基线
// 与可审计的风险抑制。
package policy

import (
	"os"

	"gopkg.in/yaml.v3"
)

// RuleOverride 覆盖某条规则的默认行为。Enabled 用指针以区分“未设置”。
type RuleOverride struct {
	Enabled  *bool  `yaml:"enabled"`
	Severity string `yaml:"severity"`
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
	return &p, nil
}

// Empty 返回不做任何覆盖的默认策略。
func Empty() *Policy {
	return &Policy{Version: "1"}
}
