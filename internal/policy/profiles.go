package policy

import "fmt"

const strictYAML = `
description: Strict baseline for production and security-sensitive teams
fail:
  on: high
capabilities:
  requireNetworkIsolation: true
`

const ciYAML = `
description: Baseline for CI pipelines
fail:
  on: high
`

// Builtin 返回命名内置基线。
func Builtin(name string) (*Policy, error) {
	switch name {
	case "", "default":
		return Empty(), nil
	case "strict":
		return Parse([]byte(strictYAML))
	case "ci":
		return Parse([]byte(ciYAML))
	}
	return nil, fmt.Errorf("unknown profile %q (available: default, strict, ci)", name)
}

// ListProfiles 返回内置基线名称。
func ListProfiles() []string {
	return []string{"default", "strict", "ci"}
}

// DescribeProfile 返回基线的简短说明。
func DescribeProfile(name string) string {
	switch name {
	case "strict":
		return "Fails on high and above; requires network isolation for servers that read/write files or run commands."
	case "ci":
		return "Fails on high and above; otherwise default rules."
	}
	return "Built-in defaults; no enforcement beyond the rule set."
}
