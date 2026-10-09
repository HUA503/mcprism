package policy

import "fmt"

const defaultYAML = `
description: Built-in defaults; fails on critical findings
fail:
  on: critical
`

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
		// 安全底线：默认即对 critical（硬编码凭据、curl|sh 等）失败，
		// 避免不带任何参数的 scan 对已知 RCE 仍返回通过。
		return Parse([]byte(defaultYAML))
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
	case "default":
		return "Fails on critical findings; no other enforcement."
	case "strict":
		return "Fails on high and above; requires network isolation for servers that read/write files or run commands."
	case "ci":
		return "Fails on high and above; otherwise default rules."
	}
	return "Built-in defaults; fails on critical findings."
}
