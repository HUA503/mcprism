// Package rules 实现 mcprism 的安全分析引擎：能力推断、静态配置检查、
// 工具描述投毒检测、权限组合建模、供应链风险与跨 server 关联分析，
// 并将每条发现映射到 OWASP MCP Top 10 风险框架。
package rules

// Severity 是发现的严重级别。
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Finding 是一条安全发现。
type Finding struct {
	RuleID      string   `json:"ruleId"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	OWASP       string   `json:"owasp,omitempty"`
	Server      string   `json:"server"`
	Location    string   `json:"location,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	Description string   `json:"description"`
	Advice      string   `json:"advice"`
	References  []string `json:"references,omitempty"`
}

// Capabilities 描述从包名与工具元数据推断出的 server 能力。
type Capabilities struct {
	CanShell      bool     `json:"canShell"`
	CanReadFiles  bool     `json:"canReadFiles"`
	CanWriteFiles bool     `json:"canWriteFiles"`
	CanNetwork    bool     `json:"canNetwork"`
	CanAccessDB   bool     `json:"canAccessDB"`
	CanBrowser    bool     `json:"canBrowser"`
	CanSendEmail  bool     `json:"canSendEmail"`
	Labels        []string `json:"labels,omitempty"`
}
