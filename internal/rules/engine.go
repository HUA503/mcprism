package rules

import (
	"sort"
	"strings"

	"github.com/HUA503/mcprism/internal/config"
	"github.com/HUA503/mcprism/internal/protocol"
)

// Input 是单个 server 的审查输入。动态字段可能为零值（离线 / 连接失败）。
type Input struct {
	Server     *config.Server             `json:"server"`
	Init       *protocol.InitializeResult `json:"init,omitempty"`
	Tools      []protocol.Tool            `json:"tools"`
	Resources  []protocol.Resource        `json:"resources"`
	Prompts    []protocol.Prompt          `json:"prompts"`
	ConnectErr error                      `json:"-"`
}

// Result 是单个 server 的审查结果。
type Result struct {
	Server        *config.Server      `json:"-"`
	Capabilities  Capabilities        `json:"capabilities"`
	Findings      []Finding           `json:"findings"`
	Connected     bool                `json:"connected"`
	Probed        bool                `json:"probed"`
	ConnectError  string              `json:"connectError,omitempty"`
	ToolCount     int                 `json:"toolCount"`
	ResourceCount int                 `json:"resourceCount"`
	PromptCount   int                 `json:"promptCount"`
	Score         int                 `json:"score"`
	Grade         string              `json:"grade"`
	Suppressed    []SuppressedFinding `json:"suppressed,omitempty"`
}

// Rescore 在策略调整 findings 后重新计算分数与等级。
func Rescore(r *Result) {
	r.Score, r.Grade = score(r)
}

// Analyze 对单个 server 执行完整分析。
func Analyze(in Input) *Result {
	r := &Result{
		Server:        in.Server,
		ToolCount:     len(in.Tools),
		ResourceCount: len(in.Resources),
		PromptCount:   len(in.Prompts),
		Connected:     in.Init != nil,
		Probed:        in.Init != nil || in.ConnectErr != nil,
	}
	if in.ConnectErr != nil {
		r.ConnectError = in.ConnectErr.Error()
	}

	r.Capabilities = inferCapabilities(in)
	r.Findings = append(r.Findings, staticConfigRules(in)...)
	r.Findings = append(r.Findings, metadataPoisoningRules(in)...)
	r.Findings = append(r.Findings, capabilityRules(in, r.Capabilities)...)
	r.Findings = append(r.Findings, supplyChainRules(in)...)
	r.Findings = append(r.Findings, networkTargetRules(in)...)
	r.Findings = append(r.Findings, sourceCodeRules(in)...)
	// Schema heuristics only when the server's own code is unavailable; when a
	// source tree exists, the SAST rules (MCP801–MCP806) are more precise.
	if in.Server.ProjectDir == "" {
		r.Findings = append(r.Findings, schemaHeuristicRules(in)...)
	}
	if !r.Connected {
		r.Findings = append(r.Findings, connectionRules(in)...)
	}

	r.Score, r.Grade = score(r)
	return r
}

// AnalyzeAll 分析多个 server，并追加跨 server 关联规则（工具遮蔽 / 命名冲突）。
func AnalyzeAll(inputs []Input) []*Result {
	results := make([]*Result, 0, len(inputs))
	owners := map[string]map[string]bool{}
	for _, in := range inputs {
		r := Analyze(in)
		results = append(results, r)
		set := owners
		_ = set
		for _, t := range in.Tools {
			if owners[t.Name] == nil {
				owners[t.Name] = map[string]bool{}
			}
			owners[t.Name][in.Server.Name] = true
		}
	}

	// 跨 server：同名工具（潜在遮蔽 / 冲突）
	toolNames := make([]string, 0)
	for n := range owners {
		toolNames = append(toolNames, n)
	}
	sort.Strings(toolNames)
	for _, tn := range toolNames {
		srvSet := owners[tn]
		if len(srvSet) < 2 {
			continue
		}
		srvList := make([]string, 0)
		for s := range srvSet {
			srvList = append(srvList, s)
		}
		sort.Strings(srvList)
		for _, r := range results {
			if !srvSet[r.Server.Name] {
				continue
			}
			r.Findings = append(r.Findings, Finding{
				RuleID:      "MCP601",
				Title:       "Cross-server tool name collision",
				Severity:    SeverityMedium,
				OWASP:       "MCP03",
				Server:      r.Server.Name,
				Location:    tn,
				Evidence:    "tool '" + tn + "' also defined by: " + strings.Join(others(srvList, r.Server.Name), ", "),
				Description: "The same tool name is exposed by multiple servers. A malicious or lower-quality server can shadow the intended one and influence which definition the agent uses (tool shadowing / namespace collision).",
				Advice:      "Rename colliding tools, scope servers explicitly, or disable untrusted servers that share tool names with trusted ones.",
				References:  []string{"https://modelcontextprotocol.io/docs/concepts/tools"},
			})
		}
	}
	return results
}

func others(list []string, self string) []string {
	out := make([]string, 0, len(list))
	for _, x := range list {
		if x != self {
			out = append(out, x)
		}
	}
	return out
}

// inferCapabilities 从命令/包名与工具元数据推断 server 的实际能力。
func inferCapabilities(in Input) Capabilities {
	c := Capabilities{}
	var b strings.Builder
	b.WriteString(strings.ToLower(in.Server.Target()))
	for _, t := range in.Tools {
		b.WriteByte(' ')
		b.WriteString(strings.ToLower(t.Name))
		b.WriteByte(' ')
		b.WriteString(strings.ToLower(t.Description))
	}
	text := b.String()

	has := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(text, w) {
				return true
			}
		}
		return false
	}

	c.CanShell = has("shell", "execute command", "run command", "exec command", "subprocess", "terminal", "powershell", "run script", "eval(", "exec(", "execute a command", "execute shell", "command-line", "bash", "sh -c", "/bin/sh", "/bin/bash")
	c.CanReadFiles = has("read file", "file contents", "list files", "read directory", "open file", "read_dir", "cat ", "filesystem", "read a file", "directory listing")
	c.CanWriteFiles = has("write file", "create file", "delete file", "edit file", "save file", "remove file", "move file", "write_file", "mkdir", "write to file", "modify file")
	c.CanNetwork = has("http request", "fetch", "download", "web request", "api call", "curl", "send request", "http://", "https://", "make a request", "url to fetch")
	c.CanAccessDB = has("sql", "database", "postgres", "mysql", "sqlite", "mongo", "redis", "run query", "execute query")
	c.CanBrowser = has("browser", "playwright", "puppeteer", "selenium", "navigate", "screenshot", "click ", "webpage", "web page")
	c.CanSendEmail = has("send email", "smtp", "e-mail", "mail message")

	pkg := strings.ToLower(in.Server.Target())
	if strings.Contains(pkg, "filesystem") {
		c.CanReadFiles = true
		c.CanWriteFiles = true
	}
	if strings.Contains(pkg, "puppeteer") || strings.Contains(pkg, "playwright") {
		c.CanBrowser = true
		c.CanNetwork = true
	}
	return c
}

func score(r *Result) (int, string) {
	penalty := 0
	for _, f := range r.Findings {
		switch f.Severity {
		case SeverityCritical:
			penalty += 25
		case SeverityHigh:
			penalty += 12
		case SeverityMedium:
			penalty += 5
		case SeverityLow:
			penalty += 2
		}
	}
	s := 100 - penalty
	if s < 0 {
		s = 0
	}
	grade := "F"
	switch {
	case s >= 90:
		grade = "A"
	case s >= 80:
		grade = "B"
	case s >= 70:
		grade = "C"
	case s >= 60:
		grade = "D"
	}
	return s, grade
}
