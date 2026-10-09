package rules

import (
	"regexp"
	"sort"
	"strings"

	"github.com/HUA503/mcprism/internal/config"
	"github.com/HUA503/mcprism/internal/protocol"
)

// urlCredsRe matches credentials embedded in a URL's userinfo
// (scheme://user:pass@host), including URLs embedded inside a sentence.
var urlCredsRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)([^\s/@"'<>]+):([^\s/@"'<>]+)@`)

// redactTextURLs replaces any URL userinfo password with ***. It works on free
// text, so it can sanitize evidence strings that quote a server URL.
func redactTextURLs(s string) string {
	return urlCredsRe.ReplaceAllString(s, "${1}${2}:***@")
}

// reportTarget returns a human-readable target for reports. Command lines are
// kept as-is (secrets belong in env/headers, which are never reported); any
// credentials embedded in a URL userinfo are redacted.
func reportTarget(s *config.Server) string {
	if s.URL != "" {
		return redactTextURLs(s.URL)
	}
	return s.Target()
}

// Input 是单个 server 的审查输入。动态字段可能为零值（离线 / 连接失败）。
type Input struct {
	Server     *config.Server             `json:"server"`
	Init       *protocol.InitializeResult `json:"init,omitempty"`
	Tools      []protocol.Tool            `json:"tools"`
	Resources  []protocol.Resource        `json:"resources"`
	Prompts    []protocol.Prompt          `json:"prompts"`
	ConnectErr error                      `json:"-"`
	// EnumErr 记录枚举 tools/resources/prompts 时发生的错误。空列表不等于安全：
	// 如果枚举没有成功完成，不能把"没有危险工具"当作结论。
	EnumErr []string `json:"-"`
}

// Result 是单个 server 的审查结果。
type Result struct {
	Server *config.Server `json:"-"`
	// 可序列化的目标标识，供 JSON/SARIF/CSV 等机器输出归档与复现。
	// Env 和 Headers 可能含凭据，有意不放进报告；URL 里的 userinfo 会脱敏。
	ServerName    string              `json:"server"`
	Transport     string              `json:"transport,omitempty"`
	Target        string              `json:"target,omitempty"`
	Source        string              `json:"source,omitempty"`
	Client        string              `json:"client,omitempty"`
	ProjectDir    string              `json:"projectDir,omitempty"`
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
		ServerName:    in.Server.Name,
		Transport:     string(in.Server.Transport),
		Target:        reportTarget(in.Server),
		Source:        in.Server.Source,
		Client:        in.Server.Client,
		ProjectDir:    in.Server.ProjectDir,
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
	if len(in.EnumErr) > 0 {
		r.Findings = append(r.Findings, enumerationRules(in)...)
	}

	// Strip credentials from any URL a rule quoted into its evidence.
	for i := range r.Findings {
		r.Findings[i].Evidence = redactTextURLs(r.Findings[i].Evidence)
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

// hintURLRe matches http(s) URLs so documentation links in tool descriptions
// are not mistaken for the ability to make network calls.
var hintURLRe = regexp.MustCompile(`https?://[^\s)\]>'"]+`)

// hintNegRe matches negation phrases. A clause containing one (e.g. "this tool
// does NOT use shell") is dropped before keyword matching so denials are not
// read as capabilities.
var hintNegRe = regexp.MustCompile(`(?i)\b(?:does not|do not|doesn'?t|don'?t|can not|cannot|can'?t|could not|will not|won'?t|without|never|no longer|not|no)\b`)

// hintSchemaKeyRe pulls JSON object keys out of an InputSchema document.
var hintSchemaKeyRe = regexp.MustCompile(`"([a-z_][a-z0-9_]{1,32})"\s*:`)

// sanitizeHints removes URLs and negated clauses from free-text metadata
// before capability keyword matching. Splitting on clause punctuation keeps a
// denial localized instead of stripping the whole description.
func sanitizeHints(s string) string {
	s = hintURLRe.ReplaceAllString(s, " ")
	clauses := strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ',', '.', ';', ':', '!', '?', '\n', '\r', '(', ')', '[', ']':
			return true
		}
		return false
	})
	keep := make([]string, 0, len(clauses))
	for _, c := range clauses {
		if strings.TrimSpace(c) == "" || hintNegRe.MatchString(c) {
			continue
		}
		keep = append(keep, c)
	}
	return strings.Join(keep, " ")
}

// schemaParamHints raises capabilities from high-confidence InputSchema
// parameter names, which describe what the tool actually accepts more reliably
// than marketing prose in its description.
func schemaParamHints(c *Capabilities, tools []protocol.Tool) {
	for _, t := range tools {
		if len(t.InputSchema) == 0 {
			continue
		}
		keys := hintSchemaKeyRe.FindAllStringSubmatch(strings.ToLower(string(t.InputSchema)), -1)
		for _, k := range keys {
			switch k[1] {
			case "command", "cmd", "executable", "script_path":
				c.CanShell = true
			case "url", "uri", "endpoint", "host", "webhook_url":
				c.CanNetwork = true
			case "sql", "query", "database", "collection", "table_name":
				c.CanAccessDB = true
			case "path", "filepath", "file_path", "dir", "directory", "folder", "filename", "file_name":
				c.CanReadFiles = true
			}
		}
	}
}

// inferCapabilities 从命令/包名与工具元数据推断 server 的实际能力。
func inferCapabilities(in Input) Capabilities {
	c := Capabilities{}
	var b strings.Builder
	// The package/command name is a strong signal, but a remote HTTP transport
	// URL is not: every streamable-HTTP server has one regardless of what its
	// tools can do, so URLs are stripped before keyword matching.
	b.WriteString(sanitizeHints(hintURLRe.ReplaceAllString(strings.ToLower(in.Server.Target()), " ")))
	for _, t := range in.Tools {
		b.WriteByte(' ')
		b.WriteString(sanitizeHints(strings.ToLower(t.Name + " " + t.Description)))
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
	c.CanNetwork = has("http request", "fetch", "download", "web request", "api call", "curl", "send request", "make a request", "url to fetch")
	c.CanAccessDB = has("sql", "database", "postgres", "mysql", "sqlite", "mongo", "redis", "run query", "execute query")
	c.CanBrowser = has("browser", "playwright", "puppeteer", "selenium", "navigate", "screenshot", "click ", "webpage", "web page")
	c.CanSendEmail = has("send email", "smtp", "e-mail", "mail message")

	schemaParamHints(&c, in.Tools)

	pkg := hintURLRe.ReplaceAllString(strings.ToLower(in.Server.Target()), " ")
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
	hasCritical, hasHigh := false, false
	for _, f := range r.Findings {
		switch f.Severity {
		case SeverityCritical:
			penalty += 25
			hasCritical = true
		case SeverityHigh:
			penalty += 12
			hasHigh = true
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
	// Highest-severity veto: a single critical finding caps the score in the F
	// band, and any high finding caps it at D. A weighted total alone would let a
	// remote-code-execution server score 75/C, which reads as "mostly fine".
	if hasCritical && s > 50 {
		s = 50
	}
	if !hasCritical && hasHigh && s > 69 {
		s = 69
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
