package rules

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/HUA503/mcprism/internal/config"
)

// configServer 是 config.Server 的简写别名。
type configServer = config.Server

var secretKeyRe = regexp.MustCompile(`(?i)(token|secret|password|passwd|api[_-]?key|private[_-]?key|credential|authorization|access[_-]?key|client[_-]?secret)`)

var liveTokenPrefixes = []string{"sk-", "ghp_", "github_pat_", "xoxb", "xoxp", "AKIA", "AIza", "glpat-", "eyJ", "gho_", "nvapi-"}

var dangerousFlags = map[string]struct {
	sev    Severity
	desc   string
	advice string
}{
	"--allow-all":                      {SeverityHigh, "The server/agent is launched with all permissions granted, removing per-action consent.", "Grant only the specific permissions required."},
	"--all-permissions":                {SeverityHigh, "All permissions are enabled at once.", "Scope permissions to individual actions."},
	"--dangerously-skip-permissions":   {SeverityCritical, "Permission checks are completely bypassed.", "Never skip permission checks; run with the minimum privilege set."},
	"--no-sandbox":                     {SeverityHigh, "The sandbox is disabled, so the process runs without isolation.", "Keep the sandbox enabled; mount only required directories."},
	"--disable-gpu-sandbox":            {SeverityHigh, "The GPU sandbox is disabled.", "Avoid disabling sandbox layers."},
	"--disable-web-security":           {SeverityHigh, "Browser web security is disabled.", "Do not disable web security outside throwaway environments."},
	"--insecure":                       {SeverityMedium, "TLS certificate verification is disabled.", "Leave certificate verification enabled; fix the root cause."},
	"--allow-running-insecure-content": {SeverityMedium, "The browser is allowed to load insecure mixed content.", "Block insecure mixed content."},
}

func staticConfigRules(in Input) []Finding {
	var f []Finding
	s := in.Server

	// 1. 环境变量中的凭据：已知 token 类型 > secret-like 变量名 > 高熵疑似
	for k, v := range s.Env {
		if v == "" || isVarReference(v) || isPlaceholder(v) {
			continue
		}
		loc := "env." + k
		if kind, ok := detectKnownToken(v); ok {
			f = append(f, Finding{
				RuleID: "MCP101", Title: "Known credential type embedded in configuration",
				Severity: SeverityCritical, OWASP: "MCP01", Server: s.Name, Location: loc,
				Evidence:    k + "=" + maskSecret(v) + " (" + kind + ")",
				Description: "A recognizable credential is embedded in the configuration and handed to the process. The server, or a compromised dependency, can read and exfiltrate it.",
				Advice:      "Reference the secret from your environment or a secret manager instead of hardcoding it; rotate any credential that was committed.",
				References:  []string{"https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/"},
			})
			continue
		}
		if secretKeyRe.MatchString(k) {
			f = append(f, Finding{
				RuleID: "MCP101", Title: "Long-lived credential embedded in configuration",
				Severity: SeverityHigh, OWASP: "MCP01", Server: s.Name, Location: loc,
				Evidence:    k + "=" + maskSecret(v),
				Description: "A secret is embedded in the server configuration and handed to the process. The server, or a compromised dependency, can read it from its environment and exfiltrate it.",
				Advice:      "Reference the secret from your environment or a secret manager instead of hardcoding it; rotate any credential that was committed.",
				References:  []string{"https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/"},
			})
			continue
		}
		if len(v) >= 20 && shannonEntropy(v) >= 4.5 {
			f = append(f, Finding{
				RuleID: "MCP108", Title: "High-entropy value that may be a secret",
				Severity: SeverityMedium, OWASP: "MCP01", Server: s.Name, Location: loc,
				Evidence:    k + "=" + maskSecret(v),
				Description: "The value has high character entropy, which is typical of generated credentials or API keys, even though the variable name does not advertise it.",
				Advice:      "Check whether this is a secret and, if so, move it to a secret manager and rotate it. Non-sensitive values can be suppressed with a documented reason.",
			})
		}
	}

	// 2. 明文 HTTP
	if strings.HasPrefix(s.URL, "http://") {
		sev := SeverityMedium
		evidence := s.URL
		if hasAuthHeader(s) {
			sev = SeverityHigh
			evidence += " (request carries an Authorization header)"
		}
		f = append(f, Finding{
			RuleID: "MCP102", Title: "Cleartext HTTP transport",
			Severity: sev, OWASP: "MCP01", Server: s.Name, Evidence: evidence,
			Description: "Traffic to the server, including credentials and data, is sent over unencrypted HTTP and can be intercepted or modified on the network.",
			Advice:      "Use HTTPS or an encrypted tunnel for remote MCP servers.",
		})
	}

	// 3. 文件系统 server 被授予过宽目录
	if strings.Contains(strings.ToLower(s.Target()), "filesystem") {
		for _, a := range s.Args {
			if isOverbroadPath(a) {
				f = append(f, Finding{
					RuleID: "MCP103", Title: "Filesystem server granted a broad directory",
					Severity: SeverityHigh, OWASP: "MCP02", Server: s.Name, Evidence: "directory: " + a,
					Description: "The filesystem server is scoped to a root or home directory, giving the agent access to sensitive files such as SSH keys, credentials and configuration.",
					Advice:      "Scope the filesystem server to the smallest project-specific directory it actually needs.",
					References:  []string{"https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem"},
				})
			}
		}
	}

	// 4. shell 下载并执行远程代码
	if isShell(s.Command) {
		script := shellScript(s.Args)
		if downloadsAndExecutes(script) {
			f = append(f, Finding{
				RuleID: "MCP104", Title: "Remote code fetched and executed by shell",
				Severity: SeverityCritical, OWASP: "MCP05", Server: s.Name, Evidence: script,
				Description: "The configuration runs a shell that downloads content from a remote URL and pipes it to an interpreter (curl|sh style) — arbitrary remote code execution with no integrity verification.",
				Advice:      "Avoid curl|sh; vendor the script, verify a checksum or signature, and pin the exact version over HTTPS.",
			})
		}
	}

	// 5. 宽松 / 不安全标志
	for _, a := range s.Args {
		if d, ok := dangerousFlags[strings.ToLower(a)]; ok {
			f = append(f, Finding{
				RuleID: "MCP105", Title: "Sandbox or permission checks disabled",
				Severity: d.sev, OWASP: "MCP02", Server: s.Name, Evidence: "flag: " + a,
				Description: d.desc,
				Advice:      d.advice,
			})
		}
	}

	// 6. 远程包未固定版本
	if isFetcher(s.Command) {
		pkg, pinned := extractPackage(s.Args)
		if pkg != "" && !pinned {
			f = append(f, Finding{
				RuleID: "MCP106", Title: "Server package not pinned to a version",
				Severity: SeverityMedium, OWASP: "MCP04", Server: s.Name, Evidence: "package: " + pkg,
				Description: "The server is launched from an unpinned package, so the newest code is fetched on each run. A publisher can change behavior after you approved the server (rug pull).",
				Advice:      "Pin an exact version (name@version for npm, name==version for Python) and upgrade deliberately.",
			})
		}
	}

	// 7. 远程 server 无认证（信息）
	if isRemote(s) && !hasAuthHeader(s) && !envHasToken(s.Env) {
		f = append(f, Finding{
			RuleID: "MCP107", Title: "Remote server configured without authentication",
			Severity: SeverityInfo, OWASP: "MCP07", Server: s.Name, Evidence: s.URL,
			Description: "The remote server has no Authorization header or token, so anyone who can reach it may be able to invoke it.",
			Advice:      "Require authentication for non-public servers.",
		})
	}
	return f
}

// ---------- helpers ----------

func isVarReference(v string) bool {
	return strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") || strings.HasPrefix(v, "$")
}

func isPlaceholder(v string) bool {
	l := strings.ToLower(v)
	for _, p := range []string{"your-", "changeme", "example", "replace", "xxxx", "todo", "<"} {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

func looksLikeLiveToken(v string) bool {
	for _, p := range liveTokenPrefixes {
		if strings.HasPrefix(v, p) {
			return true
		}
	}
	return false
}

func maskSecret(v string) string {
	if len(v) <= 8 {
		return strings.Repeat("*", len(v))
	}
	return v[:4] + strings.Repeat("*", 6) + v[len(v)-2:]
}

func hasAuthHeader(s *configServer) bool {
	for k := range s.Headers {
		if strings.EqualFold(k, "authorization") {
			return true
		}
	}
	return false
}

func isOverbroadPath(a string) bool {
	switch a {
	case "/", "/home", "/root", "/Users", "/etc", "/usr", "/var", "~", "$HOME", "/home/user", "/Users/Shared":
		return true
	}
	return false
}

func isShell(cmd string) bool {
	switch filepath.Base(cmd) {
	case "bash", "sh", "zsh", "ash", "dash", "ksh":
		return true
	}
	return false
}

func shellScript(args []string) string {
	for i, a := range args {
		if a == "-c" && i+1 < len(args) {
			return strings.Join(args[i+1:], " ")
		}
	}
	return strings.Join(args, " ")
}

func downloadsAndExecutes(script string) bool {
	l := strings.ToLower(script)
	fetches := strings.Contains(l, "curl") || strings.Contains(l, "wget")
	executes := strings.Contains(l, "| sh") || strings.Contains(l, "|sh") ||
		strings.Contains(l, "| bash") || strings.Contains(l, "|bash") ||
		strings.Contains(l, "| zsh") || strings.Contains(l, "eval ") ||
		strings.Contains(l, "|$sh") || strings.Contains(l, "| $")
	return fetches && executes
}

func isFetcher(cmd string) bool {
	switch filepath.Base(cmd) {
	case "npx", "npm", "bunx", "uvx", "pipx", "pnpm", "yarn", "deno":
		return true
	}
	return false
}

func extractPackage(args []string) (string, bool) {
	for _, a := range args {
		if strings.HasPrefix(a, "-") || a == "" {
			continue
		}
		// 跳过明显的路径
		if strings.HasPrefix(a, "/") || strings.HasPrefix(a, "./") {
			continue
		}
		return a, isPinned(a)
	}
	return "", false
}

func isPinned(pkg string) bool {
	if strings.Contains(pkg, "==") {
		return true
	}
	if strings.HasPrefix(pkg, "@") {
		if i := strings.Index(pkg, "/"); i >= 0 {
			return strings.Contains(pkg[i+1:], "@")
		}
		return false
	}
	return strings.Contains(pkg, "@")
}

func isRemote(s *configServer) bool {
	return s.Transport == "http" || s.Transport == "sse"
}

func envHasToken(env map[string]string) bool {
	for k := range env {
		if secretKeyRe.MatchString(k) {
			return true
		}
	}
	return false
}
