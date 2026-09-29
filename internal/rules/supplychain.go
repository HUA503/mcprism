package rules

import (
	"path/filepath"
	"strings"

	"github.com/HUA503/mcprism/internal/config"
)

// typoSigs 是知名 MCP 包的常见拼写劫持（typosquat）变体。
var typoSigs = []struct {
	bad  string
	good string
}{
	{"modelcontextprotcol", "@modelcontextprotocol/*"},
	{"modelcontextprotocal", "@modelcontextprotocol/*"},
	{"modelcontextprotocl", "@modelcontextprotocol/*"},
	{"modelcontext-proto", "@modelcontextprotocol/*"},
	{"mcp-server-filsystem", "server-filesystem"},
	{"mcp-server-fylesystem", "server-filesystem"},
	{"server-filsystem", "server-filesystem"},
}

func supplyChainRules(in Input) []Finding {
	var f []Finding
	s := in.Server
	target := strings.ToLower(s.Target())

	// 1. typosquat 包名
	for _, sig := range typoSigs {
		if strings.Contains(target, sig.bad) {
			f = append(f, Finding{
				RuleID: "MCP402", Title: "Possible typosquat package name",
				Severity: SeverityMedium, OWASP: "MCP04", Server: s.Name, Evidence: sig.bad,
				Description: "The package name closely resembles a well-known MCP package (" + sig.good + ") but is misspelled, which may indicate a look-alike malicious package.",
				Advice:      "Verify the exact official package name and publisher before running it.",
				References:  []string{"https://en.wikipedia.org/wiki/Typosquatting"},
			})
		}
	}

	// 2. 直接运行远程 URL 脚本
	if runsRemoteURL(s) {
		f = append(f, Finding{
			RuleID: "MCP403", Title: "Executing code directly from a remote URL",
			Severity: SeverityHigh, OWASP: "MCP04", Server: s.Name, Evidence: remoteArg(s),
			Description: "The runtime executes code fetched live from a remote URL with no local copy or version pin, so the code can change at any time (supply-chain / rug pull risk).",
			Advice:      "Vendor the code locally, pin an immutable version, and verify a checksum or signature.",
		})
	}

	// 3. 通过环境变量禁用 TLS 证书校验
	if tlsDisabled(s) {
		f = append(f, Finding{
			RuleID: "MCP404", Title: "TLS certificate verification disabled",
			Severity: SeverityHigh, OWASP: "MCP01", Server: s.Name, Evidence: tlsEvidence(s),
			Description: "The server process is configured to skip TLS certificate verification, allowing man-in-the-middle attacks on its outbound traffic.",
			Advice:      "Remove the setting that disables certificate verification and fix the underlying certificate issue.",
		})
	}
	return f
}

func runsRemoteURL(s *config.Server) bool {
	base := filepath.Base(s.Command)
	for _, a := range s.Args {
		u := strings.ToLower(a)
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			continue
		}
		switch base {
		case "deno", "bun", "npx", "npm", "bunx":
			return true
		}
	}
	return false
}

func remoteArg(s *config.Server) string {
	for _, a := range s.Args {
		u := strings.ToLower(a)
		if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			return a
		}
	}
	return ""
}

func tlsDisabled(s *config.Server) bool {
	if v, ok := s.Env["NODE_TLS_REJECT_UNAUTHORIZED"]; ok && v == "0" {
		return true
	}
	if v, ok := s.Env["PYTHONHTTPSVERIFY"]; ok && v == "0" {
		return true
	}
	return false
}

func tlsEvidence(s *config.Server) string {
	if v, ok := s.Env["NODE_TLS_REJECT_UNAUTHORIZED"]; ok && v == "0" {
		return "NODE_TLS_REJECT_UNAUTHORIZED=0"
	}
	return "PYTHONHTTPSVERIFY=0"
}
