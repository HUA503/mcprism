package sast

import (
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Analyze walks a source tree and returns issues found in supported files.
// Dependency and build directories are skipped.
func Analyze(root string) ([]Issue, error) {
	var issues []Issue
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		issues = append(issues, AnalyzeFile(p)...)
		return nil
	})
	return issues, err
}

// AnalyzeFile reviews a single source file. Unsupported files return nothing.
func AnalyzeFile(path string) []Issue {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs":
		return analyzeJS(path)
	case ".py":
		return analyzePython(path)
	case ".go":
		return analyzeGo(path)
	}
	return nil
}

// IsSourceProject reports whether a directory looks like an MCP server source
// tree: it contains a JS/Python manifest or at least one source file.
func IsSourceProject(dir string) bool {
	if hasFile(dir, "package.json") || hasFile(dir, "pyproject.toml") ||
		hasFile(dir, "setup.py") || hasFile(dir, "go.mod") {
		return true
	}
	found := false
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if found || err != nil {
			return nil
		}
		if d.IsDir() {
			if p != dir && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(d.Name())) {
		case ".js", ".ts", ".py", ".go":
			found = true
		}
		return nil
	})
	return found
}

func hasFile(dir, name string) bool {
	info, err := os.Stat(filepath.Join(dir, name))
	return err == nil && !info.IsDir()
}

func skipDir(n string) bool {
	switch n {
	case "node_modules", ".git", "dist", "build", "vendor", "venv", ".venv",
		"__pycache__", ".cache", ".mypy_cache", ".pytest_cache", "eggs", ".eggs":
		return true
	}
	return false
}

func readLines(path string) ([]srcLine, string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, ""
	}
	raw := strings.ReplaceAll(string(data), "\r\n", "\n")
	parts := strings.Split(raw, "\n")
	out := make([]srcLine, len(parts))
	for i, p := range parts {
		out[i] = srcLine{num: i + 1, text: p}
	}
	return out, raw
}

// ---------- shared secret detection (MCP806) ----------

var secretAssignRe = regexp.MustCompile(`(?:const|let|var|private|readonly)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*["'` + "`" + `]([^"'` + "`" + `]{8,})["'` + "`" + `]`)

var secretNameRe = regexp.MustCompile(`(?i)(token|secret|password|passwd|api[_-]?key|private[_-]?key|credential|auth)`)

var knownSecretPrefixes = []string{
	"sk-", "ghp_", "github_pat_", "xoxb", "xoxp", "xoxa", "AKIA", "AIza",
	"glpat-", "gho_", "nvapi-", "SG.", "RKM-",
}

func lineSecretIssues(path string, l srcLine) []Issue {
	text := l.text
	if strings.Contains(text, "process.env") || strings.Contains(text, "os.environ") ||
		strings.Contains(text, "getenv(") {
		return nil
	}
	m := secretAssignRe.FindStringSubmatch(text)
	if m == nil {
		return nil
	}
	name, val := m[1], m[2]
	if isPlaceholderVal(val) {
		return nil
	}
	known := false
	for _, p := range knownSecretPrefixes {
		if strings.HasPrefix(val, p) {
			known = true
			break
		}
	}
	switch {
	case known:
		return []Issue{{
			RuleID: "MCP806", Title: "Hardcoded secret in server source",
			Severity: SeverityHigh, File: path, Line: l.num, Code: trimCode(text),
			Advice: "Load the secret from an environment variable or secret store and rotate the exposed value.",
		}}
	case secretNameRe.MatchString(name) && len(val) >= 14 && shannon(val) >= 3.8:
		return []Issue{{
			RuleID: "MCP806", Title: "Possible hardcoded secret in server source",
			Severity: SeverityMedium, File: path, Line: l.num, Code: trimCode(text),
			Advice: "Confirm whether this is a credential; if it is, move it to a secret store and rotate it.",
		}}
	}
	return nil
}

func isPlaceholderVal(v string) bool {
	l := strings.ToLower(v)
	for _, p := range []string{"example", "changeme", "your-", "xxxx", "todo", "replace", "<", "dummy", "sample"} {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]int{}
	for _, r := range s {
		freq[r]++
	}
	var h float64
	n := float64(len(s))
	for _, c := range freq {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// ---------- small text helpers ----------

func trimCode(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

func containsWord(text, word string) bool {
	idx := 0
	for {
		i := strings.Index(text[idx:], word)
		if i < 0 {
			return false
		}
		start := idx + i
		end := start + len(word)
		before := byte(' ')
		after := byte(' ')
		if start > 0 {
			before = text[start-1]
		}
		if end < len(text) {
			after = text[end]
		}
		if !isIdentByte(before) && !isIdentByte(after) {
			return true
		}
		idx = end
	}
}

func isIdentByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '$'
}

func dedupIssues(in []Issue) []Issue {
	seen := map[string]bool{}
	out := make([]Issue, 0, len(in))
	for _, x := range in {
		key := x.RuleID + "|" + x.File + "|" + itoa(x.Line) + "|" + x.Code
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, x)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
