package sast

import (
	"regexp"
	"strings"
)

func analyzePython(path string) []Issue {
	lines, src := readLines(path)
	if src == "" {
		return nil
	}
	var out []Issue
	for _, b := range extractPythonHandlers(lines) {
		out = append(out, scanPythonBlock(path, b)...)
	}
	for _, l := range lines {
		out = append(out, lineSecretIssues(path, l)...)
	}
	return dedupIssues(out)
}

// ---------- handler extraction ----------

var pyToolDecRe = regexp.MustCompile(`@[\w\.]+\.(tool|call_tool)\b`)

func extractPythonHandlers(lines []srcLine) []handlerBlock {
	var blocks []handlerBlock
	n := len(lines)
	for i := 0; i < n; i++ {
		t := strings.TrimSpace(lines[i].text)
		if !strings.HasPrefix(t, "@") || !pyToolDecRe.MatchString(t) {
			continue
		}
		isCallTool := strings.Contains(t, "call_tool")
		// Skip stacked decorators, comments and blank lines to reach the def.
		j := i + 1
		for j < n {
			tt := strings.TrimSpace(lines[j].text)
			if tt == "" || strings.HasPrefix(tt, "@") || strings.HasPrefix(tt, "#") {
				j++
				continue
			}
			break
		}
		if j >= n {
			continue
		}
		fnName, params, ok := parsePyDef(lines[j].text)
		if !ok {
			continue
		}
		baseIndent := indentOf(lines[j].text)
		body := pyBodyRange(lines, j, baseIndent)
		if body == nil {
			continue
		}
		if isCallTool {
			params = append(params, "arguments")
		}
		blocks = append(blocks, handlerBlock{name: fnName, params: params, lines: body})
		i = j
	}
	return blocks
}

func parsePyDef(line string) (string, []string, bool) {
	re := regexp.MustCompile(`\bdef\s+(\w+)\s*\(([^)]*)\)`)
	m := re.FindStringSubmatch(line)
	if m == nil {
		return "", nil, false
	}
	var params []string
	for _, p := range strings.Split(m[2], ",") {
		p = strings.TrimSpace(p)
		if eq := strings.Index(p, "="); eq >= 0 {
			p = strings.TrimSpace(p[:eq])
		}
		if ci := strings.Index(p, ":"); ci >= 0 {
			p = strings.TrimSpace(p[:ci])
		}
		p = strings.TrimPrefix(strings.TrimPrefix(p, "*"), "*")
		if p == "" || p == "self" || p == "cls" {
			continue
		}
		params = append(params, p)
	}
	return m[1], params, true
}

func pyBodyRange(lines []srcLine, defIdx, baseIndent int) []srcLine {
	var out []srcLine
	started := false
	for k := defIdx + 1; k < len(lines); k++ {
		t := lines[k].text
		if strings.TrimSpace(t) == "" {
			if started {
				out = append(out, lines[k])
			}
			continue
		}
		if indentOf(t) <= baseIndent {
			break
		}
		started = true
		out = append(out, lines[k])
	}
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1].text) == "" {
		out = out[:len(out)-1]
	}
	return out
}

func indentOf(s string) int {
	return len(s) - len(strings.TrimLeft(s, " \t"))
}

// ---------- sink scanning ----------

func scanPythonBlock(path string, b handlerBlock) []Issue {
	var out []Issue
	text := joinLines(b.lines)
	baseLine := b.lines[0].num
	off2line := func(off int) int { return baseLine + strings.Count(text[:off], "\n") }

	// 1. process execution
	cmdRe := regexp.MustCompile(`\b(os\.system|os\.popen|subprocess\.(run|call|Popen|check_output|check_call))\s*\(`)
	for _, m := range cmdRe.FindAllStringIndex(text, -1) {
		open := m[1] - 1
		close := matchClose(text, open, '(', ')')
		if close < 0 {
			continue
		}
		arg := text[open+1 : close]
		firstArg, rest := splitTopComma(arg)
		raw := text[m[0]:m[1]]
		line := off2line(m[0])
		code := lineText(b, line)
		switch {
		case strings.HasPrefix(raw, "os.system") || strings.HasPrefix(raw, "os.popen"):
			if pyControllable(firstArg, b.params) {
				out = append(out, issue(path, "MCP801", "Tool argument passed to an OS shell", SeverityCritical, line, code,
					"Don't run a shell over agent input. Use subprocess with a fixed command and an argument list, or an allow-list."))
			}
		case strings.Contains(arg, "shell=True") && pyControllable(arg, b.params):
			out = append(out, issue(path, "MCP801", "shell=True used with tool input", SeverityCritical, line, code,
				"Remove shell=True and pass a fixed command with an argument list, or validate against an allow-list."))
		case pyControllable(firstArg, b.params):
			out = append(out, issue(path, "MCP801", "Tool input chooses the command to run", SeverityCritical, line, code,
				"Fix the command and validate tool input against an allow-list."))
		case pyControllable(rest, b.params):
			out = append(out, issue(path, "MCP801", "Tool input passed into subprocess arguments", SeverityMedium, line, code,
				"Validate arguments against an allow-list to prevent argument injection."))
		}
	}

	// 2. dynamic code execution
	dynRe := regexp.MustCompile(`\b(eval|exec)\s*\(`)
	for _, m := range dynRe.FindAllStringIndex(text, -1) {
		open := m[1] - 1
		close := matchClose(text, open, '(', ')')
		arg := text[open+1 : close]
		line := off2line(m[0])
		code := lineText(b, line)
		sev, title := SeverityHigh, "Dynamic code execution"
		if pyControllable(arg, b.params) {
			sev, title = SeverityCritical, "Tool argument passed to dynamic code execution"
		}
		out = append(out, issue(path, "MCP804", title, sev, line, code,
			"Remove eval/exec. Isolate any code that must run and never feed it agent-controlled input."))
	}

	// 3. outbound network (SSRF)
	netRe := regexp.MustCompile(`\b(requests\.(get|post|put|request)|httpx\.(get|post|put)|urlopen)\s*\(`)
	for _, m := range netRe.FindAllStringIndex(text, -1) {
		open := m[1] - 1
		close := matchClose(text, open, '(', ')')
		arg := text[open+1 : close]
		firstArg, _ := splitTopComma(arg)
		line := off2line(m[0])
		code := lineText(b, line)
		if pyControllable(firstArg, b.params) && !hasConstURLPrefix(firstArg) {
			out = append(out, issue(path, "MCP802", "Tool argument controls a request URL (SSRF)", SeverityHigh, line, code,
				"Pin a constant base URL or allow-list hosts, and block metadata endpoints and private ranges."))
		}
	}

	// 4. filesystem paths
	safePath := strings.Contains(text, ".startswith(") &&
		(strings.Contains(text, "realpath") || strings.Contains(text, "abspath") || strings.Contains(text, "commonpath"))
	openRe := regexp.MustCompile(`\bopen\s*\(`)
	for _, m := range openRe.FindAllStringIndex(text, -1) {
		open := m[1] - 1
		close := matchClose(text, open, '(', ')')
		arg := text[open+1 : close]
		firstArg, _ := splitTopComma(arg)
		line := off2line(m[0])
		code := lineText(b, line)
		if !safePath && pyControllable(firstArg, b.params) {
			out = append(out, issue(path, "MCP803", "Tool argument used as a file path", SeverityHigh, line, code,
				"Resolve the real path, confirm it stays inside one base directory with startswith, and reject traversal input."))
		}
	}
	// Path(tool input) combined with read_text/write_text.
	pathCtorRe := regexp.MustCompile(`Path\s*\(`)
	for _, m := range pathCtorRe.FindAllStringIndex(text, -1) {
		open := m[1] - 1
		close := matchClose(text, open, '(', ')')
		arg := text[open+1 : close]
		line := off2line(m[0])
		code := lineText(b, line)
		if !safePath && pyControllable(arg, b.params) &&
			(regexp.MustCompile(`read_text|write_text`).MatchString(text)) {
			out = append(out, issue(path, "MCP803", "Tool input builds a path used for file access", SeverityHigh, line, code,
				"Resolve the real path and confirm it stays inside one base directory before reading or writing."))
		}
	}

	// 5. unsafe deserialization
	deserRe := regexp.MustCompile(`\b(pickle\.(loads|load)|marshal\.loads|yaml\.load)\s*\(`)
	for _, m := range deserRe.FindAllStringIndex(text, -1) {
		open := m[1] - 1
		close := matchClose(text, open, '(', ')')
		arg := text[open+1 : close]
		raw := text[m[0]:m[1]]
		line := off2line(m[0])
		code := lineText(b, line)
		if strings.HasPrefix(raw, "yaml.load") && strings.Contains(arg, "SafeLoader") {
			continue
		}
		title := "Unsafe deserialization of untrusted data"
		advice := "Do not deserialize untrusted data with pickle/marshal. For YAML use safe_load or SafeLoader."
		if strings.HasPrefix(raw, "yaml.load") {
			title = "yaml.load without a safe loader"
			advice = "Use yaml.safe_load or yaml.load(..., Loader=yaml.SafeLoader)."
		}
		out = append(out, issue(path, "MCP805", title, SeverityHigh, line, code, advice))
	}
	return out
}

func pyControllable(expr string, params []string) bool {
	for _, p := range params {
		if p != "" && containsWord(expr, p) {
			return true
		}
	}
	return strings.Contains(expr, "arguments")
}
