package sast

import (
	"regexp"
	"strings"
	"unicode"
)

func analyzeGo(path string) []Issue {
	lines, src := readLines(path)
	if src == "" {
		return nil
	}
	var out []Issue
	for _, b := range extractGoHandlers(src) {
		out = append(out, scanGoBlock(path, b)...)
	}
	for _, l := range lines {
		out = append(out, goLineSecretIssues(path, l)...)
	}
	return dedupIssues(out)
}

// ---------- handler extraction ----------

var goAddToolRe = regexp.MustCompile(`\.?AddTool\s*\(`)

// extractGoHandlers finds mcp-go tool registrations (server.AddTool / mcp.AddTool)
// and returns each tool's callback body.
func extractGoHandlers(src string) []handlerBlock {
	var out []handlerBlock
	for _, m := range goAddToolRe.FindAllStringIndex(src, -1) {
		openParen := m[1] - 1
		closeParen := matchClose(src, openParen, '(', ')')
		if closeParen < 0 {
			continue
		}
		// The callback is the last argument: func( ... ) { ... }.
		seg := src[openParen:closeParen]
		fi := strings.LastIndex(seg, "func(")
		if fi < 0 {
			continue
		}
		absFunc := openParen + fi
		po := indexByteFrom(src, absFunc, '(', closeParen)
		pc := matchClose(src, po, '(', ')')
		if pc < 0 {
			continue
		}
		bo := indexByteFrom(src, pc, '{', closeParen)
		if bo < 0 {
			continue
		}
		bc := matchClose(src, bo, '{', '}')
		if bc < 0 {
			continue
		}
		name := firstString(src[openParen+1 : absFunc])
		if name == "" {
			name = "tool"
		}
		out = append(out, handlerBlock{name: name, lines: linesRange(src, bo, bc)})
	}
	return out
}

// ---------- sink scanning ----------

func scanGoBlock(path string, b handlerBlock) []Issue {
	var out []Issue
	text := joinLines(b.lines)
	baseLine := b.lines[0].num
	off2line := func(off int) int { return baseLine + strings.Count(text[:off], "\n") }

	ctrl := goControllableVars(b.lines)

	// 1. process execution (MCP801)
	cmdRe := regexp.MustCompile(`\b(exec\.Command(?:Context)?|os\.StartProcess|syscall\.Exec)\s*\(`)
	for _, m := range cmdRe.FindAllStringIndex(text, -1) {
		open := m[1] - 1
		close := matchClose(text, open, '(', ')')
		if close < 0 {
			continue
		}
		arg := text[open+1 : close]
		first, rest := splitTopComma(arg)
		line := off2line(open)
		code := lineText(b, line)
		switch {
		case goExprControllable(first, ctrl):
			out = append(out, issue(path, "MCP801", "Tool argument used as the command to run", SeverityCritical, line, code,
				"Don't let agent input choose the command. Use a fixed allow-list and pass arguments without a shell."))
		case goHasShellConst(arg) && goExprControllable(rest, ctrl):
			out = append(out, issue(path, "MCP801", "Tool argument passed to an OS shell", SeverityCritical, line, code,
				"Avoid running a shell over agent input. Call exec.Command with a fixed program and validated arguments, no sh -c."))
		case goExprControllable(rest, ctrl):
			out = append(out, issue(path, "MCP801", "Tool argument passed to a fixed command", SeverityMedium, line, code,
				"Validate arguments against an allow-list. A fixed command with unvalidated args can still allow argument injection."))
		}
	}

	// 2. outbound network (MCP802 / SSRF)
	simpleURL := regexp.MustCompile(`\bhttp\.(Get|Post|Head|PostForm)\s*\(`)
	for _, m := range simpleURL.FindAllStringIndex(text, -1) {
		open := m[1] - 1
		close := matchClose(text, open, '(', ')')
		if close < 0 {
			continue
		}
		first, _ := splitTopComma(text[open+1 : close])
		line := off2line(open)
		code := lineText(b, line)
		if goExprControllable(first, ctrl) && !isConstURLArg(first) {
			out = append(out, issue(path, "MCP802", "Tool argument controls a request URL (SSRF)", SeverityHigh, line, code,
				"Do not let agent input choose the host. Pin a constant base URL or allow-list hosts, and block metadata and private ranges."))
		}
	}
	newReq := regexp.MustCompile(`\bhttp\.NewRequest(?:WithContext)?\s*\(`)
	for _, m := range newReq.FindAllStringIndex(text, -1) {
		open := m[1] - 1
		close := matchClose(text, open, '(', ')')
		if close < 0 {
			continue
		}
		arg := text[open+1 : close]
		_, afterMethod := splitTopComma(arg)
		urlArg, _ := splitTopComma(afterMethod)
		line := off2line(open)
		code := lineText(b, line)
		if goExprControllable(urlArg, ctrl) && !isConstURLArg(urlArg) {
			out = append(out, issue(path, "MCP802", "Tool argument controls a request URL (SSRF)", SeverityHigh, line, code,
				"NewRequest takes the URL as its second argument. Pin a constant base URL or allow-list hosts, and block metadata and private ranges."))
		}
	}

	// 3. filesystem paths (MCP803)
	// A path is confined only when the exact variable that reaches a file sink
	// is guarded by HasPrefix. A bare filepath.Clean is not a boundary check: it
	// normalizes the path but does not stop ../ traversal, so it must not silence
	// the finding. The guard is bound to the sink argument, not to the handler.
	guarded := goGuardedVars(b.lines)
	fileRe := regexp.MustCompile(`\b(?:os|ioutil)\.(Open|OpenFile|ReadFile|Create|WriteFile)\s*\(`)
	for _, m := range fileRe.FindAllStringIndex(text, -1) {
		open := m[1] - 1
		close := matchClose(text, open, '(', ')')
		if close < 0 {
			continue
		}
		first, _ := splitTopComma(text[open+1 : close])
		line := off2line(open)
		code := lineText(b, line)
		pathJoined := strings.Contains(first, "filepath.Join(")
		switch {
		case isGoPathConfined(first, guarded):
			continue
		case goExprControllable(first, ctrl) && !pathJoined:
			out = append(out, issue(path, "MCP803", "Tool argument used as a file path", SeverityHigh, line, code,
				"Resolve the path, confirm it stays inside one base directory with HasPrefix, and reject traversal sequences. filepath.Clean alone is not a boundary check."))
		case goExprControllable(first, ctrl):
			out = append(out, issue(path, "MCP803", "Joined path without a base-directory check", SeverityMedium, line, code,
				"filepath.Join does not stop ../ traversal. Add a HasPrefix check against the resolved base directory."))
		}
	}

	return out
}

// goControllableVars collects local variables assigned from tool arguments:
// req.RequireString, req.GetString or req.Params.Arguments[...].
func goControllableVars(ls []srcLine) map[string]bool {
	set := map[string]bool{}
	for _, l := range ls {
		t := l.text
		if !strings.Contains(t, "RequireString(") && !strings.Contains(t, ".GetString(") &&
			!strings.Contains(t, "Arguments[") && !strings.Contains(t, "GetArguments(") {
			continue
		}
		i := strings.Index(t, ":=")
		if i < 0 {
			continue
		}
		lhs := strings.TrimSpace(t[:i])
		first := strings.TrimSpace(strings.Split(lhs, ",")[0])
		if isGoIdent(first) {
			set[first] = true
		}
	}
	return set
}

func goExprControllable(expr string, ctrl map[string]bool) bool {
	if strings.Contains(expr, "RequireString(") || strings.Contains(expr, ".GetString(") ||
		strings.Contains(expr, "Arguments[") || strings.Contains(expr, "GetArguments(") {
		return true
	}
	for v := range ctrl {
		if containsWord(expr, v) {
			return true
		}
	}
	return false
}

func goHasShellConst(arg string) bool {
	for _, s := range []string{`"sh"`, `"bash"`, `"/bin/sh"`, `"/bin/bash"`, `"-c"`, `"sh",`, `"bash",`} {
		if strings.Contains(arg, s) {
			return true
		}
	}
	return false
}

func isGoIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		ok := r == '_' || unicode.IsLetter(r)
		if i > 0 {
			ok = ok || unicode.IsDigit(r)
		}
		if !ok {
			return false
		}
	}
	return true
}

// goGuardedVars collects the variables that are tested with strings.HasPrefix
// anywhere in the handler. Only those exact variables are treated as confined.
func goGuardedVars(ls []srcLine) map[string]bool {
	set := map[string]bool{}
	for _, l := range ls {
		t := l.text
		i := strings.Index(t, "HasPrefix(")
		if i < 0 {
			continue
		}
		arg, _ := splitTopComma(t[i+len("HasPrefix("):])
		arg = strings.TrimSpace(arg)
		if isGoIdent(arg) {
			set[arg] = true
		}
	}
	return set
}

// isGoPathConfined reports whether the sink argument is the exact variable that
// a HasPrefix guard protects. An unrelated guard on another variable does not
// silence the finding.
func isGoPathConfined(first string, guarded map[string]bool) bool {
	first = strings.TrimSpace(first)
	return isGoIdent(first) && guarded[first]
}

// ---------- hardcoded secrets (MCP806) ----------

var goSecretRe = regexp.MustCompile(
	`(?:const\s+)?([A-Za-z_]\w*)\s*(?::=|=)\s*(?:"([^"]{8,})"|` + "`" + `([^` + "`" + `]{8,})` + "`" + `)`)

func goLineSecretIssues(path string, l srcLine) []Issue {
	t := l.text
	if strings.Contains(t, "Getenv(") || strings.Contains(t, "LookupEnv(") {
		return nil
	}
	m := goSecretRe.FindStringSubmatch(t)
	if m == nil {
		return nil
	}
	name := m[1]
	val := m[2]
	if val == "" {
		val = m[3]
	}
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
			Severity: SeverityHigh, File: path, Line: l.num, Code: trimCode(t),
			Advice: "Load the secret from an environment variable or secret store and rotate the exposed value.",
		}}
	case secretNameRe.MatchString(name) && len(val) >= 14 && shannon(val) >= 3.8:
		return []Issue{{
			RuleID: "MCP806", Title: "Possible hardcoded secret in server source",
			Severity: SeverityMedium, File: path, Line: l.num, Code: trimCode(t),
			Advice: "Confirm whether this is a credential; if it is, move it to a secret store and rotate it.",
		}}
	}
	return nil
}
