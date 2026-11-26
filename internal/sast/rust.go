package sast

import (
	"regexp"
	"strings"
)

// analyzeRust supports the official rmcp #[tool] macro and bounded taint flow
// through unambiguous same-file helpers. It does not expand macros or resolve
// trait-based dispatch.
func analyzeRust(path string) []Issue {
	lines, src := readLines(path)
	if src == "" {
		return nil
	}
	code := maskRustCode(src)
	var out []Issue
	if strings.Contains(code, "rmcp") {
		functions := extractRustFunctions(src, code)
		for _, block := range extractRustHandlers(src, code) {
			out = append(out, scanReachableRust(path, src, block, functions)...)
		}
	}
	for _, line := range maskedLines(lines, maskRustComments) {
		out = append(out, lineSecretIssues(path, line)...)
	}
	out = append(out, rustSecretIssues(path, src)...)
	return dedupIssues(out)
}

var rustToolAttributeRe = regexp.MustCompile(`(?m)#\[\s*(?:rmcp::)?tool(?:\s*\([^]]*\))?\s*\]`)
var rustToolFunctionRe = regexp.MustCompile(`(?s)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)\s*\(`)

func extractRustHandlers(src, code string) []handlerBlock {
	var out []handlerBlock
	for _, attr := range rustToolAttributeRe.FindAllStringIndex(code, -1) {
		rest := code[attr[1]:]
		fn := rustToolFunctionRe.FindStringSubmatchIndex(rest)
		if fn == nil {
			continue
		}
		fnStart := attr[1] + fn[0]
		fnName := code[attr[1]+fn[2] : attr[1]+fn[3]]
		open := strings.IndexByte(code[fnStart:attr[1]+fn[1]], '(') + fnStart
		close := rustMatchClose(code, open, '(', ')')
		if close < 0 {
			continue
		}
		bodyOpen := strings.IndexByte(code[close+1:], '{')
		if bodyOpen < 0 {
			continue
		}
		bodyOpen += close + 1
		bodyClose := rustMatchClose(code, bodyOpen, '{', '}')
		if bodyClose < 0 {
			continue
		}
		params := rustToolParameters(code[open+1 : close])
		out = append(out, handlerBlock{
			name: fnName, params: params,
			lines: linesRange(src, bodyOpen, bodyClose+1),
		})
	}
	return out
}

var rustFunctionRe = regexp.MustCompile(`\bfn\s+([A-Za-z_]\w*)(?:\s*<[^>{}]*>)?\s*\(`)

// extractRustFunctions indexes same-file functions with unique names. A helper
// whose name is repeated (for example, methods on multiple types) is omitted
// rather than resolving a call to the wrong body.
func extractRustFunctions(src, code string) map[string]handlerBlock {
	functions := map[string]handlerBlock{}
	ambiguous := map[string]bool{}
	toolNames := map[string]bool{}
	for _, handler := range extractRustHandlers(src, code) {
		toolNames[handler.name] = true
	}
	for _, m := range rustFunctionRe.FindAllStringSubmatchIndex(code, -1) {
		name := code[m[2]:m[3]]
		if toolNames[name] || ambiguous[name] {
			continue
		}
		open := m[1] - 1
		close := rustMatchClose(code, open, '(', ')')
		if close < 0 {
			continue
		}
		bodyOpen := strings.IndexByte(code[close+1:], '{')
		if bodyOpen < 0 {
			continue
		}
		bodyOpen += close + 1
		bodyClose := rustMatchClose(code, bodyOpen, '{', '}')
		if bodyClose < 0 {
			continue
		}
		if _, exists := functions[name]; exists {
			delete(functions, name)
			ambiguous[name] = true
			continue
		}
		functions[name] = handlerBlock{
			name: name, params: rustFunctionParameters(code[open+1 : close]),
			lines: linesRange(src, bodyOpen, bodyClose+1),
		}
	}
	return functions
}

func rustFunctionParameters(src string) []string {
	var names []string
	for _, param := range splitRustComma(src) {
		param = strings.TrimSpace(param)
		if param == "" {
			continue
		}
		if param == "self" || strings.HasPrefix(param, "self:") || strings.HasPrefix(param, "&self") || strings.HasPrefix(param, "&mut self") {
			continue
		}
		pattern := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(rustPatternBeforeType(param), "mut "), "ref "))
		if isRustIdent(pattern) {
			names = append(names, pattern)
		} else {
			// Preserve argument positions for unsupported destructuring patterns.
			names = append(names, "")
		}
	}
	return names
}

func scanReachableRust(path, src string, entry handlerBlock, functions map[string]handlerBlock) []Issue {
	taintedByName := map[string]map[string]bool{}
	processedByName := map[string]map[string]bool{}
	queue := []handlerBlock{entry}
	callRe := regexp.MustCompile(`\b([A-Za-z_]\w*)\s*\(`)
	var out []Issue
	for head := 0; head < len(queue); head++ {
		block := queue[head]
		seed := rustTaintedNames(block.lines, block.params)
		known := taintedByName[block.name]
		if known == nil {
			known = map[string]bool{}
			taintedByName[block.name] = known
		}
		for name := range seed {
			known[name] = true
		}
		processed := processedByName[block.name]
		if processed == nil {
			processed = map[string]bool{}
			processedByName[block.name] = processed
		}
		pending := false
		for name := range known {
			if !processed[name] {
				pending = true
				processed[name] = true
			}
		}
		if !pending && head > 0 {
			continue
		}
		params := make([]string, 0, len(known))
		for name := range known {
			params = append(params, name)
		}
		block.params = params
		out = append(out, scanRustBlock(path, src, block)...)

		text := maskRustCode(joinLines(block.lines))
		ctrl := rustTaintedNames(block.lines, params)
		for _, call := range callRe.FindAllStringSubmatchIndex(text, -1) {
			name := text[call[2]:call[3]]
			helper, ok := functions[name]
			if !ok || call[0] > 0 && text[call[0]-1] == ':' {
				continue
			}
			if call[0] > 0 && text[call[0]-1] == '.' {
				receiver := strings.TrimSpace(text[:call[0]-1])
				if !strings.HasSuffix(receiver, "self") {
					continue
				}
				receiver = strings.TrimSuffix(receiver, "self")
				if receiver != "" {
					last := receiver[len(receiver)-1]
					if isRustIdent(string(last)) || last == '.' {
						continue
					}
				}
			}
			open := call[1] - 1
			close := rustMatchClose(text, open, '(', ')')
			if close < 0 {
				continue
			}
			args := splitRustComma(text[open+1 : close])
			for i, param := range helper.params {
				if i >= len(args) {
					break
				}
				if param == "" {
					continue
				}
				if !rustControllable(args[i], ctrl) {
					continue
				}
				if taintedByName[name] == nil {
					taintedByName[name] = map[string]bool{}
				}
				if !taintedByName[name][param] {
					taintedByName[name][param] = true
					child := helper
					child.params = []string{param}
					queue = append(queue, child)
				}
			}
		}
	}
	return out
}

func rustToolParameters(src string) []string {
	var names []string
	for _, param := range splitRustComma(src) {
		param = strings.TrimSpace(param)
		if param == "" || param == "self" || strings.HasPrefix(param, "&self") {
			continue
		}
		pattern := rustPatternBeforeType(param)
		if pattern == "" {
			continue
		}
		if open := strings.Index(pattern, "Parameters("); open >= 0 {
			start := open + len("Parameters")
			end := rustMatchClose(pattern, start, '(', ')')
			if end >= 0 {
				pattern = pattern[start+1 : end]
			}
		}
		if open := strings.IndexByte(pattern, '{'); open >= 0 {
			if close := rustMatchClose(pattern, open, '{', '}'); close > open {
				for _, field := range splitRustComma(pattern[open+1 : close]) {
					field = strings.TrimSpace(field)
					if field == "" || field == ".." {
						continue
					}
					if _, rhs := splitRustTopColon(field); rhs != "" {
						field = rhs
					}
					field = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(field, "mut "), "ref "))
					if isRustIdent(field) {
						names = append(names, field)
					}
				}
				continue
			}
		}
		if open := strings.LastIndexByte(pattern, '('); open >= 0 {
			if close := rustMatchClose(pattern, open, '(', ')'); close > open {
				pattern = strings.TrimSpace(pattern[open+1 : close])
			}
		}
		pattern = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(pattern, "mut "), "ref "))
		if isRustIdent(pattern) {
			names = append(names, pattern)
		}
	}
	return dedupStrings(names)
}

func rustPatternBeforeType(param string) string {
	paren, bracket, brace, angle := 0, 0, 0, 0
	for i := 0; i < len(param); i++ {
		switch param[i] {
		case '(':
			paren++
		case ')':
			paren--
		case '[':
			bracket++
		case ']':
			bracket--
		case '{':
			brace++
		case '}':
			brace--
		case '<':
			angle++
		case '>':
			if angle > 0 {
				angle--
			}
		case ':':
			if paren == 0 && bracket == 0 && brace == 0 && angle == 0 &&
				(i+1 == len(param) || param[i+1] != ':') && (i == 0 || param[i-1] != ':') {
				return strings.TrimSpace(param[:i])
			}
		}
	}
	return strings.TrimSpace(param)
}

func splitRustTopColon(s string) (string, string) {
	paren, bracket, brace, angle := 0, 0, 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			paren++
		case ')':
			paren--
		case '[':
			bracket++
		case ']':
			bracket--
		case '{':
			brace++
		case '}':
			brace--
		case '<':
			angle++
		case '>':
			if angle > 0 {
				angle--
			}
		case ':':
			if paren == 0 && bracket == 0 && brace == 0 && angle == 0 &&
				(i+1 == len(s) || s[i+1] != ':') && (i == 0 || s[i-1] != ':') {
				return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
			}
		}
	}
	return strings.TrimSpace(s), ""
}

func splitRustComma(s string) []string {
	var out []string
	start := 0
	paren, bracket, brace, angle := 0, 0, 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			paren++
		case ')':
			paren--
		case '[':
			bracket++
		case ']':
			bracket--
		case '{':
			brace++
		case '}':
			brace--
		case '<':
			angle++
		case '>':
			if angle > 0 {
				angle--
			}
		case ',':
			if paren == 0 && bracket == 0 && brace == 0 && angle == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	if tail := strings.TrimSpace(s[start:]); tail != "" {
		out = append(out, tail)
	}
	return out
}

func scanRustBlock(path, src string, b handlerBlock) []Issue {
	if len(b.lines) == 0 {
		return nil
	}
	text := maskRustCode(joinLines(b.lines))
	raw := joinLines(b.lines)
	baseLine := b.lines[0].num
	off2line := func(off int) int { return baseLine + strings.Count(text[:off], "\n") }
	tainted := rustTaintedNames(b.lines, b.params)
	var out []Issue

	commandRe := regexp.MustCompile(`\bCommand::new\s*\(`)
	for _, m := range commandRe.FindAllStringIndex(text, -1) {
		open := m[1] - 1
		close := rustMatchClose(text, open, '(', ')')
		if close < 0 {
			continue
		}
		first, rest := splitTopComma(text[open+1 : close])
		line := off2line(open)
		codeLine := lineText(b, line)
		switch {
		case rustControllable(first, tainted):
			out = append(out, issue(path, "MCP801", "Tool input chooses the process to run", SeverityCritical, line, codeLine,
				"Use a fixed executable and pass validated arguments. Never let tool input select a program."))
		case rustControllable(rest, tainted):
			out = append(out, issue(path, "MCP801", "Tool input passed to process arguments", SeverityMedium, line, codeLine,
				"Validate process arguments against an allow-list and avoid shell interpreters."))
		}
	}

	if strings.Contains(text, "Command::new") {
		argRe := regexp.MustCompile(`\.args?\s*\(`)
		shellModeRe := regexp.MustCompile(`(?s)Command::new\s*\(\s*["'](?:sh|bash|cmd|powershell)["']\s*\).*?\.arg\s*\(\s*["'](?:-c|/c)["']`)
		shellSource := maskRustComments(raw)
		for _, m := range argRe.FindAllStringIndex(text, -1) {
			open := m[1] - 1
			close := rustMatchClose(text, open, '(', ')')
			if close < 0 {
				continue
			}
			arg := text[open+1 : close]
			if !rustControllable(arg, tainted) {
				continue
			}
			line := off2line(open)
			severity, title := SeverityMedium, "Tool input passed to process arguments"
			advice := "Validate process arguments against an allow-list and avoid shell interpreters."
			chainStart := strings.LastIndex(raw[:m[0]], "Command::new")
			if chainStart >= 0 && shellModeRe.MatchString(shellSource[chainStart:m[0]]) {
				severity, title = SeverityCritical, "Tool input passed to an OS shell"
				advice = "Do not pass tool input to sh -c or another shell. Use a fixed executable and validated argument array."
			}
			out = append(out, issue(path, "MCP801", title, severity, line, lineText(b, line), advice))
		}
	}

	if strings.Contains(maskRustCode(src), "reqwest") {
		networkRe := regexp.MustCompile(`\b(?:reqwest::get|[A-Za-z_]\w*\.(?:get|post|put|delete))\s*\(`)
		for _, m := range networkRe.FindAllStringIndex(text, -1) {
			open := m[1] - 1
			close := rustMatchClose(text, open, '(', ')')
			if close < 0 {
				continue
			}
			first, _ := splitTopComma(text[open+1 : close])
			if rustControllable(first, tainted) {
				line := off2line(open)
				out = append(out, issue(path, "MCP802", "Tool input controls a request URL (SSRF)", SeverityHigh, line, lineText(b, line),
					"Do not let tool input choose the request host. Pin a base URL or allow-list hosts and block metadata and private ranges."))
			}
		}
	}

	fileRe := regexp.MustCompile(`\b(?:(?:std::|tokio::)?fs::(?:read|read_to_string|read_link|write|remove_file|remove_dir|metadata|canonicalize|create_dir_all|read_dir)|(?:std::)?fs::File::(?:open|create)|File::(?:open|create))\s*\(`)
	for _, m := range fileRe.FindAllStringIndex(text, -1) {
		open := m[1] - 1
		close := rustMatchClose(text, open, '(', ')')
		if close < 0 {
			continue
		}
		first, _ := splitTopComma(text[open+1 : close])
		if !rustControllable(first, tainted) || rustPathGuarded(first, text) {
			continue
		}
		line := off2line(open)
		out = append(out, issue(path, "MCP803", "Tool input used as a filesystem path", SeverityHigh, line, lineText(b, line),
			"Canonicalize the path, confirm it remains under an approved base directory, and reject traversal and symlink escapes."))
	}
	return out
}

func rustTaintedNames(lines []srcLine, seeds []string) map[string]bool {
	set := map[string]bool{}
	for _, name := range seeds {
		if isRustIdent(name) {
			set[name] = true
		}
	}
	assign := regexp.MustCompile(`\blet\s+(?:mut\s+)?([^=;]+?)\s*=\s*([^;]+)`)
	code := maskRustCode(joinLines(lines))
	codeLines := strings.Split(code, "\n")
	for changed := true; changed; {
		changed = false
		for i := range lines {
			if i >= len(codeLines) {
				continue
			}
			for _, m := range assign.FindAllStringSubmatch(codeLines[i], -1) {
				lhs, _ := splitRustTopColon(strings.TrimSpace(m[1]))
				lhs = strings.TrimSpace(strings.TrimPrefix(lhs, "mut "))
				if isRustIdent(lhs) && !set[lhs] && rustControllable(m[2], set) {
					set[lhs] = true
					changed = true
				}
			}
		}
	}
	return set
}

func rustControllable(expr string, names map[string]bool) bool {
	for name := range names {
		if containsWord(expr, name) {
			return true
		}
	}
	return false
}

func rustPathGuarded(arg, body string) bool {
	arg = strings.TrimSpace(arg)
	if !isRustIdent(arg) {
		return false
	}
	name := regexp.QuoteMeta(arg)
	assignedCanonicalPath := regexp.MustCompile(`\blet\s+(?:mut\s+)?` + name + `\s*=\s*[^;\n]*(?:\.canonicalize\s*\(\)|(?:std::|tokio::)?fs::canonicalize\s*\()`).MatchString(body)
	checked := regexp.MustCompile(`\b` + name + `\.starts_with\s*\(`).MatchString(body)
	return assignedCanonicalPath && checked
}

func rustMatchClose(src string, open int, left, right byte) int {
	if open < 0 || open >= len(src) || src[open] != left {
		return -1
	}
	depth := 0
	for i := open; i < len(src); i++ {
		if src[i] == left {
			depth++
		} else if src[i] == right {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func isRustIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if (r != '_' && !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z')) &&
			(i == 0 || r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func rustSecretIssues(path, src string) []Issue {
	masked := maskRustComments(src)
	lines := strings.Split(masked, "\n")
	original := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	secret := regexp.MustCompile(`(?i)\b(?:const|static)\s+([A-Za-z_]\w*)\s*:\s*[^=]+?=\s*"([^"\n]{8,})"`)
	var out []Issue
	for i, line := range lines {
		m := secret.FindStringSubmatch(line)
		if m == nil || isPlaceholderVal(m[2]) {
			continue
		}
		known := false
		for _, prefix := range knownSecretPrefixes {
			if strings.HasPrefix(m[2], prefix) {
				known = true
				break
			}
		}
		if known || secretNameRe.MatchString(m[1]) && len(m[2]) >= 14 && shannon(m[2]) >= 3.8 {
			if i < len(original) {
				severity, title := SeverityMedium, "Possible hardcoded secret in Rust source"
				if known {
					severity, title = SeverityHigh, "Hardcoded secret in Rust source"
				}
				out = append(out, issue(path, "MCP806", title, severity, i+1, original[i],
					"Move credentials to an environment variable or secret store and rotate any exposed value."))
			}
		}
	}
	return out
}

// maskRustComments preserves offsets and newlines while removing line and
// nested block comments. String literals are skipped so comment markers inside
// them remain untouched.
func maskRustComments(src string) string { return rustMask(src, false) }

// maskRustCode additionally blanks string and character literals so delimiters
// or sink-like examples inside literals cannot be mistaken for executable code.
func maskRustCode(src string) string { return rustMask(src, true) }

func rustMask(src string, maskStrings bool) string {
	b := []byte(src)
	mask := func(start, end int) {
		for j := start; j < end && j < len(b); j++ {
			if b[j] != '\n' {
				b[j] = ' '
			}
		}
	}
	for i := 0; i < len(b); {
		if b[i] == '/' && i+1 < len(b) && b[i+1] == '/' {
			start := i
			i += 2
			for i < len(b) && b[i] != '\n' {
				i++
			}
			mask(start, i)
			continue
		}
		if b[i] == '/' && i+1 < len(b) && b[i+1] == '*' {
			start, depth := i, 1
			i += 2
			for i < len(b) && depth > 0 {
				if i+1 < len(b) && b[i] == '/' && b[i+1] == '*' {
					depth++
					i += 2
				} else if i+1 < len(b) && b[i] == '*' && b[i+1] == '/' {
					depth--
					i += 2
				} else {
					i++
				}
			}
			mask(start, i)
			continue
		}
		// Raw strings use r###"..."### and byte raw strings use br###"..."###.
		rawStart := i
		prefix := i
		if b[prefix] == 'b' && prefix+1 < len(b) && b[prefix+1] == 'r' {
			prefix++
		}
		if b[prefix] == 'r' {
			q := prefix + 1
			for q < len(b) && b[q] == '#' {
				q++
			}
			if q < len(b) && b[q] == '"' {
				hashes := q - prefix - 1
				end := q + 1
				for end < len(b) {
					if b[end] == '"' {
						x := end + 1
						for n := 0; n < hashes && x < len(b) && b[x] == '#'; n++ {
							x++
						}
						if x-end == hashes+1 {
							end = x
							break
						}
					}
					end++
				}
				if maskStrings {
					mask(rawStart, end)
				}
				i = end
				continue
			}
		}
		quote := i
		if b[i] == 'b' && i+1 < len(b) && (b[i+1] == '"' || b[i+1] == '\'') {
			quote++
		}
		if b[quote] == '"' {
			start := i
			i = quote + 1
			for i < len(b) {
				if b[i] == '\\' {
					i += 2
				} else if b[i] == '"' {
					i++
					break
				} else {
					i++
				}
			}
			if maskStrings {
				mask(start, i)
			}
			continue
		}
		if b[quote] == '\'' {
			start := i
			j := quote + 1
			for j < len(b) && b[j] != '\n' {
				if b[j] == '\\' {
					j += 2
					continue
				}
				if b[j] == '\'' {
					i = j + 1
					if maskStrings {
						mask(start, i)
					}
					break
				}
				j++
			}
			if i == start {
				i++ // Rust lifetime, such as 'a or 'static.
			}
			continue
		}
		i++
	}
	return string(b)
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
