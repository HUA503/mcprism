package sast

import (
	"regexp"
	"strings"
	"unicode"
)

func analyzeJS(path string) []Issue {
	lines, src := readLines(path)
	if src == "" {
		return nil
	}
	var out []Issue
	functions := extractJSFunctions(src)
	staticMaps := jsStaticMapNames(src)
	for _, b := range extractJSHandlers(maskJSComments(src)) {
		out = append(out, scanReachableJS(path, b, functions, staticMaps)...)
	}
	for _, l := range maskedLines(lines, maskJSComments) {
		out = append(out, lineSecretIssues(path, l)...)
	}
	return dedupIssues(out)
}

// ---------- handler extraction ----------

var jsHandlerRe = regexp.MustCompile(`(?:\.tool|setRequestHandler|registerTool)\s*\(`)

func extractJSHandlers(src string) []handlerBlock {
	var blocks []handlerBlock
	structure := maskJSCode(src)
	for _, m := range jsHandlerRe.FindAllStringIndex(structure, -1) {
		openParen := m[1] - 1
		closeParen := matchClose(src, openParen, '(', ')')
		if closeParen < 0 {
			continue
		}
		argText := src[openParen+1 : closeParen]
		body, params := jsHandlerBody(src, openParen, closeParen)
		if body == nil {
			continue
		}
		name := firstString(argText)
		if name == "" {
			name = "tool"
		}
		blocks = append(blocks, handlerBlock{name: name, params: params, lines: body})
	}
	return blocks
}

func jsHandlerBody(src string, from, to int) ([]srcLine, []string) {
	seg := src[from:to]
	if ai := strings.Index(seg, "=>"); ai >= 0 {
		params := jsArrowParams(seg[:ai])
		bo := indexByteFrom(src, from+ai+2, '{', to)
		if bo < 0 {
			return nil, nil
		}
		bc := matchClose(src, bo, '{', '}')
		if bc < 0 {
			return nil, nil
		}
		return linesRange(src, bo, bc), params
	}
	if fi := strings.Index(seg, "function"); fi >= 0 {
		po := indexByteFrom(src, from+fi, '(', to)
		if po < 0 {
			return nil, nil
		}
		pc := matchClose(src, po, '(', ')')
		params := jsParamList(src[po+1 : pc])
		bo := indexByteFrom(src, pc, '{', to)
		bc := matchClose(src, bo, '{', '}')
		return linesRange(src, bo, bc), params
	}
	return nil, nil
}

func jsArrowParams(before string) []string {
	before = strings.TrimSpace(before)
	if i := strings.LastIndex(before, "("); i >= 0 {
		if close := matchClose(before, i, '(', ')'); close >= 0 {
			return jsParamList(before[i+1 : close])
		}
	}
	return jsParamList(before)
}

func jsParamList(s string) []string {
	var out []string
	for _, p := range splitCallArgs(s) {
		p = strings.TrimSpace(p)
		p = strings.TrimPrefix(p, "async ")
		if strings.HasPrefix(p, "{") {
			close := matchClose(p, 0, '{', '}')
			if close < 0 {
				continue
			}
			for _, f := range splitCallArgs(p[1:close]) {
				f = strings.TrimSpace(f)
				if eq := strings.Index(f, "="); eq >= 0 {
					f = strings.TrimSpace(f[:eq])
				}
				if colon := strings.Index(f, ":"); colon >= 0 {
					f = strings.TrimSpace(f[colon+1:])
				}
				if f != "" {
					out = append(out, f)
				}
			}
			continue
		}
		if eq := strings.Index(p, "="); eq >= 0 {
			p = strings.TrimSpace(p[:eq])
		}
		if ci := strings.Index(p, ":"); ci >= 0 {
			p = strings.TrimSpace(p[:ci])
		}
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// extractJSFunctions indexes unambiguous same-file function declarations and
// block-bodied arrow helpers. Duplicate names are omitted to avoid following an
// ambiguous call into an unrelated function.
func extractJSFunctions(src string) map[string]handlerBlock {
	functions := map[string]handlerBlock{}
	ambiguous := map[string]bool{}
	add := func(name string, params []string, start, end int) {
		if name == "" || start < 0 || end < start || ambiguous[name] {
			return
		}
		if _, exists := functions[name]; exists {
			delete(functions, name)
			ambiguous[name] = true
			return
		}
		functions[name] = handlerBlock{name: name, params: params, lines: linesRange(src, start, end)}
	}

	masked := maskJSComments(src)
	structure := maskJSCode(src)
	declRe := regexp.MustCompile(`\bfunction\s+([A-Za-z_$][\w$]*)\s*\(`)
	for _, m := range declRe.FindAllStringSubmatchIndex(structure, -1) {
		open := m[1] - 1
		close := matchClose(masked, open, '(', ')')
		if close < 0 {
			continue
		}
		bodyOpen := indexByteFrom(masked, close+1, '{', len(masked))
		if bodyOpen < 0 {
			continue
		}
		bodyClose := matchClose(masked, bodyOpen, '{', '}')
		if bodyClose < 0 {
			continue
		}
		add(masked[m[2]:m[3]], jsParamList(masked[open+1:close]), bodyOpen+1, bodyClose)
	}

	// Parse const/let/var arrow helpers without trying to parse TypeScript's full
	// type grammar. Only identifier-named, block-bodied functions are indexed.
	arrowHead := regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=`)
	for _, m := range arrowHead.FindAllStringSubmatchIndex(structure, -1) {
		name := masked[m[2]:m[3]]
		pos := m[1]
		for pos < len(masked) && (masked[pos] == ' ' || masked[pos] == '\t' || masked[pos] == '\r' || masked[pos] == '\n') {
			pos++
		}
		if strings.HasPrefix(masked[pos:], "async") && (pos+5 == len(masked) || !isJSIdentByte(masked[pos+5])) {
			pos += 5
			for pos < len(masked) && (masked[pos] == ' ' || masked[pos] == '\t' || masked[pos] == '\r' || masked[pos] == '\n') {
				pos++
			}
		}
		var params []string
		var arrow int
		if pos < len(masked) && masked[pos] == '(' {
			close := matchClose(masked, pos, '(', ')')
			if close < 0 {
				continue
			}
			params = jsParamList(masked[pos+1 : close])
			arrow = close + 1
		} else {
			start := pos
			for pos < len(masked) && isJSIdentByte(masked[pos]) {
				pos++
			}
			if pos == start {
				continue
			}
			params = []string{masked[start:pos]}
			arrow = pos
		}
		for arrow < len(masked) && (masked[arrow] == ' ' || masked[arrow] == '\t' || masked[arrow] == '\r' || masked[arrow] == '\n') {
			arrow++
		}
		if !strings.HasPrefix(masked[arrow:], "=>") {
			continue
		}
		bodyOpen := arrow + 2
		for bodyOpen < len(masked) && (masked[bodyOpen] == ' ' || masked[bodyOpen] == '\t' || masked[bodyOpen] == '\r' || masked[bodyOpen] == '\n') {
			bodyOpen++
		}
		if bodyOpen >= len(masked) || masked[bodyOpen] != '{' {
			continue
		}
		bodyClose := matchClose(masked, bodyOpen, '{', '}')
		if bodyClose < 0 {
			continue
		}
		add(name, params, bodyOpen+1, bodyClose)
	}
	return functions
}

func isJSIdentByte(b byte) bool {
	return b == '_' || b == '$' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

func scanReachableJS(path string, entry handlerBlock, functions map[string]handlerBlock, staticMaps map[string]string) []Issue {
	taintedByName := map[string]map[string]bool{}
	processedByName := map[string]map[string]bool{}
	queue := []handlerBlock{entry}
	var out []Issue
	callRe := regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*\(`)
	for head := 0; head < len(queue); head++ {
		block := queue[head]
		seed := jsTaintedNames(block.lines, block.params, staticMaps)
		known := taintedByName[block.name]
		if known == nil {
			known = map[string]bool{}
			taintedByName[block.name] = known
		}
		for _, name := range seed {
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
		out = append(out, scanJSBlock(path, block)...)

		text := maskJSComments(joinLines(block.lines))
		structure := maskJSCode(text)
		ctrl := jsTaintedNames(block.lines, params, staticMaps)
		for _, call := range callRe.FindAllStringSubmatchIndex(structure, -1) {
			name := structure[call[2]:call[3]]
			helper, ok := functions[name]
			if !ok || call[0] > 0 && structure[call[0]-1] == '.' {
				continue
			}
			open := call[1] - 1
			close := matchClose(text, open, '(', ')')
			if close < 0 {
				continue
			}
			args := splitCallArgs(text[open+1 : close])
			for i, arg := range args {
				if i >= len(helper.params) || helper.params[i] == "" || !jsExprControllable(arg, ctrl) {
					continue
				}
				if taintedByName[name] == nil {
					taintedByName[name] = map[string]bool{}
				}
				param := helper.params[i]
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

func jsTaintedNames(lines []srcLine, seeds []string, staticMaps map[string]string) []string {
	set := map[string]bool{}
	for _, name := range seeds {
		if isJSIdent(name) {
			set[name] = true
		}
	}
	assign := regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^=;\n][^;\n]*)|\b([A-Za-z_$][\w$]*)\s*=\s*([^=;\n][^;\n]*)`)
	for changed := true; changed; {
		changed = false
		for _, line := range lines {
			text := maskJSComments(line.text)
			structure := maskJSCode(text)
			for _, m := range assign.FindAllStringSubmatchIndex(structure, -1) {
				lhs, rhs := "", ""
				if m[2] >= 0 {
					lhs, rhs = structure[m[2]:m[3]], text[m[4]:m[5]]
				} else if m[6] >= 0 {
					lhs, rhs = structure[m[6]:m[7]], text[m[8]:m[9]]
				}
				if isJSIdent(lhs) && !set[lhs] && !jsStaticMapLookup(rhs, staticMaps, mapKeys(set)) && jsExprControllable(rhs, mapKeys(set)) {
					set[lhs] = true
					changed = true
				}
			}
		}
	}
	return mapKeys(set)
}

func jsStaticMapNames(src string) map[string]string {
	structure := maskJSCode(src)
	mapStart := regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\{`)
	names := map[string]string{}
	for _, m := range mapStart.FindAllStringSubmatchIndex(structure, -1) {
		open := m[1] - 1
		close := matchClose(structure, open, '{', '}')
		if close >= 0 {
			names[structure[m[2]:m[3]]] = structure[open+1 : close]
		}
	}
	return names
}

func jsStaticMapLookup(expr string, staticMaps map[string]string, tainted []string) bool {
	m := regexp.MustCompile(`^\s*([A-Za-z_$][\w$]*)\s*\[[^\]]+\]\s*$`).FindStringSubmatch(maskJSCode(expr))
	if m == nil {
		return false
	}
	body, ok := staticMaps[m[1]]
	return ok && !jsControllable(body, tainted)
}

func mapKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	return keys
}

// ---------- sink scanning ----------

func scanJSBlock(path string, b handlerBlock) []Issue {
	var out []Issue
	text := maskJSComments(joinLines(b.lines))
	structure := maskJSCode(text)
	baseLine := b.lines[0].num
	off2line := func(off int) int { return baseLine + strings.Count(text[:off], "\n") }

	// 1. process execution
	cmdRe := regexp.MustCompile(`\b(exec|execSync|execFile|spawn|spawnSync)\s*\(`)
	for _, m := range cmdRe.FindAllStringIndex(structure, -1) {
		open := m[1] - 1
		close := matchClose(text, open, '(', ')')
		if close < 0 {
			continue
		}
		arg := text[open+1 : close]
		line := off2line(open)
		code := lineText(b, line)
		name := sinkName(text[m[0]:m[1]])
		firstArg, rest := splitTopComma(arg)
		switch {
		case jsExprControllable(firstArg, b.params):
			out = append(out, issue(path, "MCP801", "Tool argument used as the command to run", SeverityCritical, line, code,
				"Don't let agent input choose the command. Use a fixed allow-list of commands and pass arguments as an array without a shell."))
		case (name == "exec" || name == "execSync") && jsExprControllable(arg, b.params):
			out = append(out, issue(path, "MCP801", "Tool argument passed to a shell command", SeverityCritical, line, code,
				"Avoid running a shell over agent input. Use execFile or spawn with a fixed command and an argument array, or validate against an allow-list."))
		case jsExprControllable(rest, b.params) && (name == "spawn" || name == "execFile" || name == "spawnSync"):
			out = append(out, issue(path, "MCP801", "Tool argument passed to a spawned process", SeverityMedium, line, code,
				"Validate arguments against an allow-list. A fixed command with unvalidated args can still allow argument injection."))
		}
	}

	// 2. dynamic code execution
	dynRe := regexp.MustCompile(`\b(eval|Function)\s*\(`)
	for _, m := range dynRe.FindAllStringIndex(structure, -1) {
		open := m[1] - 1
		close := matchClose(text, open, '(', ')')
		arg := text[open+1 : close]
		line := off2line(open)
		code := lineText(b, line)
		sev, title := SeverityHigh, "Dynamic code execution"
		if jsExprControllable(arg, b.params) {
			sev, title = SeverityCritical, "Tool argument passed to dynamic code execution"
		}
		out = append(out, issue(path, "MCP804", title, sev, line, code,
			"Remove eval/Function. If code has to run, isolate it and never feed it agent-controlled input."))
	}

	// 3. outbound network (SSRF)
	netRe := regexp.MustCompile(`\b(fetch|got|request|axios\.(get|post|put)|https?\.get)\s*\(`)
	for _, m := range netRe.FindAllStringIndex(structure, -1) {
		open := m[1] - 1
		close := matchClose(text, open, '(', ')')
		arg := text[open+1 : close]
		firstArg, _ := splitTopComma(arg)
		line := off2line(open)
		code := lineText(b, line)
		if jsExprControllable(firstArg, b.params) && !isConstURLArg(firstArg) {
			out = append(out, issue(path, "MCP802", "Tool argument controls a request URL (SSRF)", SeverityHigh, line, code,
				"Do not let agent input choose the host. Allow-list hosts or pin a constant base URL, and block metadata and private ranges."))
		}
	}

	// 4. filesystem paths
	// A path is confined only when the exact variable that reaches a file sink
	// is tested with .startsWith. An unrelated resolve/startsWith elsewhere in
	// the handler does not silence the finding.
	guarded := jsGuardedVars(structure)
	fileRe := regexp.MustCompile(`\b(readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync|createReadStream|createWriteStream)\s*\(`)
	for _, m := range fileRe.FindAllStringIndex(structure, -1) {
		open := m[1] - 1
		close := matchClose(text, open, '(', ')')
		arg := text[open+1 : close]
		firstArg, _ := splitTopComma(arg)
		line := off2line(open)
		code := lineText(b, line)
		if isJSPathConfined(firstArg, guarded) || !jsExprControllable(firstArg, b.params) {
			continue
		}
		out = append(out, issue(path, "MCP803", "Tool argument used as a file path", SeverityHigh, line, code,
			"Resolve the path, confirm it stays inside one base directory with startsWith, and reject traversal sequences. resolve/normalize alone is not a boundary check."))
	}

	// 5. dynamic require
	reqRe := regexp.MustCompile(`\brequire\s*\(`)
	for _, m := range reqRe.FindAllStringIndex(structure, -1) {
		open := m[1] - 1
		close := matchClose(text, open, '(', ')')
		arg := text[open+1 : close]
		line := off2line(open)
		code := lineText(b, line)
		if !strings.ContainsAny(arg, "'\"`") && jsExprControllable(arg, b.params) {
			out = append(out, issue(path, "MCP807", "Dynamic module require with tool input", SeverityMedium, line, code,
				"Do not require modules named by agent input. Map requests to a fixed set of modules."))
		}
	}
	return out
}

func jsControllable(expr string, params []string) bool {
	for _, p := range params {
		if p != "" && containsWord(expr, p) {
			return true
		}
	}
	for _, g := range []string{"arguments", "request.params", "params.arguments"} {
		if strings.Contains(expr, g) {
			return true
		}
	}
	return false
}

// jsExprControllable ignores identifiers that appear only inside string
// literals while preserving data-flow checks inside template interpolations.
func jsExprControllable(expr string, params []string) bool {
	if jsControllable(maskJSCode(expr), params) {
		return true
	}
	for i := 0; i < len(expr); {
		if expr[i] == '\'' || expr[i] == '"' {
			quote := expr[i]
			i++
			for i < len(expr) {
				if expr[i] == '\\' {
					i += 2
				} else if expr[i] == quote {
					i++
					break
				} else {
					i++
				}
			}
			continue
		}
		if expr[i] != '`' {
			i++
			continue
		}
		i++
		for i < len(expr) {
			if expr[i] == '\\' {
				i += 2
				continue
			}
			if expr[i] == '`' {
				i++
				break
			}
			if expr[i] == '$' && i+1 < len(expr) && expr[i+1] == '{' {
				open := i + 1
				close := matchClose(expr, open, '{', '}')
				if close < 0 {
					break
				}
				if jsExprControllable(expr[open+1:close], params) {
					return true
				}
				i = close + 1
				continue
			}
			i++
		}
	}
	return false
}

// isConstURLArg reports whether expr is a single quoted string literal holding
// an http(s) URL. A literal used in concatenation ("https://" + host), a
// template literal with interpolation, or any variable is not constant.
func isConstURLArg(expr string) bool {
	e := strings.TrimSpace(expr)
	if len(e) < 2 {
		return false
	}
	q := e[0]
	if q != '\'' && q != '"' && q != '`' {
		return false
	}
	if e[len(e)-1] != q {
		return false // something follows the literal, e.g. "https://" + host
	}
	body := e[1 : len(e)-1]
	if q == '`' && strings.Contains(body, "${") {
		return false // template interpolation
	}
	if strings.Contains(body, string(q)) {
		return false // not one contiguous literal
	}
	return strings.HasPrefix(body, "http://") || strings.HasPrefix(body, "https://")
}

// jsGuardedVars collects variables tested with .startsWith(...) anywhere in the
// handler. Only those exact variables are treated as confined.
func jsGuardedVars(text string) map[string]bool {
	set := map[string]bool{}
	re := regexp.MustCompile(`([A-Za-z_$][\w$]*)\.startsWith\s*\(`)
	for _, m := range re.FindAllStringSubmatch(text, -1) {
		set[m[1]] = true
	}
	return set
}

// isJSPathConfined reports whether the sink argument is the exact variable that
// a .startsWith guard protects.
func isJSPathConfined(first string, guarded map[string]bool) bool {
	first = strings.TrimSpace(first)
	if !isJSIdent(first) {
		return false
	}
	return guarded[first]
}

func isJSIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if r != '_' && r != '$' && !unicode.IsLetter(r) {
				return false
			}
		} else if r != '_' && r != '$' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// ---------- shared block/lexer helpers ----------

type handlerBlock struct {
	name   string
	params []string
	lines  []srcLine
}

// matchClose returns the index of the closing character for the opener at
// openIdx, tracking strings, template literals and comments.
func matchClose(src string, openIdx int, open, close byte) int {
	depth := 0
	state := byte('c')
	i := openIdx
	for i < len(src) {
		c := src[i]
		switch state {
		case 'c':
			if c == '/' && i+1 < len(src) {
				if src[i+1] == '/' {
					state = 'l'
					i += 2
					continue
				}
				if src[i+1] == '*' {
					state = 'b'
					i += 2
					continue
				}
			}
			switch c {
			case '\'':
				state = 's'
			case '"':
				state = 'd'
			case '`':
				state = 't'
			case open:
				depth++
			case close:
				depth--
				if depth == 0 {
					return i
				}
			}
			i++
		case 'l':
			if c == '\n' {
				state = 'c'
			}
			i++
		case 'b':
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				state = 'c'
				i += 2
				continue
			}
			i++
		case 's':
			if c == '\\' {
				i += 2
				continue
			}
			if c == '\'' {
				state = 'c'
			}
			i++
		case 'd':
			if c == '\\' {
				i += 2
				continue
			}
			if c == '"' {
				state = 'c'
			}
			i++
		case 't':
			if c == '\\' {
				i += 2
				continue
			}
			if c == '`' {
				state = 'c'
				i++
				continue
			}
			if c == '$' && i+1 < len(src) && src[i+1] == '{' {
				cl := matchClose(src, i+1, '{', '}')
				if cl < 0 {
					return -1
				}
				i = cl + 1
				continue
			}
			i++
		}
	}
	return -1
}

func indexByteFrom(src string, from int, b byte, to int) int {
	for i := from; i < to && i < len(src); i++ {
		if src[i] == b {
			return i
		}
	}
	return -1
}

func linesRange(src string, bo, bc int) []srcLine {
	startLine := strings.Count(src[:bo], "\n") + 1
	parts := strings.Split(src[bo:bc], "\n")
	out := make([]srcLine, len(parts))
	for i, p := range parts {
		out[i] = srcLine{num: startLine + i, text: p}
	}
	return out
}

func firstString(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' || s[i] == '"' || s[i] == '`' {
			q := s[i]
			j := i + 1
			for j < len(s) && s[j] != q {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			return s[i+1 : j]
		}
	}
	return ""
}

func joinLines(ls []srcLine) string {
	parts := make([]string, len(ls))
	for i, l := range ls {
		parts[i] = l.text
	}
	return strings.Join(parts, "\n")
}

func lineText(b handlerBlock, line int) string {
	for _, l := range b.lines {
		if l.num == line {
			return trimCode(l.text)
		}
	}
	return ""
}

func sinkName(m string) string {
	m = strings.TrimRight(m, " (")
	if i := strings.LastIndexAny(m, "."); i >= 0 {
		m = m[i+1:]
	}
	return m
}

func splitTopComma(arg string) (string, string) {
	depth := 0
	var quote byte
	for i := 0; i < len(arg); i++ {
		c := arg[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				return strings.TrimSpace(arg[:i]), strings.TrimSpace(arg[i+1:])
			}
		}
	}
	return strings.TrimSpace(arg), ""
}

func issue(path, id, title string, sev Severity, line int, code, advice string) Issue {
	return Issue{RuleID: id, Title: title, Severity: sev, File: path, Line: line, Code: code, Advice: advice}
}
