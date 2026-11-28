package sast

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// javaHandler is a callback registered through the official Java SDK's
// callHandler/toolCall APIs. The current analyzer intentionally supports
// explicit lambda bodies rather than attempting to resolve Spring wiring.
type javaHandler struct {
	path          string
	owner         string
	body          string
	requestName   string
	startLine     int
	name          string
	depth         int
	seededTaint   map[string]bool
	receiverTypes map[string]string
}

type javaFunction struct {
	path          string
	owner         string
	name          string
	params        []string
	body          string
	startLine     int
	tool          bool
	toolTaint     map[string]bool
	receiverTypes map[string]string
}

const (
	maxJavaProjectFiles = 64
	maxJavaProjectBytes = 16 << 20
)

type javaFileIndex struct {
	code      string
	lines     []string
	functions map[string]javaFunction
}

type javaProjectIndex struct {
	files   map[string]javaFileIndex
	methods map[string]javaFunction
	ambig   map[string]bool
}

var javaTypeDeclRe = regexp.MustCompile(`\b(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)[^;{}]*\{`)

var (
	javaToolCallbackRe = regexp.MustCompile(`\.(callHandler|toolCall)\s*\(`)
	javaLambdaArgsRe   = regexp.MustCompile(`(?:\(([^()]*)\)|([A-Za-z_$][\w$]*))\s*$`)
	javaIdentifierRe   = regexp.MustCompile(`[A-Za-z_$][\w$]*`)
	javaFunctionRe     = regexp.MustCompile(`(?m)(?:^|[;{}])\s*(?:(?:public|protected|private|static|final|synchronized|native|abstract|default)\s+)*[\w.$<>, ?\[\]]+\s+([A-Za-z_$][\w$]*)\s*\(([^()]*)\)\s*(?:throws\s+[\w.$, ]+)?\s*\{`)
	javaMcpToolRe      = regexp.MustCompile(`@(?:[A-Za-z_$][\w$]*\.)*McpTool\b`)
	javaCallRe         = regexp.MustCompile(`(?:\b([A-Za-z_$][\w$]*)\s*\.\s*)?\b([A-Za-z_$][\w$]*)\s*\(`)
	javaAssignRe       = regexp.MustCompile(`(?:^|[;{}\n])\s*(?:final\s+)?[\w.$<>?, \t\[\]]*?\b([A-Za-z_$][\w$]*)\s*=\s*([^;{}]+);`)
	javaProcessSinkRe  = regexp.MustCompile(`(?:new\s+ProcessBuilder|Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec)\s*\(`)
	javaNetworkSinkRe  = regexp.MustCompile(`(?:new\s+URL|URI\s*\.\s*create|HttpRequest\s*\.\s*newBuilder|(?:restTemplate|httpClient|webClient|client)\s*\.\s*(?:getForObject|getForEntity|exchange|execute))\s*\(`)
	javaFileSinkRe     = regexp.MustCompile(`(?:new\s+File|Path\s*\.\s*of|Paths\s*\.\s*get|Files\s*\.\s*(?:readString|readAllBytes|newInputStream|newOutputStream|write|delete))\s*\(`)
	javaEvalSinkRe     = regexp.MustCompile(`\.\s*eval\s*\(`)
	javaClassLoadRe    = regexp.MustCompile(`Class\s*\.\s*forName\s*\(`)
	javaDeserialSinkRe = regexp.MustCompile(`new\s+ObjectInputStream\s*\(`)
)

func analyzeJava(path string) []Issue {
	return analyzeJavaWithIndex(path, nil)
}

func buildJavaProjectIndex(paths []string) *javaProjectIndex {
	idx := &javaProjectIndex{files: map[string]javaFileIndex{}, methods: map[string]javaFunction{}, ambig: map[string]bool{}}
	files, bytes := 0, int64(0)
	for _, path := range paths {
		if !strings.EqualFold(filepath.Ext(path), ".java") || files >= maxJavaProjectFiles {
			continue
		}
		info, err := os.Stat(path)
		if err != nil || info.Size() > maxSourceFileSize || bytes+info.Size() > maxJavaProjectBytes {
			continue
		}
		_, src := readLines(path)
		if src == "" {
			continue
		}
		code := maskJavaComments(src)
		functions := extractJavaFunctions(code)
		for name, fn := range functions {
			fn.path = path
			functions[name] = fn
			if fn.owner == "" {
				continue
			}
			key := fn.owner + "#" + fn.name
			if _, ok := idx.methods[key]; ok {
				delete(idx.methods, key)
				idx.ambig[key] = true
			} else if !idx.ambig[key] {
				idx.methods[key] = fn
			}
		}
		idx.files[path] = javaFileIndex{code: code, lines: strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n"), functions: functions}
		files++
		bytes += int64(len(src))
	}
	return idx
}

func analyzeJavaWithIndex(path string, index *javaProjectIndex) []Issue {
	lines, src := readLines(path)
	if src == "" {
		return nil
	}
	code := maskJavaComments(src)
	allLines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	var issues []Issue
	functions := extractJavaFunctions(code)
	if index != nil {
		if file, ok := index.files[path]; ok {
			code, allLines, functions = file.code, file.lines, file.functions
		}
	}
	for name, fn := range functions {
		if fn.path == "" {
			fn.path = path
			functions[name] = fn
		}
	}
	queue := extractJavaHandlers(code)
	for i := range queue {
		queue[i].path = path
	}
	for _, function := range functions {
		if function.tool {
			queue = append(queue, javaHandler{
				path: path, owner: function.owner,
				body: function.body, startLine: function.startLine, name: function.name,
				seededTaint: function.toolTaint, receiverTypes: function.receiverTypes,
			})
		}
	}
	seen := map[string]bool{}
	for head := 0; head < len(queue); head++ {
		handler := queue[head]
		key := javaTaintKey(handler.name, handler.seededTaint)
		if seen[key] {
			continue
		}
		seen[key] = true
		handlerPath := handler.path
		if handlerPath == "" {
			handlerPath = path
		}
		fileLines, fileFunctions := allLines, functions
		if index != nil {
			if file, ok := index.files[handlerPath]; ok {
				fileLines, fileFunctions = file.lines, file.functions
			}
		}
		found, helpers := scanJavaHandler(handlerPath, fileLines, handler, fileFunctions, index)
		issues = append(issues, found...)
		queue = append(queue, helpers...)
	}
	for _, line := range maskedGoLines(lines) {
		issues = append(issues, goLineSecretIssues(path, line)...)
	}
	return dedupIssues(issues)
}

func extractJavaFunctions(code string) map[string]javaFunction {
	functions := map[string]javaFunction{}
	counts := map[string]int{}
	ambiguous := map[string]bool{}
	parseCode := maskJavaAnnotations(code)
	typeRanges := javaTypeRanges(parseCode)
	for _, match := range javaFunctionRe.FindAllStringSubmatchIndex(parseCode, -1) {
		name := parseCode[match[2]:match[3]]
		paramsText := parseCode[match[4]:match[5]]
		brace := strings.LastIndexByte(parseCode[match[0]:match[1]], '{') + match[0]
		close := matchClose(parseCode, brace, '{', '}')
		if close < 0 {
			continue
		}
		params := javaParameterNames(paramsText)
		receiverTypes := javaParameterTypes(paramsText)
		owner := ""
		for _, classRange := range typeRanges {
			if brace >= classRange.start && brace < classRange.end {
				owner = classRange.name
				break
			}
		}
		toolTaint := map[string]bool{}
		isTool := javaMcpToolRe.MatchString(code[match[0]:match[1]])
		if isTool {
			for _, paramText := range splitJavaTopLevel(paramsText) {
				if javaToolContextParam(paramText) {
					continue
				}
				ids := javaIdentifierRe.FindAllString(paramText, -1)
				if len(ids) != 0 {
					toolTaint[ids[len(ids)-1]] = true
				}
			}
		}
		counts[name]++
		if counts[name] > 1 {
			delete(functions, name)
			ambiguous[name] = true
			continue
		}
		if !ambiguous[name] {
			functions[name] = javaFunction{
				name: name, owner: owner, params: params, body: code[brace+1 : close], tool: isTool, toolTaint: toolTaint, receiverTypes: receiverTypes,
				startLine: strings.Count(code[:brace+1], "\n") + 1,
			}
		}
	}
	return functions
}

func javaParameterTypes(text string) map[string]string {
	types := map[string]string{}
	for _, param := range splitJavaTopLevel(text) {
		ids := javaIdentifierRe.FindAllStringIndex(param, -1)
		if len(ids) < 2 {
			continue
		}
		name := param[ids[len(ids)-1][0]:ids[len(ids)-1][1]]
		typ := strings.TrimSpace(param[:ids[len(ids)-1][0]])
		if strings.Contains(typ, " ") {
			typ = strings.Fields(typ)[len(strings.Fields(typ))-1]
		}
		if strings.HasPrefix(typ, "final") {
			typ = strings.TrimSpace(strings.TrimPrefix(typ, "final"))
		}
		if i := strings.IndexAny(typ, "<["); i >= 0 {
			typ = typ[:i]
		}
		if i := strings.LastIndex(typ, "."); i >= 0 {
			typ = typ[i+1:]
		}
		if typ != "" {
			types[name] = typ
		}
	}
	return types
}

type javaTypeRange struct {
	name       string
	start, end int
}

func javaTypeRanges(code string) []javaTypeRange {
	var ranges []javaTypeRange
	for _, match := range javaTypeDeclRe.FindAllStringSubmatchIndex(code, -1) {
		brace := strings.LastIndexByte(code[match[0]:match[1]], '{') + match[0]
		close := matchClose(code, brace, '{', '}')
		if close >= 0 {
			ranges = append(ranges, javaTypeRange{name: code[match[2]:match[3]], start: brace, end: close})
		}
	}
	return ranges
}

func javaToolContextParam(param string) bool {
	for _, marker := range []string{"McpSyncServerExchange", "McpAsyncServerExchange", "McpTransportContext", "McpSyncRequestContext", "McpAsyncRequestContext", "McpMeta"} {
		if strings.Contains(param, marker) {
			return true
		}
	}
	return false
}

func maskJavaAnnotations(src string) string {
	b := []byte(src)
	mask := func(start, end int) {
		for i := start; i < end && i < len(b); i++ {
			if b[i] != '\n' && b[i] != '\r' {
				b[i] = ' '
			}
		}
	}
	for i := 0; i < len(b); {
		if b[i] != '@' || i+1 >= len(b) || !isJavaIdentStart(b[i+1]) {
			i++
			continue
		}
		start := i
		i += 2
		for i < len(b) {
			if isJavaIdentContinue(b[i]) || b[i] == '.' {
				i++
				continue
			}
			break
		}
		for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' || b[i] == '\n') {
			i++
		}
		if i < len(b) && b[i] == '(' {
			if close := matchClose(string(b), i, '(', ')'); close >= 0 {
				i = close + 1
			}
		}
		mask(start, i)
	}
	return string(b)
}

func isJavaIdentStart(b byte) bool {
	return b == '_' || b == '$' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func isJavaIdentContinue(b byte) bool {
	return isJavaIdentStart(b) || b >= '0' && b <= '9'
}

func javaParameterNames(text string) []string {
	var names []string
	for _, param := range splitJavaTopLevel(text) {
		ids := javaIdentifierRe.FindAllString(param, -1)
		if len(ids) != 0 {
			names = append(names, ids[len(ids)-1])
		}
	}
	return names
}

func splitJavaTopLevel(text string) []string {
	var out []string
	start, parens, brackets, angles := 0, 0, 0, 0
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '(':
			parens++
		case ')':
			parens--
		case '[':
			brackets++
		case ']':
			brackets--
		case '<':
			angles++
		case '>':
			if angles > 0 {
				angles--
			}
		case ',':
			if parens == 0 && brackets == 0 && angles == 0 {
				out = append(out, strings.TrimSpace(text[start:i]))
				start = i + 1
			}
		}
	}
	if tail := strings.TrimSpace(text[start:]); tail != "" {
		out = append(out, tail)
	}
	return out
}

func maskJavaComments(src string) string {
	b := []byte(src)
	mask := func(start, end int) {
		for i := start; i < end && i < len(b); i++ {
			if b[i] != '\n' && b[i] != '\r' {
				b[i] = ' '
			}
		}
	}
	for i := 0; i < len(b); {
		if b[i] == '\'' || b[i] == '"' {
			quote := b[i]
			if quote == '"' && i+2 < len(b) && b[i+1] == '"' && b[i+2] == '"' {
				start := i
				i += 3
				for i+2 < len(b) {
					if b[i] == '\\' {
						i += 2
						continue
					}
					if b[i] == '"' && b[i+1] == '"' && b[i+2] == '"' {
						i += 3
						break
					}
					i++
				}
				mask(start, i)
				continue
			}
			start := i
			i++
			for i < len(b) {
				if b[i] == '\\' {
					i += 2
					continue
				}
				if b[i] == quote {
					i++
					break
				}
				i++
			}
			mask(start, i)
			continue
		}
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
			start := i
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			if i+1 < len(b) {
				i += 2
			}
			mask(start, i)
			continue
		}
		i++
	}
	return string(b)
}

func extractJavaHandlers(code string) []javaHandler {
	var handlers []javaHandler
	typeRanges := javaTypeRanges(maskJavaAnnotations(code))
	for _, match := range javaToolCallbackRe.FindAllStringIndex(code, -1) {
		open := strings.LastIndexByte(code[match[0]:match[1]], '(')
		if open < 0 {
			continue
		}
		open += match[0]
		close := matchClose(code, open, '(', ')')
		if close < 0 {
			continue
		}
		call := code[open+1 : close]
		arrow := strings.Index(call, "->")
		if arrow < 0 {
			continue
		}
		params := javaLambdaArgsRe.FindStringSubmatch(strings.TrimSpace(call[:arrow]))
		if params == nil {
			continue
		}
		paramList := params[1]
		if paramList == "" {
			paramList = params[2]
		}
		parts := splitCallArgs(strings.TrimSpace(paramList))
		if len(parts) == 0 {
			continue
		}
		ids := javaIdentifierRe.FindAllString(parts[len(parts)-1], -1)
		if len(ids) == 0 {
			continue
		}
		bodyStart := open + 1 + arrow + 2
		for bodyStart < close && (code[bodyStart] == ' ' || code[bodyStart] == '\t' || code[bodyStart] == '\r' || code[bodyStart] == '\n') {
			bodyStart++
		}
		if bodyStart >= close || code[bodyStart] != '{' {
			continue
		}
		bodyEnd := matchClose(code, bodyStart, '{', '}')
		if bodyEnd < 0 || bodyEnd > close {
			continue
		}
		handlers = append(handlers, javaHandler{
			body: code[bodyStart+1 : bodyEnd], requestName: ids[len(ids)-1], owner: javaOwnerAt(typeRanges, bodyStart),
			startLine: strings.Count(code[:bodyStart+1], "\n") + 1,
			name:      fmt.Sprintf("<callback:%d>", strings.Count(code[:bodyStart+1], "\n")+1),
		})
	}
	return handlers
}

func javaOwnerAt(ranges []javaTypeRange, pos int) string {
	for _, r := range ranges {
		if pos >= r.start && pos < r.end {
			return r.name
		}
	}
	return ""
}

func javaReceiverType(body, receiver string) string {
	if receiver == "this" {
		return ""
	}
	if receiver != "" && receiver[0] >= 'A' && receiver[0] <= 'Z' {
		return receiver
	}
	if receiver == "" {
		return ""
	}
	re := regexp.MustCompile(`\b([A-Za-z_$][\w.$]*(?:\s*<[^;{}]+>)?(?:\s*\[\])?)\s+` + regexp.QuoteMeta(receiver) + `\b`)
	matches := re.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return ""
	}
	typ := strings.TrimSpace(matches[0][1])
	if len(matches) > 1 {
		for _, match := range matches[1:] {
			if strings.TrimSpace(match[1]) != typ {
				return ""
			}
		}
	}
	if i := strings.IndexAny(typ, "<["); i >= 0 {
		typ = typ[:i]
	}
	if i := strings.LastIndex(typ, "."); i >= 0 {
		typ = typ[i+1:]
	}
	return typ
}

func scanJavaHandler(path string, sourceLines []string, handler javaHandler, functions map[string]javaFunction, index *javaProjectIndex) ([]Issue, []javaHandler) {
	body := handler.body
	tainted := map[string]bool{}
	for name := range handler.seededTaint {
		tainted[name] = true
	}
	requestArgsRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(handler.requestName) + `\s*\.\s*arguments\s*\(\s*\)`)
	requestValueRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(handler.requestName) + `\s*\.\s*arguments\s*\(\s*\)\s*\.\s*get(?:OrDefault)?\s*\(`)
	exprIsTainted := func(expr string) bool {
		if handler.requestName != "" && (requestValueRe.MatchString(expr) || requestArgsRe.MatchString(expr)) {
			return true
		}
		for name := range tainted {
			if regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`).MatchString(expr) {
				return true
			}
		}
		return false
	}
	for changed := true; changed; {
		changed = false
		for _, m := range javaAssignRe.FindAllStringSubmatch(body, -1) {
			name, expr := m[1], m[2]
			if strings.HasPrefix(strings.TrimSpace(expr), "=") {
				continue
			}
			if tainted[name] || !exprIsTainted(expr) {
				continue
			}
			tainted[name] = true
			changed = true
		}
	}
	var out []Issue
	var helpers []javaHandler
	addSink := func(pattern *regexp.Regexp, ruleID, title string, severity Severity, advice string) {
		for _, match := range pattern.FindAllStringIndex(body, -1) {
			open := strings.LastIndexByte(body[match[0]:match[1]], '(')
			if open < 0 {
				continue
			}
			open += match[0]
			close := matchClose(body, open, '(', ')')
			if close < 0 || !exprIsTainted(body[open+1:close]) {
				continue
			}
			line := handler.startLine + strings.Count(body[:match[0]], "\n")
			codeLine := ""
			if line > 0 && line <= len(sourceLines) {
				codeLine = trimCode(sourceLines[line-1])
			}
			out = append(out, Issue{RuleID: ruleID, Title: title, Severity: severity, File: path, Line: line, Code: codeLine, Advice: advice})
		}
	}
	if handler.depth < 8 {
		for _, call := range javaCallRe.FindAllStringSubmatchIndex(body, -1) {
			receiver, name := "", body[call[4]:call[5]]
			if call[2] >= 0 {
				receiver = body[call[2]:call[3]]
			}
			var function javaFunction
			ok := false
			switch receiver {
			case "":
				function, ok = functions[name]
			case "this":
				function, ok = functions[name]
				if ok && handler.owner != "" && function.owner != handler.owner {
					ok = false
				}
			default:
				typ := javaReceiverType(body, receiver)
				if typ == "" {
					typ = handler.receiverTypes[receiver]
				}
				if typ == "" && receiver == handler.owner {
					typ = receiver
				}
				key := typ + "#" + name
				if index != nil && typ != "" && !index.ambig[key] {
					function, ok = index.methods[key]
				}
			}
			if !ok {
				continue
			}
			open := strings.LastIndexByte(body[call[0]:call[1]], '(') + call[0]
			close := matchClose(body, open, '(', ')')
			if close < 0 {
				continue
			}
			args := splitJavaTopLevel(body[open+1 : close])
			if len(args) != len(function.params) {
				continue
			}
			seeded := map[string]bool{}
			for i, arg := range args {
				if exprIsTainted(arg) {
					seeded[function.params[i]] = true
				}
			}
			if len(seeded) == 0 {
				continue
			}
			helpers = append(helpers, javaHandler{
				path: function.path, owner: function.owner, body: function.body, startLine: function.startLine, name: function.owner + "." + function.name,
				depth: handler.depth + 1, seededTaint: seeded, receiverTypes: function.receiverTypes,
			})
		}
	}
	addSink(javaProcessSinkRe, "MCP801", "Agent-controlled input reaches Java process execution", SeverityCritical,
		"Do not pass tool arguments to ProcessBuilder or Runtime.exec. Use a fixed executable and validate each argument against an allow-list.")
	addSink(javaNetworkSinkRe, "MCP802", "Agent-controlled input controls a Java request target", SeverityHigh,
		"Use a fixed destination or allow-list approved hosts, and reject private and link-local addresses after URL parsing.")
	addSink(javaFileSinkRe, "MCP803", "Agent-controlled input reaches a Java filesystem path", SeverityHigh,
		"Resolve the path against a fixed base directory and verify the normalized path remains inside that directory.")
	addSink(javaEvalSinkRe, "MCP804", "Agent-controlled input reaches Java script evaluation", SeverityHigh,
		"Do not evaluate tool arguments as script source.")
	addSink(javaDeserialSinkRe, "MCP805", "Agent-controlled input reaches Java object deserialization", SeverityHigh,
		"Do not deserialize attacker-controlled bytes with ObjectInputStream. Use a safe data format and validate its schema.")
	addSink(javaClassLoadRe, "MCP807", "Agent-controlled input selects a Java class", SeverityMedium,
		"Use an allow-list of supported class names instead of loading a class selected by tool input.")
	return out, helpers
}

func javaTaintKey(name string, tainted map[string]bool) string {
	var b strings.Builder
	b.WriteString(name)
	params := make([]string, 0, len(tainted))
	for param := range tainted {
		params = append(params, param)
	}
	sort.Strings(params)
	for _, param := range params {
		b.WriteByte(':')
		b.WriteString(param)
	}
	return b.String()
}
