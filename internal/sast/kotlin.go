package sast

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Kotlin support starts from the official Kotlin SDK's server.addTool { ... }
// callback. This bounded lexical pass does not compile Kotlin or resolve
// overloads, extension-function receiver types, or member dispatch across files.
type kotlinToolHandler struct {
	path      string
	request   string
	name      string
	body      string
	startLine int
	depth     int
	seeded    map[string]bool
}

type kotlinFunction struct {
	path        string
	packageName string
	name        string
	params      []string
	body        string
	startLine   int
	topLevel    bool
	private     bool
	extension   bool
}

const (
	maxKotlinProjectFiles = 64
	maxKotlinProjectBytes = 16 << 20
)

type kotlinFileIndex struct {
	lines     []srcLine
	functions map[string]kotlinFunction
	imports   map[string]string
	ktorCalls []string
}

type kotlinProjectIndex struct {
	files     map[string]kotlinFileIndex
	functions map[string]kotlinFunction
	ambiguous map[string]bool
}

type kotlinFunctionMatch struct {
	indices    []int
	topLevel   bool
	expression bool
}

var (
	kotlinAddToolRe            = regexp.MustCompile(`\.\s*addTool\s*\(`)
	kotlinLambdaParamRe        = regexp.MustCompile(`(?:\(\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\)?\s*->`)
	kotlinFunctionRe           = regexp.MustCompile(`(?m)\bfun\s+(?:<[^>]+>\s*)?(?:[A-Za-z_][\w.]*\s*\.\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(([^()]*)\)\s*(?::[^={\n]+)?\s*\{`)
	kotlinExpressionFunctionRe = regexp.MustCompile(`(?m)\bfun\s+(?:<[^>]+>\s*)?(?:[A-Za-z_][\w.]*\s*\.\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(([^()]*)\)\s*(?::[^=\n]+)?\s*=\s*([^\n;]+)`)
	kotlinPackageRe            = regexp.MustCompile(`(?m)^\s*package\s+([A-Za-z_][\w.]*)`)
	kotlinImportRe             = regexp.MustCompile(`(?m)^\s*import\s+([A-Za-z_][\w.]*)\s*(?:as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*$`)
	kotlinCallRe               = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	kotlinAssignmentRe         = regexp.MustCompile(`(?m)\b(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=\n]+)?\s*=\s*([^\n;]+)`)
	kotlinKtorImportRe         = regexp.MustCompile(`(?m)^\s*import\s+io\.ktor\.client\.request\.(get|post|put|delete|request)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*$`)
	kotlinProcessSinkRe        = regexp.MustCompile(`(?:ProcessBuilder|Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec)\s*\(`)
	kotlinNetworkSinkRe        = regexp.MustCompile(`(?:URL|URI)\s*\(|URI\s*\.\s*create\s*\(|HttpRequest\s*\.\s*newBuilder\s*\(|\b[A-Za-z_][\w]*\s*\.\s*(?:getForObject|getForEntity|exchange|execute|GetAsync|PostAsync|PutAsync|SendAsync|GetStringAsync)\s*\(`)
	kotlinFileSinkRe           = regexp.MustCompile(`(?:File\s*\(|Path\s*\.\s*of\s*\(|Paths\s*\.\s*get\s*\(|Files\s*\.\s*(?:readString|readAllBytes|newInputStream|newOutputStream|write|delete)\s*\()`)
	kotlinEvalSinkRe           = regexp.MustCompile(`(?:ScriptEngine\s*\.\s*eval|\b[A-Za-z_][\w]*\s*\.\s*eval)\s*\(`)
	kotlinClassLoadRe          = regexp.MustCompile(`Class\s*\.\s*forName\s*\(`)
	kotlinDeserialSinkRe       = regexp.MustCompile(`(?:ObjectInputStream|\b[A-Za-z_][\w]*\s*\.\s*readObject)\s*\(`)
)

func analyzeKotlin(path string) []Issue {
	return analyzeKotlinWithIndex(path, nil)
}

func buildKotlinProjectIndex(paths []string) *kotlinProjectIndex {
	idx := &kotlinProjectIndex{files: map[string]kotlinFileIndex{}, functions: map[string]kotlinFunction{}, ambiguous: map[string]bool{}}
	files, bytes := 0, int64(0)
	for _, path := range paths {
		if (!strings.EqualFold(filepath.Ext(path), ".kt") && !strings.EqualFold(filepath.Ext(path), ".kts")) || files >= maxKotlinProjectFiles {
			continue
		}
		info, err := os.Stat(path)
		if err != nil || info.Size() > maxSourceFileSize || bytes+info.Size() > maxKotlinProjectBytes {
			continue
		}
		lines, src := readLines(path)
		if src == "" {
			continue
		}
		code := maskJavaComments(src)
		packageName := kotlinPackageName(code)
		functions := extractKotlinFunctions(src, code)
		for name, count := range kotlinTopLevelFunctionCounts(code) {
			key := packageName + "." + name
			if count > 1 && packageName != "" {
				delete(idx.functions, key)
				idx.ambiguous[key] = true
			}
		}
		for name, fn := range functions {
			fn.path, fn.packageName = path, packageName
			functions[name] = fn
			if !fn.topLevel || fn.private || fn.extension || packageName == "" {
				continue
			}
			key := packageName + "." + name
			if idx.ambiguous[key] {
				continue
			}
			if _, exists := idx.functions[key]; exists {
				delete(idx.functions, key)
				idx.ambiguous[key] = true
			} else if !idx.ambiguous[key] {
				idx.functions[key] = fn
			}
		}
		idx.files[path] = kotlinFileIndex{
			lines: lines, functions: functions,
			imports: kotlinFunctionImports(code), ktorCalls: kotlinKtorRequestCalls(code),
		}
		files++
		bytes += int64(len(src))
	}
	return idx
}

func analyzeKotlinWithIndex(path string, index *kotlinProjectIndex) []Issue {
	lines, src := readLines(path)
	if src == "" {
		return nil
	}
	code := maskJavaComments(src)
	ktorCalls := kotlinKtorRequestCalls(code)
	functions := extractKotlinFunctions(src, code)
	queue := extractKotlinToolHandlers(src, code)
	imports := kotlinFunctionImports(code)
	if index != nil {
		if file, ok := index.files[path]; ok {
			functions, lines, imports = file.functions, file.lines, file.imports
		}
	}
	var out []Issue
	seen := map[string]bool{}
	for head := 0; head < len(queue); head++ {
		handler := queue[head]
		handlerPath := handler.path
		if handlerPath == "" {
			handlerPath = path
		}
		handlerFunctions, handlerLines, handlerImports := functions, lines, imports
		handlerKtorCalls := ktorCalls
		if index != nil {
			if file, ok := index.files[handlerPath]; ok {
				handlerFunctions, handlerLines, handlerImports = file.functions, file.lines, file.imports
				handlerKtorCalls = file.ktorCalls
			}
		}
		key := handlerPath + "::" + javaTaintKey(handler.name, handler.seeded)
		if seen[key] {
			continue
		}
		seen[key] = true
		issues, helpers := scanKotlinHandler(handlerPath, handlerLines, handler, handlerFunctions, handlerImports, index, handlerKtorCalls)
		out = append(out, issues...)
		queue = append(queue, helpers...)
	}
	for _, line := range maskedLines(lines, maskJavaComments) {
		out = append(out, lineSecretIssues(path, line)...)
	}
	return dedupIssues(out)
}

func kotlinPackageName(code string) string {
	if match := kotlinPackageRe.FindStringSubmatch(code); match != nil {
		return match[1]
	}
	return ""
}

func kotlinFunctionImports(code string) map[string]string {
	imports := map[string]string{}
	ambiguous := map[string]bool{}
	for _, match := range kotlinImportRe.FindAllStringSubmatch(code, -1) {
		qualified := match[1]
		lastDot := strings.LastIndexByte(qualified, '.')
		if lastDot < 0 {
			continue
		}
		alias := match[2]
		if alias == "" {
			alias = qualified[lastDot+1:]
		}
		if prior, exists := imports[alias]; exists && prior != qualified {
			delete(imports, alias)
			ambiguous[alias] = true
		} else if !ambiguous[alias] {
			imports[alias] = qualified
		}
	}
	return imports
}

func extractKotlinFunctions(src, code string) map[string]kotlinFunction {
	functions := map[string]kotlinFunction{}
	counts := map[string]int{}
	ambiguous := map[string]bool{}
	for _, declaration := range kotlinFunctionMatches(code) {
		match := declaration.indices
		name := code[match[2]:match[3]]
		var body string
		var startLine int
		if declaration.expression {
			body = src[match[6]:match[7]]
			startLine = strings.Count(src[:match[6]], "\n") + 1
		} else {
			open := strings.LastIndexByte(code[match[0]:match[1]], '{') + match[0]
			close := matchClose(code, open, '{', '}')
			if close < 0 {
				continue
			}
			body = src[open+1 : close]
			startLine = strings.Count(src[:open+1], "\n") + 1
		}
		paramsText := code[match[4]:match[5]]
		counts[name]++
		if counts[name] > 1 {
			delete(functions, name)
			ambiguous[name] = true
			continue
		}
		if !ambiguous[name] {
			lineStart := strings.LastIndex(code[:match[0]], "\n") + 1
			prefix := code[lineStart:match[0]]
			functions[name] = kotlinFunction{
				name: name, params: kotlinParameterNames(paramsText), body: body,
				startLine: startLine,
				topLevel:  declaration.topLevel,
				private:   regexp.MustCompile(`\bprivate\b`).MatchString(prefix),
				extension: strings.Contains(code[match[0]:match[2]], "."),
			}
		}
	}
	return functions
}

func kotlinTopLevelFunctionCounts(code string) map[string]int {
	counts := map[string]int{}
	for _, declaration := range kotlinFunctionMatches(code) {
		match := declaration.indices
		if declaration.topLevel {
			if strings.Contains(code[match[0]:match[2]], ".") {
				continue
			}
			lineStart := strings.LastIndex(code[:match[0]], "\n") + 1
			if regexp.MustCompile(`\bprivate\b`).MatchString(code[lineStart:match[0]]) {
				continue
			}
			counts[code[match[2]:match[3]]]++
		}
	}
	return counts
}

func kotlinFunctionMatches(code string) []kotlinFunctionMatch {
	var declarations []kotlinFunctionMatch
	for _, indices := range kotlinFunctionRe.FindAllStringSubmatchIndex(code, -1) {
		declarations = append(declarations, kotlinFunctionMatch{indices: indices})
	}
	for _, indices := range kotlinExpressionFunctionRe.FindAllStringSubmatchIndex(code, -1) {
		declarations = append(declarations, kotlinFunctionMatch{indices: indices, expression: true})
	}
	sort.Slice(declarations, func(i, j int) bool {
		return declarations[i].indices[0] < declarations[j].indices[0]
	})
	depth, cursor := 0, 0
	for i := range declarations {
		match := declarations[i].indices
		for cursor < match[0] {
			switch code[cursor] {
			case '{':
				depth++
			case '}':
				depth--
			}
			cursor++
		}
		declarations[i].topLevel = depth == 0
	}
	return declarations
}

func kotlinParameterNames(text string) []string {
	var names []string
	for _, param := range splitJavaTopLevel(text) {
		declaration := param
		if colon := strings.IndexByte(declaration, ':'); colon >= 0 {
			declaration = declaration[:colon]
		}
		ids := javaIdentifierRe.FindAllString(declaration, -1)
		if len(ids) != 0 {
			names = append(names, ids[len(ids)-1])
		}
	}
	return names
}

func kotlinKtorRequestCalls(code string) []string {
	var calls []string
	for _, match := range kotlinKtorImportRe.FindAllStringSubmatch(code, -1) {
		name := match[2]
		if name == "" {
			name = match[1]
		}
		calls = append(calls, name)
	}
	return calls
}

func extractKotlinToolHandlers(src, code string) []kotlinToolHandler {
	var handlers []kotlinToolHandler
	for _, call := range kotlinAddToolRe.FindAllStringIndex(code, -1) {
		open := strings.LastIndexByte(code[call[0]:call[1]], '(') + call[0]
		close := matchClose(code, open, '(', ')')
		if close < 0 {
			continue
		}
		bodyStart := close + 1
		for bodyStart < len(code) && (code[bodyStart] == ' ' || code[bodyStart] == '\t' || code[bodyStart] == '\r' || code[bodyStart] == '\n') {
			bodyStart++
		}
		if bodyStart >= len(code) || code[bodyStart] != '{' {
			continue
		}
		bodyEnd := matchClose(code, bodyStart, '{', '}')
		if bodyEnd < 0 {
			continue
		}
		lambda := code[bodyStart+1 : bodyEnd]
		arrow := strings.Index(lambda, "->")
		if arrow < 0 {
			continue
		}
		params := kotlinLambdaParamRe.FindStringSubmatch(strings.TrimSpace(lambda[:arrow+2]))
		if params == nil {
			continue
		}
		innerStart := bodyStart + 1 + arrow + 2
		startLine := strings.Count(src[:innerStart], "\n") + 1
		handlers = append(handlers, kotlinToolHandler{
			request: params[1], name: "tool@" + strconv.Itoa(startLine) + "#" + strconv.Itoa(len(handlers)),
			body: src[innerStart:bodyEnd], startLine: startLine,
		})
	}
	return handlers
}

func scanKotlinHandler(path string, sourceLines []srcLine, handler kotlinToolHandler, functions map[string]kotlinFunction, imports map[string]string, index *kotlinProjectIndex, ktorCalls []string) ([]Issue, []kotlinToolHandler) {
	body := maskJavaComments(handler.body)
	tainted := map[string]bool{}
	for name := range handler.seeded {
		tainted[name] = true
	}
	var source *regexp.Regexp
	if handler.request != "" {
		source = regexp.MustCompile(`\b` + regexp.QuoteMeta(handler.request) + `\s*\.\s*arguments\b`)
	}
	exprIsTainted := func(expr string) bool {
		if source != nil && source.MatchString(expr) {
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
		for _, match := range kotlinAssignmentRe.FindAllStringSubmatch(body, -1) {
			if !tainted[match[1]] && exprIsTainted(match[2]) {
				tainted[match[1]] = true
				changed = true
			}
		}
	}
	var out []Issue
	var helpers []kotlinToolHandler
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
			code := ""
			if line > 0 && line <= len(sourceLines) {
				code = trimCode(sourceLines[line-1].text)
			}
			out = append(out, Issue{RuleID: ruleID, Title: title, Severity: severity, File: path, Line: line, Code: code, Advice: advice})
		}
	}
	if handler.depth < 8 {
		for _, call := range kotlinCallRe.FindAllStringSubmatchIndex(body, -1) {
			name := body[call[2]:call[3]]
			function, ok := functions[name]
			if ok && function.extension {
				continue
			}
			if !ok && index != nil {
				if qualified, imported := imports[name]; imported && !index.ambiguous[qualified] {
					function, ok = index.functions[qualified]
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
			if len(seeded) != 0 {
				functionPath := function.path
				if functionPath == "" {
					functionPath = path
				}
				helpers = append(helpers, kotlinToolHandler{
					path: functionPath, name: function.name, body: function.body, startLine: function.startLine,
					depth: handler.depth + 1, seeded: seeded,
				})
			}
		}
	}
	addSink(kotlinProcessSinkRe, "MCP801", "Agent-controlled input reaches Kotlin process execution", SeverityCritical,
		"Do not pass tool arguments to ProcessBuilder or Runtime.exec. Use a fixed executable and validate each argument against an allow-list.")
	networkSink := kotlinNetworkSinkRe
	if len(ktorCalls) != 0 {
		quoted := make([]string, 0, len(ktorCalls))
		for _, name := range ktorCalls {
			quoted = append(quoted, regexp.QuoteMeta(name))
		}
		ktor := `\b[A-Za-z_][\w]*\s*\.\s*(?:` + strings.Join(quoted, "|") + `)\s*\(`
		networkSink = regexp.MustCompile(`(?:` + kotlinNetworkSinkRe.String() + `|` + ktor + `)`)
	}
	addSink(networkSink, "MCP802", "Agent-controlled input controls a Kotlin request target", SeverityHigh,
		"Use a fixed destination or allow-list approved hosts, and reject private and link-local addresses after URL parsing.")
	addSink(kotlinFileSinkRe, "MCP803", "Agent-controlled input reaches a Kotlin filesystem path", SeverityHigh,
		"Resolve the path against a fixed base directory and verify the normalized path remains inside that directory.")
	addSink(kotlinEvalSinkRe, "MCP804", "Agent-controlled input reaches Kotlin script evaluation", SeverityHigh,
		"Do not evaluate tool arguments as script source.")
	addSink(kotlinDeserialSinkRe, "MCP805", "Agent-controlled input reaches Kotlin object deserialization", SeverityHigh,
		"Do not deserialize attacker-controlled bytes. Use a safe data format and validate its schema.")
	addSink(kotlinClassLoadRe, "MCP807", "Agent-controlled input selects a Kotlin class", SeverityMedium,
		"Use an allow-list of supported class names instead of loading a class selected by tool input.")
	return out, helpers
}
