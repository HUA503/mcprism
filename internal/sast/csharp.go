package sast

import (
	"regexp"
	"strings"
)

// The C# analyzer starts from the official SDK's attribute-based registration
// pattern. It is deliberately a bounded lexical pass: it does not run dotnet,
// load assemblies, or resolve arbitrary dependency-injection and reflection.
type csharpFunction struct {
	name      string
	params    []string
	body      string
	startLine int
	tool      bool
	toolTaint map[string]bool
}

type csharpHandler struct {
	body        string
	startLine   int
	name        string
	depth       int
	seededTaint map[string]bool
}

type csharpTypeRange struct {
	name       string
	start, end int
	toolType   bool
}

var (
	csharpTypeDeclRe     = regexp.MustCompile(`\bclass\s+([A-Za-z_][A-Za-z0-9_]*)[^;{}]*\{`)
	csharpMethodRe       = regexp.MustCompile(`(?m)(?:^|[;{}])\s*(?:\[[^\]]*\]\s*)*(?:(?:public|private|protected|internal|static|async|virtual|override|sealed|partial|new|unsafe|extern|readonly|ref|file)\s+)*(?:[A-Za-z_][\w.<>,?\[\] ]*?)\s+([A-Za-z_][\w]*)\s*\(([^()]*)\)\s*(?:where\s+[\w, :]+\s*)?\{`)
	csharpToolAttrRe     = regexp.MustCompile(`\[\s*(?:[A-Za-z_][\w.]*\.)?McpServerTool(?:Attribute)?\b`)
	csharpTypeAttrRe     = regexp.MustCompile(`\[\s*(?:[A-Za-z_][\w.]*\.)?McpServerToolType(?:Attribute)?\b`)
	csharpCallRe         = regexp.MustCompile(`(?:\bthis\s*\.\s*)?\b([A-Za-z_][\w]*)\s*\(`)
	csharpAssignRe       = regexp.MustCompile(`(?:^|[;{}\n])\s*(?:(?:var|dynamic|readonly)\s+|[\w.<>,?\[\]]+\s+)?([A-Za-z_][\w]*)\s*=\s*([^;{}]+);`)
	csharpProcessRe      = regexp.MustCompile(`(?:Process\s*\.\s*Start|new\s+ProcessStartInfo)\s*\(`)
	csharpNetworkRe      = regexp.MustCompile(`(?:new\s+Uri|WebRequest\s*\.\s*Create|new\s+HttpRequestMessage|\b[A-Za-z_][\w]*\s*\.\s*(?:GetAsync|PostAsync|PutAsync|DeleteAsync|SendAsync|GetStringAsync|GetByteArrayAsync))\s*\(`)
	csharpFileRe         = regexp.MustCompile(`(?:File\s*\.\s*(?:Open\w*|Read\w*|Write\w*|Append\w*|Create\w*|Copy|Move|Delete)|Directory\s*\.\s*(?:Get\w*|Enumerate\w*|Create\w*|Move|Delete)|new\s+(?:FileStream|FileInfo|DirectoryInfo))\s*\(`)
	csharpEvalRe         = regexp.MustCompile(`CSharpScript\s*\.\s*(?:EvaluateAsync|RunAsync|Create)\s*\(`)
	csharpClassLoadRe    = regexp.MustCompile(`(?:Type\s*\.\s*GetType|Assembly\s*\.\s*Load(?:From)?)\s*\(`)
	csharpDeserialTypeRe = regexp.MustCompile(`(?:BinaryFormatter|LosFormatter|NetDataContractSerializer)`)
	csharpDeserialVarRe  = regexp.MustCompile(`(?:BinaryFormatter|LosFormatter|NetDataContractSerializer)\s+([A-Za-z_][\w]*)|var\s+([A-Za-z_][\w]*)\s*=\s*new\s+(?:BinaryFormatter|LosFormatter|NetDataContractSerializer)\b`)
)

func analyzeCSharp(path string) []Issue {
	lines, src := readLines(path)
	if src == "" {
		return nil
	}
	parseCode := maskCSharpLiterals(src)
	types := extractCSharpTypes(parseCode)
	functions := extractCSharpFunctions(src, parseCode, types)
	allLines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	var queue []csharpHandler
	for _, fn := range functions {
		if fn.tool {
			queue = append(queue, csharpHandler{body: fn.body, startLine: fn.startLine, name: fn.name, seededTaint: fn.toolTaint})
		}
	}
	seen := map[string]bool{}
	var issues []Issue
	for head := 0; head < len(queue); head++ {
		handler := queue[head]
		key := javaTaintKey(handler.name, handler.seededTaint)
		if seen[key] {
			continue
		}
		seen[key] = true
		found, helpers := scanCSharpHandler(path, allLines, handler, functions)
		issues = append(issues, found...)
		queue = append(queue, helpers...)
	}
	for _, line := range maskedGoLines(lines) {
		issues = append(issues, goLineSecretIssues(path, line)...)
	}
	return dedupIssues(issues)
}

func extractCSharpTypes(code string) []csharpTypeRange {
	var out []csharpTypeRange
	for _, match := range csharpTypeDeclRe.FindAllStringSubmatchIndex(code, -1) {
		brace := strings.LastIndexByte(code[match[0]:match[1]], '{') + match[0]
		close := matchClose(code, brace, '{', '}')
		if close < 0 {
			continue
		}
		segmentStart := strings.LastIndexAny(code[:match[0]], ";{}") + 1
		toolType := csharpTypeAttrRe.MatchString(code[segmentStart:match[0]])
		out = append(out, csharpTypeRange{name: code[match[2]:match[3]], start: brace, end: close, toolType: toolType})
	}
	return out
}

func extractCSharpFunctions(src, parseCode string, types []csharpTypeRange) map[string]csharpFunction {
	functions := map[string]csharpFunction{}
	counts := map[string]int{}
	ambiguous := map[string]bool{}
	for _, match := range csharpMethodRe.FindAllStringSubmatchIndex(parseCode, -1) {
		name := parseCode[match[2]:match[3]]
		paramsText := parseCode[match[4]:match[5]]
		brace := strings.LastIndexByte(parseCode[match[0]:match[1]], '{') + match[0]
		close := matchClose(parseCode, brace, '{', '}')
		if close < 0 {
			continue
		}
		ownerIsToolType := false
		for _, typ := range types {
			if brace >= typ.start && brace < typ.end && typ.toolType {
				ownerIsToolType = true
				break
			}
		}
		segmentStart := match[0]
		if segmentStart < len(parseCode) && strings.ContainsRune(";{}", rune(parseCode[segmentStart])) {
			segmentStart++
		}
		isTool := ownerIsToolType && csharpToolAttrRe.MatchString(parseCode[segmentStart:match[2]])
		params := javaParameterNames(paramsText)
		toolTaint := map[string]bool{}
		if isTool {
			for _, param := range splitJavaTopLevel(paramsText) {
				if csharpContextParam(param) {
					continue
				}
				ids := javaIdentifierRe.FindAllString(param, -1)
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
			functions[name] = csharpFunction{
				name: name, params: params, body: src[brace+1 : close],
				startLine: strings.Count(src[:brace+1], "\n") + 1,
				tool:      isTool, toolTaint: toolTaint,
			}
		}
	}
	return functions
}

func csharpContextParam(param string) bool {
	for _, marker := range []string{"CancellationToken", "IServiceProvider", "IMcpServer", "RequestContext", "McpServer", "FromServices", "FromKeyedServices"} {
		if strings.Contains(param, marker) {
			return true
		}
	}
	return false
}

func scanCSharpHandler(path string, sourceLines []string, handler csharpHandler, functions map[string]csharpFunction) ([]Issue, []csharpHandler) {
	body := maskCSharpComments(handler.body)
	tainted := map[string]bool{}
	for name := range handler.seededTaint {
		tainted[name] = true
	}
	exprIsTainted := func(expr string) bool {
		for name := range tainted {
			if regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`).MatchString(expr) {
				return true
			}
		}
		return false
	}
	for changed := true; changed; {
		changed = false
		for _, match := range csharpAssignRe.FindAllStringSubmatch(body, -1) {
			if !tainted[match[1]] && exprIsTainted(match[2]) {
				tainted[match[1]] = true
				changed = true
			}
		}
	}
	var issues []Issue
	var helpers []csharpHandler
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
				code = trimCode(sourceLines[line-1])
			}
			issues = append(issues, Issue{RuleID: ruleID, Title: title, Severity: severity, File: path, Line: line, Code: code, Advice: advice})
		}
	}
	if handler.depth < 8 {
		for _, call := range csharpCallRe.FindAllStringSubmatchIndex(body, -1) {
			name := body[call[2]:call[3]]
			function, ok := functions[name]
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
				helpers = append(helpers, csharpHandler{body: function.body, startLine: function.startLine, name: function.name, depth: handler.depth + 1, seededTaint: seeded})
			}
		}
	}
	addSink(csharpProcessRe, "MCP801", "Agent-controlled input reaches C# process execution", SeverityCritical,
		"Do not pass tool arguments to Process.Start or ProcessStartInfo. Use a fixed executable and validate each argument against an allow-list.")
	addSink(csharpNetworkRe, "MCP802", "Agent-controlled input controls a C# request target", SeverityHigh,
		"Use a fixed destination or allow-list approved hosts, and reject private and link-local addresses after URL parsing.")
	addSink(csharpFileRe, "MCP803", "Agent-controlled input reaches a C# filesystem path", SeverityHigh,
		"Resolve the path against a fixed base directory and verify the normalized path remains inside that directory.")
	addSink(csharpEvalRe, "MCP804", "Agent-controlled input reaches C# code loading or evaluation", SeverityHigh,
		"Do not compile, evaluate or load code selected by tool input. Use a fixed set of operations.")
	addSink(csharpDeserializerPattern(body), "MCP805", "Agent-controlled input reaches unsafe C# deserialization", SeverityHigh,
		"Do not deserialize attacker-controlled data with unsafe formatters. Use a safe data format and validate its schema.")
	addSink(csharpClassLoadRe, "MCP807", "Agent-controlled input selects a C# type", SeverityMedium,
		"Use an allow-list of supported type names instead of resolving a type selected by tool input.")
	return issues, helpers
}

func csharpDeserializerPattern(body string) *regexp.Regexp {
	var receivers []string
	for _, match := range csharpDeserialVarRe.FindAllStringSubmatch(body, -1) {
		name := match[1]
		if name == "" {
			name = match[2]
		}
		if name != "" {
			receivers = append(receivers, regexp.QuoteMeta(name))
		}
	}
	// Common names also catch a formatter created through a helper where the
	// declaration is not visible in the current method body.
	receivers = append(receivers, `formatter`, `deserializer`)
	return regexp.MustCompile(`(?:` + csharpDeserialTypeRe.String() + `|(?:new\s+)?(?:` + csharpDeserialTypeRe.String() + `)\s*\([^)]*\)|` + strings.Join(receivers, "|") + `)\s*\.\s*Deserialize\s*\(`)
}

// maskCSharpComments blanks comments while leaving strings intact for taint
// checks. String literals are masked separately when locating declarations so
// braces in interpolated or raw strings cannot corrupt block boundaries.
func maskCSharpComments(src string) string {
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
			i = csharpStringEnd(b, i)
			continue
		}
		if b[i] == '/' && i+1 < len(b) && b[i+1] == '/' {
			start := i
			i += 2
			for i < len(b) && b[i] != '\n' && b[i] != '\r' {
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

func maskCSharpLiterals(src string) string {
	b := []byte(maskCSharpComments(src))
	mask := func(start, end int) {
		for i := start; i < end && i < len(b); i++ {
			if b[i] != '\n' && b[i] != '\r' {
				b[i] = ' '
			}
		}
	}
	for i := 0; i < len(b); {
		if b[i] != '\'' && b[i] != '"' {
			i++
			continue
		}
		start := i
		end := csharpStringEnd(b, i)
		mask(start, end)
		i = end
	}
	return string(b)
}

func csharpStringEnd(b []byte, quote int) int {
	if b[quote] == '"' && quote+2 < len(b) && b[quote+1] == '"' && b[quote+2] == '"' {
		i := quote + 3
		for i+2 < len(b) {
			if b[i] == '"' && b[i+1] == '"' && b[i+2] == '"' {
				return i + 3
			}
			i++
		}
		return len(b)
	}
	verbatim := quote > 0 && b[quote-1] == '@'
	i := quote + 1
	for i < len(b) {
		if !verbatim && b[i] == '\\' {
			i += 2
			continue
		}
		if b[i] == b[quote] {
			if verbatim && i+1 < len(b) && b[i+1] == b[quote] {
				i += 2
				continue
			}
			return i + 1
		}
		i++
	}
	return len(b)
}
