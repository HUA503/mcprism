package sast

import (
	"regexp"
	"strings"
)

// Kotlin support starts from the official Kotlin SDK's server.addTool { ... }
// callback. This bounded lexical pass does not compile Kotlin or resolve
// extension functions, overloads, or cross-file dispatch.
type kotlinToolHandler struct {
	request   string
	body      string
	startLine int
}

var (
	kotlinAddToolRe      = regexp.MustCompile(`\.\s*addTool\s*\(`)
	kotlinLambdaParamRe  = regexp.MustCompile(`(?:\(\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\)?\s*->`)
	kotlinAssignmentRe   = regexp.MustCompile(`(?m)\b(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=\n]+)?\s*=\s*([^\n;]+)`)
	kotlinKtorImportRe   = regexp.MustCompile(`(?m)^\s*import\s+io\.ktor\.client\.request\.(get|post|put|delete|request)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*$`)
	kotlinProcessSinkRe  = regexp.MustCompile(`(?:ProcessBuilder|Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec)\s*\(`)
	kotlinNetworkSinkRe  = regexp.MustCompile(`(?:URL|URI)\s*\(|URI\s*\.\s*create\s*\(|HttpRequest\s*\.\s*newBuilder\s*\(|\b[A-Za-z_][\w]*\s*\.\s*(?:getForObject|getForEntity|exchange|execute|GetAsync|PostAsync|PutAsync|SendAsync|GetStringAsync)\s*\(`)
	kotlinFileSinkRe     = regexp.MustCompile(`(?:File\s*\(|Path\s*\.\s*of\s*\(|Paths\s*\.\s*get\s*\(|Files\s*\.\s*(?:readString|readAllBytes|newInputStream|newOutputStream|write|delete)\s*\()`)
	kotlinEvalSinkRe     = regexp.MustCompile(`(?:ScriptEngine\s*\.\s*eval|\b[A-Za-z_][\w]*\s*\.\s*eval)\s*\(`)
	kotlinClassLoadRe    = regexp.MustCompile(`Class\s*\.\s*forName\s*\(`)
	kotlinDeserialSinkRe = regexp.MustCompile(`(?:ObjectInputStream|\b[A-Za-z_][\w]*\s*\.\s*readObject)\s*\(`)
)

func analyzeKotlin(path string) []Issue {
	lines, src := readLines(path)
	if src == "" {
		return nil
	}
	code := maskJavaComments(src)
	ktorCalls := kotlinKtorRequestCalls(code)
	var out []Issue
	for _, handler := range extractKotlinToolHandlers(src, code) {
		out = append(out, scanKotlinHandler(path, lines, handler, ktorCalls)...)
	}
	for _, line := range maskedLines(lines, maskJavaComments) {
		out = append(out, lineSecretIssues(path, line)...)
	}
	return dedupIssues(out)
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
			request: params[1], body: src[innerStart:bodyEnd], startLine: startLine,
		})
	}
	return handlers
}

func scanKotlinHandler(path string, sourceLines []srcLine, handler kotlinToolHandler, ktorCalls []string) []Issue {
	body := maskJavaComments(handler.body)
	tainted := map[string]bool{}
	source := regexp.MustCompile(`\b` + regexp.QuoteMeta(handler.request) + `\s*\.\s*arguments\b`)
	exprIsTainted := func(expr string) bool {
		if source.MatchString(expr) {
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
	return out
}
