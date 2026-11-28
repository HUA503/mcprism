package sast

import (
	"regexp"
	"strings"
)

// javaHandler is a callback registered through the official Java SDK's
// callHandler/toolCall APIs. The current analyzer intentionally supports
// explicit lambda bodies rather than attempting to resolve Spring wiring.
type javaHandler struct {
	body        string
	requestName string
	startLine   int
}

var (
	javaToolCallbackRe = regexp.MustCompile(`\.(callHandler|toolCall)\s*\(`)
	javaLambdaArgsRe   = regexp.MustCompile(`(?:\(([^()]*)\)|([A-Za-z_$][\w$]*))\s*$`)
	javaIdentifierRe   = regexp.MustCompile(`[A-Za-z_$][\w$]*`)
	javaAssignRe       = regexp.MustCompile(`(?:^|[;{}\n])\s*(?:final\s+)?[\w.$<>?, \t\[\]]*?\b([A-Za-z_$][\w$]*)\s*=\s*([^;{}]+);`)
	javaProcessSinkRe  = regexp.MustCompile(`(?:new\s+ProcessBuilder|Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec)\s*\(`)
	javaNetworkSinkRe  = regexp.MustCompile(`(?:new\s+URL|URI\s*\.\s*create|HttpRequest\s*\.\s*newBuilder|(?:restTemplate|httpClient|webClient|client)\s*\.\s*(?:getForObject|getForEntity|exchange|execute))\s*\(`)
	javaFileSinkRe     = regexp.MustCompile(`(?:new\s+File|Path\s*\.\s*of|Paths\s*\.\s*get|Files\s*\.\s*(?:readString|readAllBytes|newInputStream|newOutputStream|write|delete))\s*\(`)
	javaEvalSinkRe     = regexp.MustCompile(`\.\s*eval\s*\(`)
	javaClassLoadRe    = regexp.MustCompile(`Class\s*\.\s*forName\s*\(`)
	javaDeserialSinkRe = regexp.MustCompile(`new\s+ObjectInputStream\s*\(`)
)

func analyzeJava(path string) []Issue {
	lines, src := readLines(path)
	if src == "" {
		return nil
	}
	code := maskJavaComments(src)
	allLines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	var issues []Issue
	for _, handler := range extractJavaHandlers(code) {
		issues = append(issues, scanJavaHandler(path, allLines, handler)...)
	}
	for _, line := range maskedGoLines(lines) {
		issues = append(issues, goLineSecretIssues(path, line)...)
	}
	return dedupIssues(issues)
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
			body: code[bodyStart+1 : bodyEnd], requestName: ids[len(ids)-1],
			startLine: strings.Count(code[:bodyStart+1], "\n") + 1,
		})
	}
	return handlers
}

func scanJavaHandler(path string, sourceLines []string, handler javaHandler) []Issue {
	body := handler.body
	tainted := map[string]bool{}
	requestArgsRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(handler.requestName) + `\s*\.\s*arguments\s*\(\s*\)`)
	requestValueRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(handler.requestName) + `\s*\.\s*arguments\s*\(\s*\)\s*\.\s*get(?:OrDefault)?\s*\(`)
	exprIsTainted := func(expr string) bool {
		if requestValueRe.MatchString(expr) || requestArgsRe.MatchString(expr) {
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
	return out
}
