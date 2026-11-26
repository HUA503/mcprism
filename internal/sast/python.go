package sast

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	maxPythonModuleDepth = 8
	maxPythonModuleFiles = 64
	maxPythonModuleBytes = 16 << 20
)

type pythonFunctionScopes struct {
	functions  map[string]map[string]handlerBlock
	staticMaps map[string]map[string]bool
	bytes      int64
	files      int
}

func analyzePython(path string) []Issue {
	lines, src := readLines(path)
	if src == "" {
		return nil
	}
	var out []Issue
	rootBytes := int64(len(src))
	if info, err := os.Stat(path); err == nil {
		rootBytes = info.Size()
	}
	scopes := &pythonFunctionScopes{
		functions:  map[string]map[string]handlerBlock{},
		staticMaps: map[string]map[string]bool{},
		bytes:      rootBytes,
		files:      1,
	}
	buildPythonFunctionScope(path, lines, 0, scopes)
	for _, b := range extractPythonHandlers(lines) {
		b.path = path
		out = append(out, scanReachablePython(path, b, scopes)...)
	}
	for _, l := range maskedPythonLines(lines) {
		out = append(out, lineSecretIssues(path, l)...)
	}
	return dedupIssues(out)
}

// ---------- handler extraction ----------

var pyToolDecRe = regexp.MustCompile(`@[\w\.]+\.(tool|call_tool)\b`)
var pyDefRe = regexp.MustCompile(`\bdef\s+(\w+)\s*\(([^)]*)\)`)
var pyCallRe = regexp.MustCompile(`\b([A-Za-z_]\w*)\s*\(`)
var pyFromImportRe = regexp.MustCompile(`^from\s+(\.{0,1}[A-Za-z_]\w*)\s+import\s+(.+?)\s*$`)

func buildPythonFunctionScope(path string, lines []srcLine, depth int, scopes *pythonFunctionScopes) map[string]handlerBlock {
	key := filepath.Clean(path)
	if functions, ok := scopes.functions[key]; ok {
		return functions
	}
	functions := extractPythonFunctions(lines)
	for name, helper := range functions {
		helper.path = path
		functions[name] = helper
	}
	// Store the partial scope before recursion so circular imports terminate.
	scopes.functions[key] = functions
	scopes.staticMaps[key] = pyStaticMapNames(lines, nil)
	localNames := map[string]bool{}
	for _, line := range maskedPythonLines(lines) {
		if m := pyDefRe.FindStringSubmatch(line.text); m != nil {
			localNames[m[1]] = true
		}
	}
	if depth < maxPythonModuleDepth {
		mergePythonImportedFunctions(path, lines, functions, localNames, depth, scopes)
	}
	return functions
}

// mergePythonImportedFunctions resolves explicit imports from bounded,
// same-directory Python modules. Ambiguous aliases and star imports stay
// unresolved.
func mergePythonImportedFunctions(path string, lines []srcLine, functions map[string]handlerBlock, localNames map[string]bool, depth int, scopes *pythonFunctionScopes) {
	type importedHelper struct {
		block handlerBlock
		count int
	}
	candidates := map[string]importedHelper{}
	for _, line := range maskedPythonLines(lines) {
		m := pyFromImportRe.FindStringSubmatch(line.text)
		if m == nil {
			continue
		}
		modulePath := pythonLocalModulePath(path, m[1])
		if modulePath == "" {
			continue
		}
		moduleKey := filepath.Clean(modulePath)
		moduleFunctions, ok := scopes.functions[moduleKey]
		if !ok {
			if scopes.files >= maxPythonModuleFiles || depth >= maxPythonModuleDepth {
				continue
			}
			info, err := os.Lstat(modulePath)
			if err != nil || !info.Mode().IsRegular() || info.Size() > maxSourceFileSize ||
				scopes.bytes+info.Size() > maxPythonModuleBytes {
				continue
			}
			moduleLines, moduleSrc := readLines(modulePath)
			if moduleSrc == "" || scopes.bytes+int64(len(moduleSrc)) > maxPythonModuleBytes {
				continue
			}
			scopes.bytes += info.Size()
			scopes.files++
			moduleFunctions = buildPythonFunctionScope(modulePath, moduleLines, depth+1, scopes)
		}
		for _, item := range strings.Split(strings.Trim(strings.TrimSpace(m[2]), "()"), ",") {
			fields := strings.Fields(strings.TrimSpace(item))
			if len(fields) == 0 || fields[0] == "*" {
				continue
			}
			original, alias := fields[0], fields[0]
			if len(fields) == 3 && fields[1] == "as" {
				alias = fields[2]
			} else if len(fields) != 1 {
				continue
			}
			helper, exists := moduleFunctions[original]
			if !exists || localNames[alias] {
				continue
			}
			helper.name = alias
			candidate := candidates[alias]
			candidate.block = helper
			candidate.count++
			candidates[alias] = candidate
		}
	}
	for alias, candidate := range candidates {
		if candidate.count != 1 || localNames[alias] {
			continue
		}
		functions[alias] = candidate.block
	}
}

func pythonLocalModulePath(path, module string) string {
	name := strings.TrimPrefix(module, ".")
	if name == "" || strings.Contains(name, ".") || strings.ContainsAny(name, `/\\`) {
		return ""
	}
	candidate := filepath.Join(filepath.Dir(path), name+".py")
	info, err := os.Lstat(candidate)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxSourceFileSize {
		return ""
	}
	return candidate
}

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
	m := pyDefRe.FindStringSubmatch(line)
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

// extractPythonFunctions indexes unambiguous same-file function definitions.
// Ambiguous names (for example methods with the same short name) are omitted
// so a call cannot taint an unrelated body.
func extractPythonFunctions(lines []srcLine) map[string]handlerBlock {
	functions := map[string]handlerBlock{}
	ambiguous := map[string]bool{}
	for i, line := range lines {
		name, params, ok := parsePyDef(line.text)
		if !ok || ambiguous[name] {
			continue
		}
		body := pyBodyRange(lines, i, indentOf(line.text))
		if body == nil {
			continue
		}
		if _, exists := functions[name]; exists {
			delete(functions, name)
			ambiguous[name] = true
			continue
		}
		functions[name] = handlerBlock{name: name, params: params, lines: body}
	}
	return functions
}

// scanReachablePython follows tainted positional/keyword arguments through
// unambiguous same-file helpers and explicitly imported, same-directory
// modules. Each helper is scanned only for parameters reached from tool input.
func scanReachablePython(path string, entry handlerBlock, scopes *pythonFunctionScopes) []Issue {
	taintedByName := map[string]map[string]bool{}
	processedByName := map[string]map[string]bool{}
	queue := []handlerBlock{entry}
	var out []Issue
	for head := 0; head < len(queue); head++ {
		block := queue[head]
		blockPath := block.path
		if blockPath == "" {
			blockPath = path
		}
		moduleKey := filepath.Clean(blockPath)
		functions := scopes.functions[moduleKey]
		staticMaps := scopes.staticMaps[moduleKey]
		seed := pyTaintedNames(block.lines, block.params, staticMaps)
		stateKey := moduleKey + "::" + block.name
		known := taintedByName[stateKey]
		if known == nil {
			known = map[string]bool{}
			taintedByName[stateKey] = known
		}
		for _, name := range seed {
			known[name] = true
		}
		processed := processedByName[stateKey]
		if processed == nil {
			processed = map[string]bool{}
			processedByName[stateKey] = processed
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
		issuePath := block.path
		if issuePath == "" {
			issuePath = path
		}
		out = append(out, scanPythonBlock(issuePath, block)...)

		text := maskPythonComments(joinLines(block.lines))
		for _, call := range pyCallRe.FindAllStringSubmatchIndex(text, -1) {
			name := text[call[2]:call[3]]
			helper, ok := functions[name]
			if !ok {
				continue
			}
			if call[0] > 0 && text[call[0]-1] == '.' && helper.path != "" &&
				filepath.Clean(helper.path) != filepath.Clean(blockPath) {
				continue
			}
			open := call[1] - 1
			close := matchClose(text, open, '(', ')')
			if close < 0 {
				continue
			}
			args := splitCallArgs(text[open+1 : close])
			for i, arg := range args {
				param := pythonParamForArg(arg, i, helper.params)
				if param == "" || !pyControllable(arg, params) {
					continue
				}
				helperPath := helper.path
				if helperPath == "" {
					helperPath = blockPath
				}
				helperKey := filepath.Clean(helperPath) + "::" + helper.name
				if taintedByName[helperKey] == nil {
					taintedByName[helperKey] = map[string]bool{}
				}
				if !taintedByName[helperKey][param] {
					taintedByName[helperKey][param] = true
					child := helper
					child.params = []string{param}
					queue = append(queue, child)
				}
			}
		}
	}
	return out
}

func pythonParamForArg(arg string, position int, params []string) string {
	if eq := strings.Index(arg, "="); eq > 0 && (eq+1 >= len(arg) || arg[eq+1] != '=') {
		name := strings.TrimSpace(arg[:eq])
		for _, p := range params {
			if p == name {
				return p
			}
		}
		return ""
	}
	if position >= 0 && position < len(params) {
		return params[position]
	}
	return ""
}

func pyTaintedNames(lines []srcLine, seeds []string, fileStaticMaps map[string]bool) []string {
	set := map[string]bool{}
	for _, name := range seeds {
		if name != "" {
			set[name] = true
		}
	}
	assign := regexp.MustCompile(`^\s*([A-Za-z_]\w*)(?:\s*:[^=]+)?\s*=\s*(.*)$`)
	for changed := true; changed; {
		changed = false
		staticMaps := pyStaticMapNames(lines, set)
		for name := range fileStaticMaps {
			staticMaps[name] = true
		}
		params := make([]string, 0, len(set))
		for name := range set {
			params = append(params, name)
		}
		for _, line := range maskedPythonLines(lines) {
			m := assign.FindStringSubmatch(line.text)
			if m == nil || strings.HasPrefix(strings.TrimSpace(m[2]), "=") || set[m[1]] ||
				pyStaticMapLookup(m[2], staticMaps) || !pyControllable(m[2], params) {
				continue
			}
			set[m[1]] = true
			changed = true
		}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	return out
}

// pyStaticMapNames finds literal maps whose values do not depend on tainted
// handler input. Selecting one of their fixed values by a tool argument is an
// allow-list choice, not propagation of the argument as an executable value.
func pyStaticMapNames(lines []srcLine, tainted map[string]bool) map[string]bool {
	text := joinLines(lines)
	mapStart := regexp.MustCompile(`(?m)^\s*([A-Za-z_]\w*)\s*=\s*\{`)
	names := map[string]bool{}
	for _, m := range mapStart.FindAllStringSubmatchIndex(text, -1) {
		open := m[1] - 1
		close := matchClose(text, open, '{', '}')
		if close < 0 {
			continue
		}
		body := text[open+1 : close]
		dependsOnInput := false
		for name := range tainted {
			if containsWord(body, name) {
				dependsOnInput = true
				break
			}
		}
		if !dependsOnInput {
			names[text[m[2]:m[3]]] = true
		}
	}
	return names
}

func pyStaticMapLookup(expr string, staticMaps map[string]bool) bool {
	m := regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*\[[^\]]+\]\s*$`).FindStringSubmatch(expr)
	return m != nil && staticMaps[m[1]]
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
	text := maskPythonComments(joinLines(b.lines))
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
		if pyControllable(firstArg, b.params) && !isConstURLArg(firstArg) {
			out = append(out, issue(path, "MCP802", "Tool argument controls a request URL (SSRF)", SeverityHigh, line, code,
				"Pin a constant base URL or allow-list hosts, and block metadata endpoints and private ranges."))
		}
	}

	// 4. filesystem paths. A path is confined only when the exact variable that
	// reaches open()/Path() is guarded by .startswith. A startswith check on a
	// different variable must not silence the finding for an unguarded sink.
	guarded := pyGuardedVars(text)
	openRe := regexp.MustCompile(`\bopen\s*\(`)
	for _, m := range openRe.FindAllStringIndex(text, -1) {
		open := m[1] - 1
		close := matchClose(text, open, '(', ')')
		arg := text[open+1 : close]
		firstArg, _ := splitTopComma(arg)
		line := off2line(m[0])
		code := lineText(b, line)
		if isPyPathConfined(firstArg, guarded) {
			continue
		}
		if pyControllable(firstArg, b.params) {
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
		if isPyPathConfined(arg, guarded) {
			continue
		}
		if pyControllable(arg, b.params) &&
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

var pyStartGuardRe = regexp.MustCompile(`([A-Za-z_]\w*)\.startswith\s*\(`)

// pyGuardedVars collects variables checked with "<var>.startswith(...)", i.e.
// a prefix/boundary check is applied to that specific variable.
func pyGuardedVars(text string) map[string]bool {
	set := map[string]bool{}
	for _, m := range pyStartGuardRe.FindAllStringSubmatch(text, -1) {
		set[m[1]] = true
	}
	return set
}

// isPyPathConfined reports whether the expression reaching a file sink is a
// single variable that carries a startswith boundary guard.
func isPyPathConfined(expr string, guarded map[string]bool) bool {
	e := strings.TrimSpace(expr)
	if !isPyIdent(e) {
		return false
	}
	return guarded[e]
}

func isPyIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}
