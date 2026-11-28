package sast

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
	imports    map[string]pythonImports
	bytes      int64
	files      int
}

type pythonImports struct {
	modules          map[string]string
	calls            map[string]string
	ambiguousModules map[string]bool
	ambiguousCalls   map[string]bool
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
		imports:    map[string]pythonImports{},
		bytes:      rootBytes,
		files:      1,
	}
	buildPythonFunctionScope(path, lines, 0, scopes)
	for _, b := range extractPythonHandlers(lines) {
		b.path = path
		out = append(out, scanReachablePython(path, b, scopes)...)
	}
	for _, b := range extractPythonRegisteredHandlers(lines, extractPythonFunctions(lines)) {
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
var pyAssignmentTargetRe = regexp.MustCompile(`^\s*([A-Za-z_]\w*)(?:\s*:\s*[^=]+)?\s*=\s*(.*?)\s*$`)
var pyCallableExprRe = regexp.MustCompile(`^[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*$`)
var pyFromImportRe = regexp.MustCompile(`^from\s+(\.*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*|\.+)\s+import\s+(.+?)\s*$`)
var pyImportRe = regexp.MustCompile(`^import\s+(.+?)\s*$`)
var pyFieldAssignRe = regexp.MustCompile(`^\s*([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*|\s*\[\s*['"][A-Za-z_]\w*['"]\s*\]))\s*=\s*(.*)$`)
var pyFieldBaseRe = regexp.MustCompile(`^([A-Za-z_]\w*)\s*(?:\.|\[)`)

func parsePythonImports(lines []srcLine, topLevelOnly bool) pythonImports {
	imports := pythonImports{
		modules: map[string]string{}, calls: map[string]string{},
		ambiguousModules: map[string]bool{}, ambiguousCalls: map[string]bool{},
	}
	add := func(dst map[string]string, ambiguous map[string]bool, alias, target string) {
		if alias == "" || ambiguous[alias] {
			return
		}
		if prior, exists := dst[alias]; exists && prior != target {
			delete(dst, alias)
			ambiguous[alias] = true
			return
		}
		dst[alias] = target
	}
	for _, line := range maskedPythonLines(lines) {
		if topLevelOnly && strings.TrimSpace(line.text) != "" && indentOf(line.text) != 0 {
			continue
		}
		text := strings.TrimSpace(line.text)
		if m := pyImportRe.FindStringSubmatch(text); m != nil {
			for _, item := range strings.Split(m[1], ",") {
				fields := strings.Fields(strings.TrimSpace(item))
				if len(fields) == 0 || (len(fields) != 1 && (len(fields) != 3 || fields[1] != "as")) {
					continue
				}
				module := fields[0]
				if len(fields) == 3 {
					add(imports.modules, imports.ambiguousModules, fields[2], module)
				} else if len(fields) == 1 && !strings.Contains(module, ".") {
					add(imports.modules, imports.ambiguousModules, module, module)
				}
			}
			continue
		}
		m := pyFromImportRe.FindStringSubmatch(text)
		if m == nil || strings.HasPrefix(m[1], ".") {
			continue
		}
		for _, item := range strings.Split(strings.Trim(strings.TrimSpace(m[2]), "()"), ",") {
			fields := strings.Fields(strings.TrimSpace(item))
			if len(fields) == 0 || (len(fields) != 1 && (len(fields) != 3 || fields[1] != "as")) {
				continue
			}
			name, alias := fields[0], fields[0]
			if len(fields) == 3 {
				alias = fields[2]
			}
			if isIdent(name) && isIdent(alias) {
				add(imports.calls, imports.ambiguousCalls, alias, m[1]+"."+name)
			}
		}
	}
	return imports
}

type pythonCall struct {
	start, end int
	canonical  string
}

func pythonCalls(text string, imports pythonImports, targets ...string) []pythonCall {
	var calls []pythonCall
	seen := map[string]bool{}
	callableAliases := pythonCallableAliases(text, imports)
	for _, target := range targets {
		names := map[string]bool{target: true}
		for alias, canonical := range imports.calls {
			if canonical == target {
				names[alias] = true
			}
		}
		for alias, module := range imports.modules {
			if strings.HasPrefix(target, module+".") {
				names[alias+strings.TrimPrefix(target, module)] = true
			}
		}
		for alias, canonical := range callableAliases {
			if canonical == target {
				names[alias] = true
			}
		}
		alternatives := make([]string, 0, len(names))
		for name := range names {
			alternatives = append(alternatives, regexp.QuoteMeta(name))
		}
		re := regexp.MustCompile(`\b(?:` + strings.Join(alternatives, "|") + `)\s*\(`)
		for _, match := range re.FindAllStringIndex(text, -1) {
			key := fmt.Sprintf("%d:%d:%s", match[0], match[1], target)
			if !seen[key] {
				seen[key] = true
				calls = append(calls, pythonCall{start: match[0], end: match[1], canonical: target})
			}
		}
	}
	sort.Slice(calls, func(i, j int) bool { return calls[i].start < calls[j].start })
	return calls
}

// pythonCallableAliases follows simple local assignments of imported callables,
// such as `run = subprocess.run` or `fetch = httpx.get`. This catches common
// sink indirection while omitting names reassigned to a different or dynamic value.
func pythonCallableAliases(text string, imports pythonImports) map[string]string {
	assignments := map[string]string{}
	ambiguous := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		m := pyAssignmentTargetRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		alias, expr := m[1], strings.ReplaceAll(m[2], " ", "")
		if strings.HasPrefix(strings.TrimSpace(expr), "=") {
			continue
		}
		if !pyCallableExprRe.MatchString(m[2]) {
			delete(assignments, alias)
			ambiguous[alias] = true
			continue
		}
		if prior, exists := assignments[alias]; exists && prior != expr {
			delete(assignments, alias)
			ambiguous[alias] = true
			continue
		}
		if !ambiguous[alias] {
			assignments[alias] = expr
		}
	}

	aliases := map[string]string{}
	for changed := true; changed; {
		changed = false
		for alias, expr := range assignments {
			if ambiguous[alias] {
				continue
			}
			canonical := aliases[expr]
			if canonical == "" {
				canonical = imports.calls[expr]
			}
			if canonical == "" {
				for moduleAlias, module := range imports.modules {
					if expr == moduleAlias || strings.HasPrefix(expr, moduleAlias+".") {
						canonical = module + strings.TrimPrefix(expr, moduleAlias)
						break
					}
				}
			}
			if canonical == "" && strings.Contains(expr, ".") {
				canonical = expr
			}
			if canonical != "" && aliases[alias] != canonical {
				aliases[alias] = canonical
				changed = true
			}
		}
	}
	return aliases
}

func mergePythonImports(base, local pythonImports) pythonImports {
	merged := pythonImports{
		modules: map[string]string{}, calls: map[string]string{},
		ambiguousModules: map[string]bool{}, ambiguousCalls: map[string]bool{},
	}
	for alias, target := range base.modules {
		merged.modules[alias] = target
	}
	for alias, target := range local.modules {
		merged.modules[alias] = target
	}
	for alias, target := range base.calls {
		merged.calls[alias] = target
	}
	for alias := range local.ambiguousModules {
		delete(merged.modules, alias)
		merged.ambiguousModules[alias] = true
	}
	for alias := range local.ambiguousCalls {
		delete(merged.calls, alias)
		merged.ambiguousCalls[alias] = true
	}
	for alias, target := range local.calls {
		if !merged.ambiguousCalls[alias] {
			merged.calls[alias] = target
		}
	}
	for alias, target := range local.modules {
		if !merged.ambiguousModules[alias] {
			merged.modules[alias] = target
		}
	}
	return merged
}

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
	scopes.imports[key] = parsePythonImports(lines, true)
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

// mergePythonImportedFunctions resolves explicit imports from bounded local
// Python modules. Ambiguous aliases and star imports stay unresolved.
func mergePythonImportedFunctions(path string, lines []srcLine, functions map[string]handlerBlock, localNames map[string]bool, depth int, scopes *pythonFunctionScopes) {
	type importedHelper struct {
		block handlerBlock
		count int
	}
	candidates := map[string]importedHelper{}
	for _, line := range maskedPythonLines(lines) {
		if m := pyImportRe.FindStringSubmatch(line.text); m != nil {
			for _, item := range strings.Split(m[1], ",") {
				fields := strings.Fields(strings.TrimSpace(item))
				if len(fields) == 0 || (len(fields) != 1 && (len(fields) != 3 || fields[1] != "as")) {
					continue
				}
				module := fields[0]
				alias := module
				if len(fields) == 3 {
					alias = fields[2]
				} else if dot := strings.LastIndexByte(alias, '.'); dot >= 0 {
					alias = alias[dot+1:]
				}
				modulePath := pythonLocalModulePath(path, module)
				if modulePath == "" || localNames[alias] {
					continue
				}
				moduleFunctions, ok := pythonImportedScope(modulePath, depth, scopes)
				if !ok {
					continue
				}
				for name, helper := range moduleFunctions {
					// Import only definitions from the target module itself. Dotted
					// keys already represent its own explicitly imported helpers.
					if strings.Contains(name, ".") {
						continue
					}
					key := alias + "." + name
					if localNames[key] {
						continue
					}
					helper.name = key
					functions[key] = helper
				}
			}
			continue
		}
		m := pyFromImportRe.FindStringSubmatch(line.text)
		if m == nil {
			continue
		}
		modulePath := pythonLocalModulePath(path, m[1])
		if modulePath == "" {
			continue
		}
		moduleFunctions, ok := pythonImportedScope(modulePath, depth, scopes)
		if !ok {
			continue
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

func pythonImportedScope(modulePath string, depth int, scopes *pythonFunctionScopes) (map[string]handlerBlock, bool) {
	moduleKey := filepath.Clean(modulePath)
	if functions, ok := scopes.functions[moduleKey]; ok {
		return functions, true
	}
	if scopes.files >= maxPythonModuleFiles || depth >= maxPythonModuleDepth {
		return nil, false
	}
	info, err := os.Lstat(modulePath)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxSourceFileSize ||
		scopes.bytes+info.Size() > maxPythonModuleBytes {
		return nil, false
	}
	moduleLines, moduleSrc := readLines(modulePath)
	if moduleSrc == "" || scopes.bytes+int64(len(moduleSrc)) > maxPythonModuleBytes {
		return nil, false
	}
	scopes.bytes += info.Size()
	scopes.files++
	return buildPythonFunctionScope(modulePath, moduleLines, depth+1, scopes), true
}

func pythonLocalModulePath(path, module string) string {
	dotCount := len(module) - len(strings.TrimLeft(module, "."))
	name := module[dotCount:]
	baseDir := filepath.Dir(path)
	if dotCount > 0 {
		// A single leading dot is relative to this package directory; each
		// additional dot moves up one package level. Require an explicit
		// package marker before each ascent so a hostile import cannot make a
		// single-file scan read arbitrary parent directories.
		for i := 1; i < dotCount; i++ {
			marker, err := os.Lstat(filepath.Join(baseDir, "__init__.py"))
			if err != nil || !marker.Mode().IsRegular() {
				return ""
			}
			baseDir = filepath.Dir(baseDir)
		}
		if dotCount > 1 {
			marker, err := os.Lstat(filepath.Join(baseDir, "__init__.py"))
			if err != nil || !marker.Mode().IsRegular() {
				return ""
			}
		}
		if name == "" {
			name = "__init__"
		}
	} else if name == "" || strings.Contains(name, ".") {
		return ""
	}
	parts := strings.Split(name, ".")
	for _, part := range parts {
		if !isIdent(part) {
			return ""
		}
	}
	candidate := filepath.Join(baseDir, filepath.Join(parts...)+".py")
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

var pyRegisteredToolCallRe = regexp.MustCompile(`\.\s*(add_tool|register_tool|addTool|registerTool|tool)\s*\(`)

// extractPythonRegisteredHandlers recognizes callback functions passed to
// common tool-registration methods, in addition to decorator-based SDKs. It
// only follows a direct reference to an unambiguous function defined locally.
func extractPythonRegisteredHandlers(sourceLines []srcLine, functions map[string]handlerBlock) []handlerBlock {
	lines := maskedPythonLines(sourceLines)
	var masked strings.Builder
	for i, line := range lines {
		if i > 0 {
			masked.WriteByte('\n')
		}
		masked.WriteString(line.text)
	}
	text := masked.String()
	var out []handlerBlock
	seen := map[string]bool{}
	for _, match := range pyRegisteredToolCallRe.FindAllStringSubmatchIndex(text, -1) {
		open := strings.IndexByte(text[match[0]:match[1]], '(')
		if open < 0 {
			continue
		}
		open += match[0]
		close := matchClose(text, open, '(', ')')
		if close < 0 {
			continue
		}
		var positional []string
		var callback string
		for _, arg := range splitCallArgs(text[open+1 : close]) {
			if eq := strings.IndexByte(arg, '='); eq >= 0 {
				key, value := strings.TrimSpace(arg[:eq]), strings.TrimSpace(arg[eq+1:])
				switch key {
				case "handler", "callback", "func", "function":
					callback = value
				}
			} else {
				positional = append(positional, strings.TrimSpace(arg))
			}
		}
		if callback == "" && len(positional) > 0 {
			callback = positional[len(positional)-1]
		}
		if !isIdent(callback) || seen[callback] {
			continue
		}
		block, ok := functions[callback]
		if !ok {
			continue
		}
		block.name = callback
		out = append(out, block)
		seen[callback] = true
	}
	return out
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
		imports := mergePythonImports(scopes.imports[moduleKey], parsePythonImports(block.lines, false))
		out = append(out, scanPythonBlock(issuePath, block, imports)...)

		text := maskPythonComments(joinLines(block.lines))
		for _, call := range pyCallRe.FindAllStringSubmatchIndex(text, -1) {
			name := text[call[2]:call[3]]
			helper, ok := functions[name]
			if call[0] > 0 && text[call[0]-1] == '.' {
				// Resolve only an explicitly imported module alias. Other selector
				// calls may be methods on unrelated objects with the same name.
				selectorStart := call[0] - 1
				for selectorStart > 0 && (isIdentByte(text[selectorStart-1]) || text[selectorStart-1] == '.') {
					selectorStart--
				}
				selector := strings.Trim(text[selectorStart:call[0]-1], ".") + "." + name
				resolved, explicit := functions[selector]
				if explicit {
					helper = resolved
					ok = true
				} else if !ok || (helper.path != "" && filepath.Clean(helper.path) != filepath.Clean(blockPath)) {
					continue
				}
			}
			if !ok {
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
	tupleAssign := regexp.MustCompile(`^\s*[\(\[]?\s*((?:\*?[A-Za-z_]\w*\s*,\s*)+\*?[A-Za-z_]\w*\s*,?)\s*[\)\]]?\s*=\s*(.*)$`)
	for changed := true; changed; {
		changed = false
		staticMaps := pyStaticMapNames(lines, set)
		for name := range fileStaticMaps {
			staticMaps[name] = true
		}
		// A map literal stops being a static allow-list after a tainted field
		// assignment. Keep subsequent lookups in the taint flow.
		for name := range set {
			if m := pyFieldBaseRe.FindStringSubmatch(name); m != nil {
				delete(staticMaps, m[1])
			}
		}
		params := make([]string, 0, len(set))
		for name := range set {
			params = append(params, name)
		}
		for _, line := range maskedPythonLines(lines) {
			if m := tupleAssign.FindStringSubmatch(line.text); m != nil &&
				!strings.HasPrefix(strings.TrimSpace(m[2]), "=") && pyControllable(m[2], params) {
				for _, target := range strings.Split(strings.TrimSuffix(m[1], ","), ",") {
					target = strings.TrimPrefix(strings.TrimSpace(target), "*")
					if isPyIdent(target) && !set[target] {
						set[target] = true
						changed = true
					}
				}
			}
			if field := pyFieldAssignRe.FindStringSubmatch(line.text); field != nil {
				target := normalizeTaintTarget(field[1])
				if !set[target] && pyControllable(field[2], params) {
					set[target] = true
					changed = true
				}
			}
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

func scanPythonBlock(path string, b handlerBlock, imports pythonImports) []Issue {
	var out []Issue
	text := maskPythonComments(joinLines(b.lines))
	baseLine := b.lines[0].num
	off2line := func(off int) int { return baseLine + strings.Count(text[:off], "\n") }

	// 1. process execution
	cmdTargets := []string{"os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call"}
	for _, call := range pythonCalls(text, imports, cmdTargets...) {
		open := call.end - 1
		close := matchClose(text, open, '(', ')')
		if close < 0 {
			continue
		}
		arg := text[open+1 : close]
		firstArg, rest := splitTopComma(arg)
		line := off2line(call.start)
		code := lineText(b, line)
		switch {
		case call.canonical == "os.system" || call.canonical == "os.popen":
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
	netTargets := []string{"requests.get", "requests.post", "requests.put", "requests.request", "httpx.get", "httpx.post", "httpx.put", "urllib.request.urlopen", "urllib.urlopen", "urlopen"}
	for _, call := range pythonCalls(text, imports, netTargets...) {
		open := call.end - 1
		close := matchClose(text, open, '(', ')')
		arg := text[open+1 : close]
		firstArg, _ := splitTopComma(arg)
		line := off2line(call.start)
		code := lineText(b, line)
		if pyControllable(firstArg, b.params) && !isConstURLArg(firstArg) {
			out = append(out, issue(path, "MCP802", "Tool argument controls a request URL (SSRF)", SeverityHigh, line, code,
				"Pin a constant base URL or allow-list hosts, and block metadata endpoints and private ranges."))
		}
	}
	for _, call := range pythonCalls(text, imports, "socket.create_connection") {
		open := call.end - 1
		close := matchClose(text, open, '(', ')')
		if close < 0 {
			continue
		}
		address, _ := splitTopComma(text[open+1 : close])
		if !pyControllable(address, b.params) {
			continue
		}
		line := off2line(call.start)
		out = append(out, issue(path, "MCP802", "Tool argument controls an outbound network target (SSRF)", SeverityHigh, line, lineText(b, line),
			"Use a fixed destination or allow-list approved hosts, and reject private, loopback and link-local addresses after resolving the target."))
	}
	socketVars := map[string]bool{}
	socketAssignments := map[string]string{}
	ambiguousSockets := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		assignment := pyAssignmentTargetRe.FindStringSubmatch(line)
		if assignment == nil {
			continue
		}
		name, expression := assignment[1], strings.TrimSpace(assignment[2])
		isSocket := false
		for _, constructor := range pythonCalls(expression, imports, "socket.socket") {
			open := constructor.end - 1
			close := matchClose(expression, open, '(', ')')
			if close >= 0 && strings.TrimSpace(expression[:constructor.start]) == "" && strings.TrimSpace(expression[close+1:]) == "" {
				isSocket = true
				break
			}
		}
		if prior, exists := socketAssignments[name]; exists {
			if prior != expression {
				delete(socketVars, name)
				delete(socketAssignments, name)
				ambiguousSockets[name] = true
			}
		} else if isSocket && !ambiguousSockets[name] {
			socketVars[name] = true
			socketAssignments[name] = expression
		}
	}
	for receiver := range socketVars {
		connectRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(receiver) + `\s*\.\s*(connect|connect_ex)\s*\(`)
		for _, match := range connectRe.FindAllStringIndex(text, -1) {
			open := match[1] - 1
			close := matchClose(text, open, '(', ')')
			if close < 0 {
				continue
			}
			address, _ := splitTopComma(text[open+1 : close])
			if !pyControllable(address, b.params) {
				continue
			}
			line := off2line(match[0])
			out = append(out, issue(path, "MCP802", "Tool argument controls an outbound network target (SSRF)", SeverityHigh, line, lineText(b, line),
				"Use a fixed destination or allow-list approved hosts, and reject private, loopback and link-local addresses after resolving the target."))
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
	for _, call := range pythonCalls(text, imports, "pathlib.Path", "Path") {
		open := call.end - 1
		close := matchClose(text, open, '(', ')')
		arg := text[open+1 : close]
		line := off2line(call.start)
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
	deserTargets := []string{"pickle.loads", "pickle.load", "marshal.loads", "yaml.load"}
	for _, call := range pythonCalls(text, imports, deserTargets...) {
		open := call.end - 1
		close := matchClose(text, open, '(', ')')
		arg := text[open+1 : close]
		line := off2line(call.start)
		code := lineText(b, line)
		if call.canonical == "yaml.load" && strings.Contains(arg, "SafeLoader") {
			continue
		}
		title := "Unsafe deserialization of untrusted data"
		advice := "Do not deserialize untrusted data with pickle/marshal. For YAML use safe_load or SafeLoader."
		if call.canonical == "yaml.load" {
			title = "yaml.load without a safe loader"
			advice = "Use yaml.safe_load or yaml.load(..., Loader=yaml.SafeLoader)."
		}
		out = append(out, issue(path, "MCP805", title, SeverityHigh, line, code, advice))
	}
	return out
}

func pyControllable(expr string, params []string) bool {
	expr = normalizeTaintTarget(expr)
	for _, p := range params {
		if p != "" && containsWord(expr, normalizeTaintTarget(p)) {
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
