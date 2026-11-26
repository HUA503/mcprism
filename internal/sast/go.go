package sast

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

func analyzeGo(path string) []Issue {
	_, functions := extractGoPackageFunctions(path)
	return analyzeGoWithFunctions(path, functions)
}

func analyzeGoWithFunctions(path string, functions map[string]handlerBlock) []Issue {
	lines, src := readLines(path)
	if src == "" {
		return nil
	}
	// Keep same-file method helpers available while package-level discovery is
	// limited to free functions whose receiver does not need resolving.
	allFunctions := make(map[string]handlerBlock, len(functions))
	for name, helper := range functions {
		allFunctions[name] = helper
	}
	for name, helper := range extractGoFunctions(src) {
		if _, exists := allFunctions[name]; !exists {
			helper.path = path
			allFunctions[name] = helper
		}
	}
	var out []Issue
	for _, b := range extractGoHandlers(maskGoComments(src)) {
		b.path = path
		out = append(out, scanReachableGo(path, b, allFunctions)...)
	}
	for _, l := range maskedGoLines(lines) {
		out = append(out, goLineSecretIssues(path, l)...)
	}
	return dedupIssues(out)
}

// goPackageName returns a source file's declared package name.
func goPackageName(path string) (string, bool) {
	src, err := os.ReadFile(path)
	if err != nil || len(src) > maxSourceFileSize {
		return "", false
	}
	fset := token.NewFileSet()
	file, _ := parser.ParseFile(fset, path, src, parser.PackageClauseOnly)
	if file == nil || file.Name == nil {
		return "", false
	}
	return file.Name.Name, true
}

// extractGoPackageFunctions includes same-package free functions from sibling
// files. Methods from sibling files are excluded because short-name matching
// cannot resolve their receiver type. Size and file-count caps keep package
// discovery bounded for hostile source trees.
func extractGoPackageFunctions(path string) (string, map[string]handlerBlock) {
	functions := map[string]handlerBlock{}
	counts := map[string]int{}
	pkgName, ok := goPackageName(path)
	if !ok {
		return "", functions
	}
	dirEntries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(dirEntries) > 256 {
		return pkgName, extractGoFunctionsFromPath(path)
	}
	var total int64
	for _, entry := range dirEntries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".go") {
			continue
		}
		filePath := filepath.Join(filepath.Dir(path), entry.Name())
		info, err := entry.Info()
		if err != nil || info.Size() > maxSourceFileSize {
			continue
		}
		total += info.Size()
		if total > 16<<20 {
			break
		}
		src, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}
		fset := token.NewFileSet()
		file, _ := parser.ParseFile(fset, filePath, src, parser.ParseComments|parser.AllErrors)
		if file == nil || file.Name == nil || file.Name.Name != pkgName {
			continue
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Recv != nil {
				continue
			}
			name := fn.Name.Name
			counts[name]++
			if counts[name] > 1 {
				delete(functions, name)
				continue
			}
			var params []string
			if fn.Type.Params != nil {
				for _, field := range fn.Type.Params.List {
					if len(field.Names) == 0 {
						params = append(params, "")
						continue
					}
					for _, param := range field.Names {
						params = append(params, param.Name)
					}
				}
			}
			bodyOpen := fset.Position(fn.Body.Lbrace).Offset
			bodyClose := fset.Position(fn.Body.Rbrace).Offset
			functions[name] = handlerBlock{
				name: name, params: params, lines: linesRange(string(src), bodyOpen, bodyClose+1), path: filePath,
			}
		}
	}
	return pkgName, functions
}

func extractGoFunctionsFromPath(path string) map[string]handlerBlock {
	_, src := readLines(path)
	return extractGoFunctions(src)
}

// ---------- handler extraction ----------

var goAddToolRe = regexp.MustCompile(`\.?AddTool\s*\(`)
var goCallRe = regexp.MustCompile(`\b([A-Za-z_]\w*)\s*\(`)

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

func extractGoFunctions(src string) map[string]handlerBlock {
	functions := map[string]handlerBlock{}
	ambiguous := map[string]bool{}
	fset := token.NewFileSet()
	file, _ := parser.ParseFile(fset, "", src, parser.ParseComments|parser.AllErrors)
	if file == nil {
		return functions
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		name := fn.Name.Name
		if ambiguous[name] {
			continue
		}
		if _, exists := functions[name]; exists {
			delete(functions, name)
			ambiguous[name] = true
			continue
		}
		var params []string
		if fn.Type.Params != nil {
			for _, field := range fn.Type.Params.List {
				if len(field.Names) == 0 {
					params = append(params, "")
					continue
				}
				for _, param := range field.Names {
					params = append(params, param.Name)
				}
			}
		}
		bodyOpen := fset.Position(fn.Body.Lbrace).Offset
		bodyClose := fset.Position(fn.Body.Rbrace).Offset
		functions[name] = handlerBlock{
			name: name, params: params,
			lines: linesRange(src, bodyOpen, bodyClose+1),
		}
	}
	return functions
}

func scanReachableGo(path string, entry handlerBlock, functions map[string]handlerBlock) []Issue {
	taintedByName := map[string]map[string]bool{}
	processedByName := map[string]map[string]bool{}
	queue := []handlerBlock{entry}
	var out []Issue
	for head := 0; head < len(queue); head++ {
		block := queue[head]
		seed := goTaintedNames(block.lines, block.params)
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
		issuePath := block.path
		if issuePath == "" {
			issuePath = path
		}
		out = append(out, scanGoBlockWithTaint(issuePath, block, params)...)

		text := maskGoComments(joinLines(block.lines))
		ctrl := goTaintedNames(block.lines, params)
		for _, call := range goCallRe.FindAllStringSubmatchIndex(text, -1) {
			name := text[call[2]:call[3]]
			helper, ok := functions[name]
			if !ok {
				continue
			}
			if call[0] > 0 && text[call[0]-1] == '.' &&
				helper.path != "" && filepath.Clean(helper.path) != filepath.Clean(path) {
				// A selector call may be a method on an unrelated receiver. Do not
				// resolve it to a same-named free helper from another file.
				continue
			}
			open := call[1] - 1
			close := matchClose(text, open, '(', ')')
			if close < 0 {
				continue
			}
			args := splitCallArgs(text[open+1 : close])
			for i, arg := range args {
				if i >= len(helper.params) || helper.params[i] == "" || !goExprControllable(arg, ctrl) {
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

// ---------- sink scanning ----------

func scanGoBlock(path string, b handlerBlock) []Issue {
	return scanGoBlockWithTaint(path, b, nil)
}

func scanGoBlockWithTaint(path string, b handlerBlock, seeds []string) []Issue {
	var out []Issue
	text := maskGoComments(joinLines(b.lines))
	baseLine := b.lines[0].num
	off2line := func(off int) int { return baseLine + strings.Count(text[:off], "\n") }

	ctrl := goTaintedNames(b.lines, seeds)

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
	guarded := goGuardedVars(maskedGoLines(b.lines))
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
	for _, l := range maskedGoLines(ls) {
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

// goTaintedNames extends direct MCP argument extraction to simple local aliases
// and parameters explicitly passed into same-file helper functions.
func goTaintedNames(ls []srcLine, seeds []string) map[string]bool {
	set := goControllableVars(ls)
	for _, name := range seeds {
		if isGoIdent(name) {
			set[name] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for _, line := range maskedGoLines(ls) {
			t := strings.TrimSpace(line.text)
			i := strings.Index(t, ":=")
			width := 2
			if i < 0 {
				i = strings.Index(t, "=")
				width = 1
				if i < 0 || i+1 < len(t) && t[i+1] == '=' || i > 0 && t[i-1] == '=' {
					continue
				}
			}
			lhs := strings.TrimSpace(t[:i])
			rhs := strings.TrimSpace(t[i+width:])
			first := strings.TrimSpace(strings.Split(lhs, ",")[0])
			if isGoIdent(first) && !set[first] && goExprControllable(rhs, set) {
				set[first] = true
				changed = true
			}
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
