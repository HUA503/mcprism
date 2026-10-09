package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

type candPath struct {
	path   string
	client string
	scope  string
}

// Discover 查找系统中存在的所有 MCP 客户端配置文件。
// projectDir 非空时，同时查找该目录及其父级链中的项目级配置。
func Discover(projectDir string) ([]*ClientFile, error) {
	paths := globalCandidates()
	if projectDir != "" {
		paths = append(paths, projectCandidates(projectDir)...)
	}

	seen := map[string]bool{}
	var files []*ClientFile
	for _, p := range paths {
		if p.path == "" || seen[p.path] {
			continue
		}
		info, err := os.Stat(p.path)
		if err != nil || info.IsDir() {
			continue
		}
		seen[p.path] = true
		cf, err := ParseFile(p.path, p.client, p.scope)
		if err != nil {
			// A file that exists but cannot be parsed may be a real MCP config the
			// user expects to be checked. Say so instead of silently skipping it.
			fmt.Fprintf(os.Stderr, "mcprism: warning: cannot parse MCP config %s: %v\n", p.path, err)
			continue
		}
		if len(cf.Servers) > 0 {
			files = append(files, cf)
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func globalCandidates() []candPath {
	home, _ := os.UserHomeDir()
	cfgDir, _ := os.UserConfigDir()
	var out []candPath

	add := func(client, scope, path string) {
		if path != "" {
			out = append(out, candPath{path, client, scope})
		}
	}

	// Claude Desktop
	switch runtime.GOOS {
	case "darwin":
		add("claude-desktop", "global", filepath.Join(home, "Library/Application Support/Claude/claude_desktop_config.json"))
	default:
		// Windows 与 Linux 都落在用户配置目录下的 Claude/ 中
		add("claude-desktop", "global", filepath.Join(cfgDir, "Claude", "claude_desktop_config.json"))
	}

	// Claude Code（顶层 mcpServers + projects.<path>.mcpServers）
	add("claude-code", "global", filepath.Join(home, ".claude.json"))

	// Cursor 全局
	add("cursor", "global", filepath.Join(home, ".cursor", "mcp.json"))

	// Windsurf
	add("windsurf", "global", filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"))

	// Cline / Roo Code（VS Code 衍生存储）
	for _, editor := range []string{"Code", "Code - Insiders", "VSCodium"} {
		base := filepath.Join(cfgDir, editor, "User", "globalStorage")
		add("cline", "global", filepath.Join(base, "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"))
		add("roo-code", "global", filepath.Join(base, "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"))
	}

	// Continue
	add("continue", "global", filepath.Join(home, ".continue", "config.json"))

	return out
}

func projectCandidates(dir string) []candPath {
	var out []candPath
	d := dir
	for i := 0; i < 6 && d != ""; i++ {
		out = append(out,
			candPath{filepath.Join(d, ".mcp.json"), "generic", "project"},
			candPath{filepath.Join(d, ".cursor", "mcp.json"), "cursor", "project"},
			candPath{filepath.Join(d, ".vscode", "mcp.json"), "vscode", "project"},
		)
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	return out
}
