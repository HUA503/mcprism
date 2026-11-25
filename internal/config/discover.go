package config

import (
	"errors"
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

// Discover finds project configs in projectDir and its ancestors, and user
// configs when includeGlobal is true.
func Discover(projectDir string, includeGlobal bool) ([]*ClientFile, error) {
	var paths []candPath
	if includeGlobal {
		paths = globalCandidates()
	}
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
			if errors.Is(err, errNoMCPServersTable) {
				continue
			}
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

	// Cline CLI uses a user-level settings file and supports an explicit path
	// override. Keep the VS Code extension locations below for older installs.
	clineSettings := os.Getenv("CLINE_MCP_SETTINGS_PATH")
	if clineSettings == "" {
		clineSettings = filepath.Join(home, ".cline", "data", "settings", "cline_mcp_settings.json")
	}
	add("cline", "global", clineSettings)

	// Cline / Roo Code（VS Code 衍生存储）
	for _, editor := range []string{"Code", "Code - Insiders", "VSCodium"} {
		base := filepath.Join(cfgDir, editor, "User", "globalStorage")
		add("cline", "global", filepath.Join(base, "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"))
		add("roo-code", "global", filepath.Join(base, "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"))
	}

	// Continue
	add("continue", "global", filepath.Join(home, ".continue", "config.json"))

	// Zed MCP servers are stored in the user's settings file.
	add("zed", "global", filepath.Join(cfgDir, "zed", "settings.json"))
	add("zed", "global", filepath.Join(home, ".config", "zed", "settings.json"))
	add("zed", "global", filepath.Join(home, ".zed", "settings.json"))

	// GitHub Copilot CLI keeps user MCP servers under COPILOT_HOME (or ~/.copilot).
	copilotHome := os.Getenv("COPILOT_HOME")
	if copilotHome == "" {
		copilotHome = filepath.Join(home, ".copilot")
	}
	add("github-copilot-cli", "global", filepath.Join(copilotHome, "mcp-config.json"))

	// Gemini CLI user settings use JSON with a top-level mcpServers object.
	add("gemini-cli", "global", filepath.Join(home, ".gemini", "settings.json"))

	// OpenCode user settings use mcp.servers in opencode.json(c).
	openCodeUserDir := filepath.Join(home, ".config", "opencode")
	for _, name := range []string{"opencode.json", "opencode.jsonc"} {
		add("opencode", "global", filepath.Join(openCodeUserDir, name))
	}

	// Gemini CLI supports system defaults and system overrides. The documented
	// environment variables replace the corresponding platform default paths.
	geminiDefaults := os.Getenv("GEMINI_CLI_SYSTEM_DEFAULTS_PATH")
	geminiSettings := os.Getenv("GEMINI_CLI_SYSTEM_SETTINGS_PATH")
	if geminiDefaults == "" || geminiSettings == "" {
		var geminiSystemDir string
		switch runtime.GOOS {
		case "darwin":
			geminiSystemDir = filepath.Join(string(filepath.Separator), "Library", "Application Support", "GeminiCli")
		case "windows":
			programData := os.Getenv("ProgramData")
			if programData == "" {
				systemDrive := os.Getenv("SystemDrive")
				if systemDrive == "" {
					systemDrive = `C:`
				}
				programData = filepath.Join(systemDrive+string(filepath.Separator), "ProgramData")
			}
			geminiSystemDir = filepath.Join(programData, "gemini-cli")
		default:
			geminiSystemDir = filepath.Join(string(filepath.Separator), "etc", "gemini-cli")
		}
		if geminiDefaults == "" {
			geminiDefaults = filepath.Join(geminiSystemDir, "system-defaults.json")
		}
		if geminiSettings == "" {
			geminiSettings = filepath.Join(geminiSystemDir, "settings.json")
		}
	}
	add("gemini-cli", "system-defaults", geminiDefaults)
	add("gemini-cli", "system", geminiSettings)

	// Codex CLI / IDE use TOML, with CODEX_HOME allowing a custom config dir.
	codexHome := os.Getenv("CODEX_HOME")
	if codexHome == "" {
		codexHome = filepath.Join(home, ".codex")
	}
	add("codex", "global", filepath.Join(codexHome, "config.toml"))

	// Codex can also receive MCP servers from system-managed configuration.
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			systemDrive := os.Getenv("SystemDrive")
			if systemDrive == "" {
				systemDrive = `C:`
			}
			programData = filepath.Join(systemDrive+string(filepath.Separator), "ProgramData")
		}
		add("codex", "system", filepath.Join(programData, "OpenAI", "Codex", "config.toml"))
	} else {
		add("codex", "system", filepath.Join(string(filepath.Separator), "etc", "codex", "config.toml"))
	}

	// OpenCode machine-wide settings follow its documented system config directory.
	var openCodeSystemDir string
	switch runtime.GOOS {
	case "darwin":
		openCodeSystemDir = filepath.Join(string(filepath.Separator), "Library", "Application Support", "opencode")
	case "windows":
		programData := os.Getenv("ProgramData")
		if programData == "" {
			systemDrive := os.Getenv("SystemDrive")
			if systemDrive == "" {
				systemDrive = `C:`
			}
			programData = filepath.Join(systemDrive+string(filepath.Separator), "ProgramData")
		}
		openCodeSystemDir = filepath.Join(programData, "opencode")
	default:
		openCodeSystemDir = filepath.Join(string(filepath.Separator), "etc", "opencode")
	}
	for _, name := range []string{"opencode.json", "opencode.jsonc"} {
		add("opencode", "system", filepath.Join(openCodeSystemDir, name))
	}

	return out
}

func projectCandidates(dir string) []candPath {
	var out []candPath
	d := dir
	for d != "" {
		out = append(out,
			candPath{filepath.Join(d, ".mcp.json"), "generic", "project"},
			candPath{filepath.Join(d, ".github", "mcp.json"), "github-copilot-cli", "project"},
			candPath{filepath.Join(d, ".zed", "settings.json"), "zed", "project"},
			candPath{filepath.Join(d, ".cursor", "mcp.json"), "cursor", "project"},
			candPath{filepath.Join(d, ".vscode", "mcp.json"), "vscode", "project"},
			candPath{filepath.Join(d, ".roo", "mcp.json"), "roo-code", "project"},
			candPath{filepath.Join(d, ".gemini", "settings.json"), "gemini-cli", "project"},
			candPath{filepath.Join(d, "opencode.json"), "opencode", "project"},
			candPath{filepath.Join(d, "opencode.jsonc"), "opencode", "project"},
			candPath{filepath.Join(d, ".opencode", "opencode.json"), "opencode", "project"},
			candPath{filepath.Join(d, ".opencode", "opencode.jsonc"), "opencode", "project"},
			candPath{filepath.Join(d, ".codex", "config.toml"), "codex", "project"},
			candPath{filepath.Join(d, "config.toml"), "codex", "project"},
		)
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	return out
}
