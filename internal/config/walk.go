package config

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
)

var knownConfigNames = map[string]bool{
	"claude_desktop_config.json": true,
	"mcp.json":                   true,
	".mcp.json":                  true,
	"opencode.json":              true,
	"opencode.jsonc":             true,
}

func isConfigName(base string) bool {
	if knownConfigNames[base] {
		return true
	}
	return strings.HasSuffix(base, ".mcp.json")
}

func skipDirName(name string) bool {
	switch name {
	case "node_modules", ".git", "dist", "bin", "vendor", ".cache":
		return true
	}
	return false
}

// WalkDir recursively finds and parses MCP config files under root. It looks
// for the common config names, Codex TOML config files, Gemini CLI settings,
// OpenCode and JetBrains Air configs, and any *.mcp.json file, skipping
// dependency and build directories.
func WalkDir(root string) ([]*ClientFile, error) {
	var out []*ClientFile
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && skipDirName(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		isCodexConfig := d.Name() == "config.toml" &&
			(filepath.Dir(p) == root || filepath.Base(filepath.Dir(p)) == ".codex")
		isGeminiConfig := d.Name() == "settings.json" &&
			(filepath.Base(filepath.Dir(p)) == ".gemini" ||
				(filepath.Base(root) == ".gemini" && filepath.Clean(filepath.Dir(p)) == filepath.Clean(root)))
		isOpenCodeConfig := d.Name() == "opencode.json" || d.Name() == "opencode.jsonc"
		isJunieConfig := d.Name() == "mcp.json" &&
			filepath.Base(filepath.Dir(p)) == "mcp" &&
			filepath.Base(filepath.Dir(filepath.Dir(p))) == ".junie"
		isJetBrainsAirConfig := d.Name() == "mcp.json" && filepath.Base(filepath.Dir(p)) == ".air"
		isRooCodeConfig := d.Name() == "mcp.json" && filepath.Base(filepath.Dir(p)) == ".roo"
		isCopilotProjectConfig := d.Name() == "mcp.json" && filepath.Base(filepath.Dir(p)) == ".github"
		isZedConfig := d.Name() == "settings.json" && filepath.Base(filepath.Dir(p)) == ".zed"
		if !isConfigName(d.Name()) && !isCodexConfig && !isGeminiConfig && !isOpenCodeConfig && !isRooCodeConfig && !isCopilotProjectConfig && !isZedConfig {
			return nil
		}
		client := "walk"
		if filepath.Ext(p) == ".toml" {
			client = "codex"
		} else if isGeminiConfig {
			client = "gemini-cli"
		} else if isOpenCodeConfig {
			client = "opencode"
		} else if isJunieConfig {
			client = "junie"
		} else if isJetBrainsAirConfig {
			client = "jetbrains-air"
		} else if isRooCodeConfig {
			client = "roo-code"
		} else if isCopilotProjectConfig {
			client = "github-copilot-cli"
		} else if isZedConfig {
			client = "zed"
		} else if d.Name() == ".mcp.json" {
			client = "generic"
		}
		cf, err := ParseFile(p, client, "project")
		if err != nil {
			if errors.Is(err, errNoMCPServersTable) {
				return nil
			}
			return err
		}
		if len(cf.Servers) > 0 {
			out = append(out, cf)
		}
		return nil
	})
	return out, err
}
