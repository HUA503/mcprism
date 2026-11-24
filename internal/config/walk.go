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
// for the common config names, Codex TOML config files and any *.mcp.json file,
// skipping dependency and build directories.
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
		if !isConfigName(d.Name()) && !isCodexConfig {
			return nil
		}
		client := "walk"
		if filepath.Ext(p) == ".toml" {
			client = "codex"
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
