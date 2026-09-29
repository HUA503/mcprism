package config

import (
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
// for the common config names and any *.mcp.json file, skipping dependency
// and build directories.
func WalkDir(root string) ([]*ClientFile, error) {
	var out []*ClientFile
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != root && skipDirName(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !isConfigName(d.Name()) {
			return nil
		}
		cf, perr := ParseFile(p, "walk", "project")
		if perr == nil && len(cf.Servers) > 0 {
			out = append(out, cf)
		}
		return nil
	})
	return out, err
}
