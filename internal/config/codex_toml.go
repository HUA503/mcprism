package config

import (
	"bytes"
	"errors"
	"sort"

	"github.com/pelletier/go-toml/v2"
)

var errNoMCPServersTable = errors.New("missing [mcp_servers] table")

type codexConfig struct {
	MCPServers map[string]codexMCPServer `toml:"mcp_servers"`
}

type codexMCPServer struct {
	Command           string            `toml:"command"`
	Args              []string          `toml:"args"`
	Env               map[string]string `toml:"env"`
	URL               string            `toml:"url"`
	BearerTokenEnvVar string            `toml:"bearer_token_env_var"`
	HTTPHeaders       map[string]string `toml:"http_headers"`
	EnvHTTPHeaders    map[string]string `toml:"env_http_headers"`
	Cwd               string            `toml:"cwd"`
	Enabled           *bool             `toml:"enabled"`
}

// ParseCodexTOML reads Codex's [mcp_servers.<name>] configuration. It maps
// only fields mcprism can audit and never resolves environment variables.
func ParseCodexTOML(data []byte) ([]*Server, error) {
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	var cfg codexConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	names := make([]string, 0, len(cfg.MCPServers))
	for name := range cfg.MCPServers {
		names = append(names, name)
	}
	sort.Strings(names)

	servers := make([]*Server, 0, len(names))
	for _, name := range names {
		entry := cfg.MCPServers[name]
		if entry.Enabled != nil && !*entry.Enabled {
			continue
		}
		if entry.Command == "" && entry.URL == "" {
			// Codex supports partial project overrides. Without the merged user
			// config, such an entry has no target that mcprism can meaningfully scan.
			continue
		}

		server := &Server{
			Name:    name,
			Command: entry.Command,
			Args:    entry.Args,
			Env:     entry.Env,
			URL:     entry.URL,
			Cwd:     entry.Cwd,
			Headers: make(map[string]string, len(entry.HTTPHeaders)+len(entry.EnvHTTPHeaders)+1),
		}
		if entry.Command != "" {
			server.Transport = TransportStdio
		} else {
			server.Transport = TransportHTTP
		}
		for key, value := range entry.HTTPHeaders {
			server.Headers[key] = value
		}
		for key, envName := range entry.EnvHTTPHeaders {
			server.Headers[key] = "${" + envName + "}"
		}
		if entry.BearerTokenEnvVar != "" {
			server.Headers["Authorization"] = "Bearer ${" + entry.BearerTokenEnvVar + "}"
		}
		if len(server.Headers) == 0 {
			server.Headers = nil
		}
		servers = append(servers, server)
	}
	if len(servers) == 0 && cfg.MCPServers == nil {
		return nil, errNoMCPServersTable
	}
	return servers, nil
}
