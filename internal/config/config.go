// Package config 定义 MCP server 配置模型，并负责解析各类 MCP 客户端配置文件。
//
// mcprism 同时理解多种主流 MCP 客户端的配置格式（Claude Desktop、Claude Code、
// Codex、Gemini CLI、OpenCode、Cursor、VS Code/Copilot、Windsurf、Cline 等），包括 JSON 和 TOML。
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Transport 是 MCP server 的传输方式。
type Transport string

const (
	// TransportStdio 表示通过子进程标准输入输出通信（newline-delimited JSON-RPC）。
	TransportStdio Transport = "stdio"
	// TransportHTTP 表示 Streamable HTTP（单端点 POST，可返回 SSE 流）。
	TransportHTTP Transport = "http"
	// TransportSSE 表示旧版 HTTP+SSE 传输（GET /sse 建立事件流 + POST 发消息）。
	TransportSSE Transport = "sse"
)

// Server 描述一个被配置的 MCP server。
type Server struct {
	Name      string            `json:"name"`
	Transport Transport         `json:"transport"`
	Command   string            `json:"command,omitempty"`
	Args      []string          `json:"args,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	URL       string            `json:"url,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Cwd       string            `json:"cwd,omitempty"`

	// ProjectDir is the root of a server implementation checked out on disk.
	// When set, mcprism runs source-code review over it in addition to the
	// configuration checks.
	ProjectDir string `json:"projectDir,omitempty"`
	// ProjectFiles limits source review to specific files. When empty, the
	// whole ProjectDir is reviewed.
	ProjectFiles []string `json:"projectFiles,omitempty"`

	// Source 是该定义所在配置文件的绝对路径。
	Source string `json:"source,omitempty"`
	// Client 是客户端标识（如 claude-desktop、cursor）。
	Client string `json:"client,omitempty"`
	// Scope 是 global 或 project。
	Scope string `json:"scope,omitempty"`

	// Raw 保存原始 JSON 定义，供供应链规则做深入分析。
	Raw json.RawMessage `json:"-"`
}

// Target 返回该 server 的人类可读目标描述。
func (s *Server) Target() string {
	switch {
	case s.Transport == TransportStdio && s.Command != "":
		return strings.TrimSpace(s.Command + " " + strings.Join(s.Args, " "))
	case s.URL != "":
		return s.URL
	case s.ProjectDir != "":
		if len(s.ProjectFiles) == 1 {
			return "source file: " + s.ProjectFiles[0]
		}
		return "source tree: " + s.ProjectDir
	}
	return ""
}

// ClientFile 表示一个已发现的 MCP 客户端配置文件。
type ClientFile struct {
	Path    string    `json:"path"`
	Client  string    `json:"client"`
	Scope   string    `json:"scope"`
	Servers []*Server `json:"servers"`
}

// ParseFile 解析单个配置文件。
func ParseFile(path, client, scope string) (*ClientFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var servers []*Server
	if strings.EqualFold(filepath.Ext(path), ".toml") {
		servers, err = ParseCodexTOML(data)
	} else if client == "github-copilot-cli" || filepath.Base(path) == ".mcp.json" {
		servers, err = ParseCopilotBytes(data)
	} else if strings.EqualFold(filepath.Base(path), "opencode.json") || strings.EqualFold(filepath.Base(path), "opencode.jsonc") {
		servers, err = ParseOpenCodeBytes(data)
	} else {
		servers, err = ParseBytes(data)
	}
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for _, s := range servers {
		s.Source = path
		s.Client = client
		s.Scope = scope
	}
	return &ClientFile{Path: path, Client: client, Scope: scope, Servers: servers}, nil
}

// ParseCopilotBytes supports GitHub Copilot CLI's mcpServers object and its
// project-level bare server map. A bare map is only considered when no known
// MCP wrapper key is present, so unrelated config keys are not treated as
// servers.
func ParseCopilotBytes(data []byte) ([]*Server, error) {
	servers, err := ParseBytes(data)
	if err != nil || len(servers) > 0 {
		return servers, err
	}
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	cleaned := stripTrailingCommas(stripJSONC(data))
	var root map[string]json.RawMessage
	if err := json.Unmarshal(cleaned, &root); err != nil {
		return nil, err
	}
	for _, key := range []string{"mcpServers", "servers", "projects"} {
		if _, ok := root[key]; ok {
			return nil, nil
		}
	}
	names := make([]string, 0, len(root))
	for name := range root {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		server, err := decodeServer(name, root[name])
		if err == nil && server != nil && (server.Command != "" || server.URL != "") {
			servers = append(servers, server)
		}
	}
	return servers, nil
}

// ParseOpenCodeBytes extracts OpenCode's mcp.servers definitions from JSON/JSONC.
func ParseOpenCodeBytes(data []byte) ([]*Server, error) {
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	cleaned := stripTrailingCommas(stripJSONC(data))
	var root map[string]json.RawMessage
	if err := json.Unmarshal(cleaned, &root); err != nil {
		return nil, err
	}
	var mcp map[string]json.RawMessage
	if err := json.Unmarshal(root["mcp"], &mcp); err != nil {
		return nil, nil
	}
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(mcp["servers"], &entries); err != nil {
		return nil, nil
	}
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	servers := make([]*Server, 0, len(names))
	for _, name := range names {
		server, err := decodeOpenCodeServer(name, entries[name])
		if err == nil && server != nil {
			servers = append(servers, server)
		}
	}
	return servers, nil
}

type openCodeServerDTO struct {
	Type        string            `json:"type"`
	Command     []string          `json:"command"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Environment map[string]string `json:"environment"`
	Cwd         string            `json:"cwd"`
}

func decodeOpenCodeServer(name string, raw json.RawMessage) (*Server, error) {
	var dto openCodeServerDTO
	if err := json.Unmarshal(raw, &dto); err != nil {
		return nil, err
	}
	server := &Server{
		Name:    name,
		URL:     dto.URL,
		Headers: dto.Headers,
		Env:     dto.Environment,
		Cwd:     dto.Cwd,
		Raw:     append(json.RawMessage(nil), raw...),
	}
	switch strings.ToLower(dto.Type) {
	case "local":
		if len(dto.Command) == 0 {
			return nil, nil
		}
		server.Transport = TransportStdio
		server.Command = dto.Command[0]
		server.Args = dto.Command[1:]
	case "remote":
		if dto.URL == "" {
			return nil, nil
		}
		server.Transport = TransportHTTP
	default:
		return nil, nil
	}
	return server, nil
}

// ParseBytes 从 JSON/JSONC 字节中提取所有 server。
// 支持 mcpServers / servers 根键，以及 Claude Code 的 projects.<path>.mcpServers。
func ParseBytes(data []byte) ([]*Server, error) {
	// Editors on Windows (Notepad, PowerShell redirection) often save a UTF-8 BOM.
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	// Remove comments first, then trailing commas (common in .vscode/mcp.json).
	cleaned := stripTrailingCommas(stripJSONC(data))
	var root map[string]json.RawMessage
	if err := json.Unmarshal(cleaned, &root); err != nil {
		return nil, err
	}

	var candidates []json.RawMessage
	for _, key := range []string{"mcpServers", "servers"} {
		if raw, ok := root[key]; ok {
			candidates = append(candidates, raw)
		}
	}
	// Claude Code：projects.<path>.mcpServers。每个项目用独立键，避免后一个
	// 项目覆盖前一个，否则前面的 server 会被静默丢弃。
	if projectsRaw, ok := root["projects"]; ok {
		var projects map[string]json.RawMessage
		if err := json.Unmarshal(projectsRaw, &projects); err == nil {
			paths := make([]string, 0, len(projects))
			for path := range projects {
				paths = append(paths, path)
			}
			sort.Strings(paths)
			for _, path := range paths {
				var pobj map[string]json.RawMessage
				if err := json.Unmarshal(projects[path], &pobj); err == nil {
					if mcp, ok := pobj["mcpServers"]; ok {
						candidates = append(candidates, mcp)
					}
				}
			}
		}
	}

	var out []*Server
	for _, raw := range candidates {
		// 标准形态：对象映射
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err == nil {
			names := make([]string, 0, len(obj))
			for n := range obj {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, name := range names {
				s, err := decodeServer(name, obj[name])
				if err == nil {
					out = append(out, s)
				}
			}
			continue
		}
		// 数组形态（部分客户端）
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err == nil {
			for i, item := range arr {
				if s, err := decodeServer(fmt.Sprintf("server-%d", i+1), item); err == nil {
					out = append(out, s)
				}
			}
		}
	}
	// Preserve root and project order when multiple entries share a name.
	sort.SliceStable(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

// serverDTO 用于解码单个 server 定义。
type serverDTO struct {
	Command      string            `json:"command"`
	Args         []string          `json:"args"`
	Env          map[string]string `json:"env"`
	URL          string            `json:"url"`
	Type         string            `json:"type"`
	Headers      map[string]string `json:"headers"`
	Cwd          string            `json:"cwd"`
	Name         string            `json:"name"`
	ProjectDir   string            `json:"projectDir"`
	ProjectFiles []string          `json:"projectFiles"`
}

func decodeServer(name string, raw json.RawMessage) (*Server, error) {
	// 数组形态：["npx","-y","pkg"]
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		return &Server{
			Name:      name,
			Transport: TransportStdio,
			Command:   arr[0],
			Args:      arr[1:],
			Raw:       append(json.RawMessage(nil), raw...),
		}, nil
	}

	var dto serverDTO
	if err := json.Unmarshal(raw, &dto); err != nil {
		return nil, err
	}
	s := &Server{
		Name:         name,
		Args:         dto.Args,
		Env:          dto.Env,
		URL:          dto.URL,
		Headers:      dto.Headers,
		Cwd:          dto.Cwd,
		ProjectDir:   dto.ProjectDir,
		ProjectFiles: dto.ProjectFiles,
		Raw:          append(json.RawMessage(nil), raw...),
	}
	if dto.Name != "" {
		s.Name = dto.Name
	}

	switch strings.ToLower(dto.Type) {
	case "sse":
		s.Transport = TransportSSE
	case "http", "streamable-http", "streamablehttp":
		s.Transport = TransportHTTP
	default:
		if dto.Command != "" {
			s.Transport = TransportStdio
			s.Command = dto.Command
		} else if dto.URL != "" {
			if strings.Contains(dto.URL, "/sse") {
				s.Transport = TransportSSE
			} else {
				s.Transport = TransportHTTP
			}
		}
	}
	return s, nil
}

// stripJSONC 移除 JSONC 风格注释（// 行注释与 /* 块注释 */），保留字符串内容。
func stripJSONC(data []byte) []byte {
	var out bytes.Buffer
	i, n := 0, len(data)
	inString := false
	for i < n {
		c := data[i]
		if inString {
			out.WriteByte(c)
			if c == '\\' && i+1 < n {
				out.WriteByte(data[i+1])
				i += 2
				continue
			}
			if c == '"' {
				inString = false
			}
			i++
			continue
		}
		switch {
		case c == '"':
			inString = true
			out.WriteByte(c)
			i++
		case c == '/' && i+1 < n && data[i+1] == '/':
			i += 2
			for i < n && data[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && data[i+1] == '*':
			i += 2
			for i+1 < n && !(data[i] == '*' && data[i+1] == '/') {
				i++
			}
			i += 2
		default:
			out.WriteByte(c)
			i++
		}
	}
	return out.Bytes()
}

// stripTrailingCommas removes a comma that directly precedes a closing brace or
// bracket (ignoring whitespace), so VS Code-style JSONC with trailing commas
// parses. Commas inside strings are left untouched.
func stripTrailingCommas(data []byte) []byte {
	var out bytes.Buffer
	i, n := 0, len(data)
	inString := false
	for i < n {
		c := data[i]
		if inString {
			out.WriteByte(c)
			if c == '\\' && i+1 < n {
				out.WriteByte(data[i+1])
				i += 2
				continue
			}
			if c == '"' {
				inString = false
			}
			i++
			continue
		}
		switch {
		case c == '"':
			inString = true
			out.WriteByte(c)
			i++
		case c == ',':
			j := i + 1
			for j < n && (data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r') {
				j++
			}
			if j < n && (data[j] == '}' || data[j] == ']') {
				i++ // trailing comma: drop it
				continue
			}
			out.WriteByte(c)
			i++
		default:
			out.WriteByte(c)
			i++
		}
	}
	return out.Bytes()
}
