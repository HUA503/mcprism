// Package config 定义 MCP server 配置模型，并负责解析各类 MCP 客户端配置文件。
//
// mcprism 同时理解多种主流 MCP 客户端的配置格式（Claude Desktop、Claude Code、
// Cursor、VS Code/Copilot、Windsurf、Cline 等），它们的共同点是使用一个
// "server 名称 -> server 定义" 的映射，根键通常为 mcpServers 或 servers。
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
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
	servers, err := ParseBytes(data)
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

	candidates := map[string]json.RawMessage{}
	for _, key := range []string{"mcpServers", "servers"} {
		if raw, ok := root[key]; ok {
			candidates[key] = raw
		}
	}
	// Claude Code：projects.<path>.mcpServers。每个项目用独立键，避免后一个
	// 项目覆盖前一个，否则前面的 server 会被静默丢弃。
	if projectsRaw, ok := root["projects"]; ok {
		var projects map[string]json.RawMessage
		if err := json.Unmarshal(projectsRaw, &projects); err == nil {
			i := 0
			for _, p := range projects {
				var pobj map[string]json.RawMessage
				if err := json.Unmarshal(p, &pobj); err == nil {
					if mcp, ok := pobj["mcpServers"]; ok {
						candidates[fmt.Sprintf("projects.%d.mcpServers", i)] = mcp
						i++
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
	// 多项目 / 多根键来自 map，遍历顺序不确定；按名称排序保证结果确定性，
	// 否则同一配置在不同机器上可能得到不同顺序的 server，影响 CI 判定。
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
