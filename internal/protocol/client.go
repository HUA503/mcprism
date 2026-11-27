// Package protocol 是一个精简的 Model Context Protocol（MCP）客户端实现，
// 支持 stdio、Streamable HTTP 与旧版 SSE 三种传输，用于连接并枚举任意 MCP server
// 暴露的 tools、resources、prompts，为安全审查提供真实的运行时能力清单。
package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HUA503/mcprism/internal/config"
)

// PreferredVersion 是旧版握手协议中最新的版本。
const PreferredVersion = "2025-11-25"

// ModernVersion 是使用无状态请求与 server/discover 的当前协议版本。
const ModernVersion = "2026-07-28"

// ClientVersion 是 mcprism 自身版本，会在 clientInfo 中上报。
// ClientVersion is reported to servers in clientInfo. The main package sets it
// to the build version at startup, so the scanner never advertises a stale one.
var ClientVersion = "dev"

// RPCRequest 是一条 JSON-RPC 2.0 请求。
type RPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// RPCError 是 JSON-RPC 错误对象。
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
}

// RPCResponse 是一条 JSON-RPC 2.0 响应。
type RPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// transport 抽象底层传输。
type transport interface {
	call(ctx context.Context, id int64, method string, params any) (json.RawMessage, error)
	notify(ctx context.Context, method string, params any) error
	close() error
}

// Client 是 MCP 客户端会话。
type Client struct {
	tr      transport
	once    sync.Once
	idSeq   int64
	version string
	modern  bool
}

// Dial 根据 server 配置建立 MCP 会话。
func Dial(ctx context.Context, srv *config.Server) (*Client, error) {
	var t transport
	var err error
	switch srv.Transport {
	case config.TransportStdio:
		t, err = newStdioTransport(ctx, srv)
	case config.TransportHTTP:
		t, err = newHTTPTransport(ctx, srv, false)
	case config.TransportSSE:
		t, err = newHTTPTransport(ctx, srv, true)
	default:
		return nil, fmt.Errorf("unknown transport %q", srv.Transport)
	}
	if err != nil {
		return nil, err
	}
	return &Client{tr: t}, nil
}

func (c *Client) nextID() int64 {
	return atomic.AddInt64(&c.idSeq, 1)
}

// Close 关闭底层连接。
func (c *Client) Close() error {
	var err error
	c.once.Do(func() { err = c.tr.close() })
	return err
}

// ServerInfo 描述 server 实现。
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// InitializeResult 是 legacy initialize 或现代 server/discover 的统一结果。
type InitializeResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ServerInfo      ServerInfo     `json:"serverInfo"`
	Instructions    string         `json:"instructions,omitempty"`
}

// Initialize 协商新旧 MCP 协议。新版 server 使用 server/discover 与
// 无状态请求；旧版 server 回退到 initialize/initialized 握手。
func (c *Client) Initialize(ctx context.Context) (*InitializeResult, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	params := requestMeta(ModernVersion)
	raw, probeErr := c.tr.call(probeCtx, c.nextID(), "server/discover", params)
	cancel()

	if probeErr == nil {
		var discovered discoverResult
		if err := json.Unmarshal(raw, &discovered); err == nil && len(discovered.SupportedVersions) > 0 {
			version, ok := selectVersion(discovered.SupportedVersions)
			if !ok {
				return nil, incompatibleVersionError(discovered.SupportedVersions)
			}
			if version == ModernVersion {
				c.version, c.modern = version, true
				return &InitializeResult{
					ProtocolVersion: version,
					Capabilities:    discovered.Capabilities,
					ServerInfo:      discovered.Meta.ServerInfo,
					Instructions:    discovered.Instructions,
				}, nil
			}
			return c.initializeLegacy(ctx, version)
		}
	} else if rpcErr, ok := probeErr.(*RPCError); ok && rpcErr.Code == unsupportedProtocolVersionCode {
		versions := supportedVersions(rpcErr.Data)
		if version, ok := selectVersion(versions); ok && version != ModernVersion {
			return c.initializeLegacy(ctx, version)
		}
		return nil, incompatibleVersionError(versions)
	}

	// Older servers do not know server/discover. On stdio they may return an
	// unknown-method error or stay silent until the bounded probe times out.
	return c.initializeLegacy(ctx, PreferredVersion)
}

const unsupportedProtocolVersionCode = -32022

type discoverResult struct {
	SupportedVersions []string       `json:"supportedVersions"`
	Capabilities      map[string]any `json:"capabilities"`
	Meta              struct {
		ServerInfo ServerInfo `json:"io.modelcontextprotocol/serverInfo"`
	} `json:"_meta"`
	Instructions string `json:"instructions"`
}

func requestMeta(version string) map[string]any {
	return map[string]any{"_meta": map[string]any{
		"io.modelcontextprotocol/protocolVersion":    version,
		"io.modelcontextprotocol/clientInfo":         map[string]string{"name": "mcprism", "version": ClientVersion},
		"io.modelcontextprotocol/clientCapabilities": map[string]any{},
	}}
}

func selectVersion(versions []string) (string, bool) {
	for _, preferred := range []string{ModernVersion, PreferredVersion, "2025-06-18", "2025-03-26", "2024-11-05"} {
		for _, supported := range versions {
			if supported == preferred {
				return preferred, true
			}
		}
	}
	return "", false
}

func supportedVersions(data any) []string {
	encoded, err := json.Marshal(data)
	if err != nil {
		return nil
	}
	var detail struct {
		Supported []string `json:"supported"`
	}
	if json.Unmarshal(encoded, &detail) != nil {
		return nil
	}
	return detail.Supported
}

func incompatibleVersionError(versions []string) error {
	if len(versions) == 0 {
		return fmt.Errorf("MCP server does not support a protocol version mcprism can use")
	}
	return fmt.Errorf("MCP server supports protocol versions %v, but none are supported by mcprism", versions)
}

func (c *Client) setVersion(version string, modern bool) {
	c.version, c.modern = version, modern
	if setter, ok := c.tr.(interface{ setProtocolVersion(string) }); ok {
		setter.setProtocolVersion(version)
	}
}

func (c *Client) initializeLegacy(ctx context.Context, version string) (*InitializeResult, error) {
	c.setVersion(version, false)
	params := map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]string{"name": "mcprism", "version": ClientVersion},
	}
	raw, err := c.tr.call(ctx, c.nextID(), "initialize", params)
	if err != nil {
		return nil, err
	}
	var res InitializeResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("decode initialize: %w", err)
	}
	if res.ProtocolVersion != "" {
		c.setVersion(res.ProtocolVersion, false)
	}
	if err := c.tr.notify(ctx, "notifications/initialized", map[string]any{}); err != nil {
		return nil, fmt.Errorf("send initialized notification: %w", err)
	}
	return &res, nil
}

func (c *Client) call(ctx context.Context, method string, params map[string]any) (json.RawMessage, error) {
	if c.modern {
		metadata := requestMeta(c.version)["_meta"]
		params["_meta"] = metadata
	}
	return c.tr.call(ctx, c.nextID(), method, params)
}

// Tool 是一个 MCP 工具定义。
type Tool struct {
	Name         string          `json:"name"`
	Title        string          `json:"title,omitempty"`
	Description  string          `json:"description,omitempty"`
	InputSchema  json.RawMessage `json:"inputSchema,omitempty"`
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
	Annotations  json.RawMessage `json:"annotations,omitempty"`
}

// listAll 循环调用一个分页的列表方法，直到服务端不再返回 nextCursor。
// 不处理分页会漏掉后续页里的工具，而"看到空列表"可能只是枚举不完整。
func (c *Client) listAll(ctx context.Context, method, itemsField string, appendFn func(json.RawMessage) error) error {
	cursor := ""
	for page := 0; ; page++ {
		if page > 10000 {
			return fmt.Errorf("%s: pagination exceeded 10000 pages", method)
		}
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		raw, err := c.call(ctx, method, params)
		if err != nil {
			return err
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(raw, &body); err != nil {
			return fmt.Errorf("decode %s: %w", method, err)
		}
		items, ok := body[itemsField]
		if !ok {
			return fmt.Errorf("decode %s: missing %s array", method, itemsField)
		}
		if bytes.Equal(bytes.TrimSpace(items), []byte("null")) {
			return fmt.Errorf("decode %s.%s: expected an array, got null", method, itemsField)
		}
		var list []json.RawMessage
		if err := json.Unmarshal(items, &list); err != nil {
			return fmt.Errorf("decode %s.%s: %w", method, itemsField, err)
		}
		for _, it := range list {
			if err := appendFn(it); err != nil {
				return err
			}
		}
		next := ""
		if raw, ok := body["nextCursor"]; ok {
			_ = json.Unmarshal(raw, &next)
		}
		if next == "" {
			break
		}
		cursor = next
	}
	return nil
}

// ListTools 返回 server 暴露的全部工具（跨分页）。
func (c *Client) ListTools(ctx context.Context) ([]Tool, error) {
	var out []Tool
	err := c.listAll(ctx, "tools/list", "tools", func(raw json.RawMessage) error {
		var t Tool
		if err := json.Unmarshal(raw, &t); err != nil {
			return err
		}
		out = append(out, t)
		return nil
	})
	return out, err
}

// Resource 是一个 MCP 资源。
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mimeType,omitempty"`
}

// ResourceContent contains one text or binary resource payload.
type ResourceContent struct {
	URI      string `json:"uri"`
	MIMEType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
	Blob     string `json:"blob,omitempty"`
}

// ListResources 返回 server 暴露的全部资源（跨分页）。
func (c *Client) ListResources(ctx context.Context) ([]Resource, error) {
	var out []Resource
	err := c.listAll(ctx, "resources/list", "resources", func(raw json.RawMessage) error {
		var r Resource
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		out = append(out, r)
		return nil
	})
	return out, err
}

// ReadResource fetches one listed resource. Binary blobs are returned by the
// protocol layer but callers can choose not to inspect or persist them.
func (c *Client) ReadResource(ctx context.Context, uri string) ([]ResourceContent, error) {
	raw, err := c.call(ctx, "resources/read", map[string]any{"uri": uri})
	if err != nil {
		return nil, err
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("decode resources/read: %w", err)
	}
	items, ok := body["contents"]
	if !ok || bytes.Equal(bytes.TrimSpace(items), []byte("null")) {
		return nil, fmt.Errorf("decode resources/read: missing contents array")
	}
	var contents []ResourceContent
	if err := json.Unmarshal(items, &contents); err != nil {
		return nil, fmt.Errorf("decode resources/read.contents: %w", err)
	}
	return contents, nil
}

// PromptArgument 是 prompt 的参数声明。
type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// Prompt 是一个 MCP 提示模板。
type Prompt struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

// PromptMessage is one rendered message from prompts/get.
type PromptMessage struct {
	Role    string               `json:"role"`
	Content PromptMessageContent `json:"content"`
}

// PromptMessageContent retains text and embedded resource text. Other content
// types are represented by their type tag and are intentionally not decoded.
type PromptMessageContent struct {
	Type     string           `json:"type"`
	Text     string           `json:"text,omitempty"`
	Resource *ResourceContent `json:"resource,omitempty"`
}

// PromptResult is a rendered prompt instance.
type PromptResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

// ListPrompts 返回 server 暴露的全部提示模板（跨分页）。
func (c *Client) ListPrompts(ctx context.Context) ([]Prompt, error) {
	var out []Prompt
	err := c.listAll(ctx, "prompts/list", "prompts", func(raw json.RawMessage) error {
		var p Prompt
		if err := json.Unmarshal(raw, &p); err != nil {
			return err
		}
		out = append(out, p)
		return nil
	})
	return out, err
}

// GetPrompt renders one prompt with the supplied string arguments.
func (c *Client) GetPrompt(ctx context.Context, name string, args map[string]string) (*PromptResult, error) {
	params := map[string]any{"name": name}
	if len(args) > 0 {
		params["arguments"] = args
	}
	raw, err := c.call(ctx, "prompts/get", params)
	if err != nil {
		return nil, err
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("decode prompts/get: %w", err)
	}
	messages, ok := body["messages"]
	if !ok || bytes.Equal(bytes.TrimSpace(messages), []byte("null")) {
		return nil, fmt.Errorf("decode prompts/get: missing messages array")
	}
	var result PromptResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("decode prompts/get.messages: %w", err)
	}
	return &result, nil
}

// Ping 发送 ping 心跳。
func (c *Client) Ping(ctx context.Context) error {
	if c.modern {
		return fmt.Errorf("ping is not part of MCP protocol version %s", c.version)
	}
	_, err := c.call(ctx, "ping", map[string]any{})
	return err
}
