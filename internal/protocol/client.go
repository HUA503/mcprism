// Package protocol 是一个精简的 Model Context Protocol（MCP）客户端实现，
// 支持 stdio、Streamable HTTP 与旧版 SSE 三种传输，用于连接并枚举任意 MCP server
// 暴露的 tools、resources、prompts，为安全审查提供真实的运行时能力清单。
package protocol

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/HUA503/mcprism/internal/config"
)

// PreferredVersion 是客户端发起握手时请求的协议版本。
const PreferredVersion = "2025-06-18"

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
	tr    transport
	once  sync.Once
	idSeq int64
}

// Dial 根据 server 配置建立 MCP 会话。
func Dial(ctx context.Context, srv *config.Server) (*Client, error) {
	var t transport
	var err error
	switch srv.Transport {
	case config.TransportStdio:
		t, err = newStdioTransport(ctx, srv)
	case config.TransportHTTP:
		t, err = newHTTPTransport(srv, false)
	case config.TransportSSE:
		t, err = newHTTPTransport(srv, true)
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

// InitializeResult 是 initialize 的返回。
type InitializeResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ServerInfo      ServerInfo     `json:"serverInfo"`
	Instructions    string         `json:"instructions,omitempty"`
}

// Initialize 执行 MCP 握手并发送 initialized 通知。
func (c *Client) Initialize(ctx context.Context) (*InitializeResult, error) {
	params := map[string]any{
		"protocolVersion": PreferredVersion,
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
	_ = c.tr.notify(context.Background(), "notifications/initialized", map[string]any{})
	return &res, nil
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
		raw, err := c.tr.call(ctx, c.nextID(), method, params)
		if err != nil {
			return err
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(raw, &body); err != nil {
			return fmt.Errorf("decode %s: %w", method, err)
		}
		if items, ok := body[itemsField]; ok {
			var list []json.RawMessage
			if err := json.Unmarshal(items, &list); err != nil {
				return fmt.Errorf("decode %s.%s: %w", method, itemsField, err)
			}
			for _, it := range list {
				if err := appendFn(it); err != nil {
					return err
				}
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

// Ping 发送 ping 心跳。
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.tr.call(ctx, c.nextID(), "ping", map[string]any{})
	return err
}
