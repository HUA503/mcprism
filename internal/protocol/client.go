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
const ClientVersion = "0.1.0"

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

// ListTools 返回 server 暴露的全部工具。
func (c *Client) ListTools(ctx context.Context) ([]Tool, error) {
	raw, err := c.tr.call(ctx, c.nextID(), "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	var out struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode tools/list: %w", err)
	}
	return out.Tools, nil
}

// Resource 是一个 MCP 资源。
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mimeType,omitempty"`
}

// ListResources 返回 server 暴露的全部资源。
func (c *Client) ListResources(ctx context.Context) ([]Resource, error) {
	raw, err := c.tr.call(ctx, c.nextID(), "resources/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	var out struct {
		Resources []Resource `json:"resources"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode resources/list: %w", err)
	}
	return out.Resources, nil
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

// ListPrompts 返回 server 暴露的全部提示模板。
func (c *Client) ListPrompts(ctx context.Context) ([]Prompt, error) {
	raw, err := c.tr.call(ctx, c.nextID(), "prompts/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	var out struct {
		Prompts []Prompt `json:"prompts"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode prompts/list: %w", err)
	}
	return out.Prompts, nil
}

// Ping 发送 ping 心跳。
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.tr.call(ctx, c.nextID(), "ping", map[string]any{})
	return err
}
