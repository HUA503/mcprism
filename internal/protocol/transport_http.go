package protocol

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/HUA503/mcprism/internal/config"
)

// streamingHTTPClient bounds the connection and header phases but leaves the
// response body open, so a long-lived SSE stream is not cut off. The dialer
// enforces the egress guard (no link-local/cloud-metadata targets, including
// hosts that resolve to them), and redirects are confined to the same host.
func streamingHTTPClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: egressControl,
	}
	return &http.Client{
		CheckRedirect: safeCheckRedirect,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
		},
	}
}

// defaultHTTPClient adds an overall timeout for request/response calls.
func defaultHTTPClient() *http.Client {
	c := streamingHTTPClient()
	c.Timeout = 30 * time.Second
	return c
}

// newHTTPTransport 创建基于 HTTP 的传输；legacy 为 true 时使用旧版 SSE 模式。
func newHTTPTransport(ctx context.Context, srv *config.Server, legacy bool) (transport, error) {
	if srv.URL == "" {
		return nil, fmt.Errorf("server %q has no url", srv.Name)
	}
	u, err := url.Parse(srv.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid MCP server URL: %w", err)
	}
	if err := validateProbeURL(u); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if legacy {
		t := &legacySSETransport{
			url:         srv.URL,
			headers:     srv.Headers,
			client:      streamingHTTPClient(),
			pending:     map[int64]chan callResult{},
			closed:      make(chan struct{}),
			gotEndpoint: make(chan struct{}),
		}
		if err := t.connect(ctx); err != nil {
			return nil, err
		}
		return t, nil
	}
	return &httpTransport{
		url:     srv.URL,
		headers: srv.Headers,
		client:  defaultHTTPClient(),
	}, nil
}

// ---------- Streamable HTTP ----------

const maxRPCMessageSize = 16 * 1024 * 1024

type httpTransport struct {
	url     string
	headers map[string]string
	client  *http.Client
	mu      sync.Mutex
	session string
}

func (t *httpTransport) call(ctx context.Context, id int64, method string, params any) (json.RawMessage, error) {
	resp, err := t.roundTrip(ctx, RPCRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	return resp.Result, nil
}

func (t *httpTransport) notify(ctx context.Context, method string, params any) error {
	_, err := t.roundTrip(ctx, RPCRequest{JSONRPC: "2.0", Method: method, Params: params})
	return err
}

func (t *httpTransport) roundTrip(ctx context.Context, req RPCRequest) (*RPCResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode HTTP request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if err := validateProbeURL(httpReq.URL); err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range t.headers {
		httpReq.Header.Set(k, v)
	}
	t.mu.Lock()
	if t.session != "" {
		httpReq.Header.Set("Mcp-Session-Id", t.session)
	}
	t.mu.Unlock()

	resp, err := t.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("MCP HTTP request returned status %d", resp.StatusCode)
	}

	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		t.mu.Lock()
		t.session = sid
		t.mu.Unlock()
	}

	// A notification has no response, even if the server keeps its body open.
	if req.ID == nil {
		return &RPCResponse{}, nil
	}
	wantID, _ := req.ID.(int64)
	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		return parseSSEResponse(resp.Body, wantID)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRPCMessageSize+1))
	if err != nil {
		return nil, fmt.Errorf("read HTTP response: %w", err)
	}
	if len(data) > maxRPCMessageSize {
		return nil, fmt.Errorf("HTTP response exceeds %d byte limit", maxRPCMessageSize)
	}
	var rpcResp RPCResponse
	if err := json.Unmarshal(data, &rpcResp); err != nil {
		return nil, fmt.Errorf("decode http response (status %d): %w", resp.StatusCode, err)
	}
	if !matchesRPCResponse(&rpcResp, wantID) {
		return nil, fmt.Errorf("HTTP response is not a JSON-RPC response for request id %d", wantID)
	}
	return &rpcResp, nil
}

func (t *httpTransport) close() error { return nil }

func matchesRPCResponse(resp *RPCResponse, wantID int64) bool {
	var id int64
	return resp.JSONRPC == "2.0" && json.Unmarshal(resp.ID, &id) == nil && id == wantID &&
		(len(resp.Result) > 0 || resp.Error != nil)
}

// parseSSEResponse extracts the JSON-RPC response for wantID from an SSE
// stream. Streamable HTTP servers may interleave notifications and progress
// events, so the last message is not necessarily ours: messages are matched by
// request id. wantID 0 is a notification, which carries no result.
func parseSSEResponse(r io.Reader, wantID int64) (*RPCResponse, error) {
	if wantID == 0 {
		return &RPCResponse{}, nil
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxRPCMessageSize)
	var dataBuf bytes.Buffer
	flush := func() *RPCResponse {
		if dataBuf.Len() == 0 {
			return nil
		}
		var rpcResp RPCResponse
		err := json.Unmarshal(dataBuf.Bytes(), &rpcResp)
		dataBuf.Reset()
		if err == nil && matchesRPCResponse(&rpcResp, wantID) {
			return &rpcResp
		}
		return nil
	}
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "data:"):
			payload := strings.TrimPrefix(line, "data:")
			payload = strings.TrimPrefix(payload, " ")
			if dataBuf.Len()+len(payload)+1 > maxRPCMessageSize {
				return nil, fmt.Errorf("SSE event exceeds %d byte limit", maxRPCMessageSize)
			}
			if dataBuf.Len() > 0 {
				dataBuf.WriteByte('\n')
			}
			dataBuf.WriteString(payload)
		case line == "":
			if resp := flush(); resp != nil {
				return resp, nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read SSE response: %w", err)
	}
	if resp := flush(); resp != nil {
		return resp, nil
	}
	return nil, fmt.Errorf("no JSON-RPC response for id %d in SSE stream", wantID)
}

// ---------- Legacy HTTP+SSE ----------

type legacySSETransport struct {
	url          string
	postURL      string
	headers      map[string]string
	client       *http.Client
	cancel       context.CancelFunc
	mu           sync.Mutex
	pending      map[int64]chan callResult
	closed       chan struct{}
	gotEndpoint  chan struct{}
	endpointOnce sync.Once
	readErr      error // protected by mu; recorded before closed is signaled
}

func (t *legacySSETransport) connect(ctx context.Context) error {
	streamCtx, cancel := context.WithCancel(ctx)
	t.cancel = cancel
	// Bound setup without imposing a lifetime limit on an established stream.
	setupCtx, setupCancel := context.WithTimeout(ctx, 12*time.Second)
	stopSetup := context.AfterFunc(setupCtx, cancel)
	defer func() { stopSetup(); setupCancel() }()

	req, err := http.NewRequestWithContext(streamCtx, http.MethodGet, t.url, nil)
	if err != nil {
		cancel()
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		cancel()
		if setupCtx.Err() != nil {
			return setupCtx.Err()
		}
		return err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancel()
		return fmt.Errorf("sse connect returned status %d", resp.StatusCode)
	}
	go t.readLoop(resp.Body)

	select {
	case <-t.gotEndpoint:
		return nil
	case <-setupCtx.Done():
		cancel()
		return fmt.Errorf("waiting for SSE endpoint event: %w", setupCtx.Err())
	case <-t.closed:
		cancel()
		t.mu.Lock()
		err := t.readErr
		t.mu.Unlock()
		return fmt.Errorf("sse stream closed before endpoint event: %w", err)
	}
}

func (t *legacySSETransport) readLoop(body io.ReadCloser) {
	defer body.Close()
	streamErr := fmt.Errorf("legacy sse stream closed")
	defer func() {
		t.mu.Lock()
		t.readErr = streamErr
		t.mu.Unlock()
		close(t.closed)
		t.failAll(streamErr)
	}()
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), maxRPCMessageSize)

	var eventType string
	var dataBuf bytes.Buffer
	dispatch := func() error {
		if dataBuf.Len() == 0 {
			eventType = ""
			return nil
		}
		data := dataBuf.String()
		dataBuf.Reset()
		if eventType == "endpoint" {
			endpoint, err := resolveSSEEndpoint(t.url, data)
			if err != nil {
				return err
			}
			t.mu.Lock()
			t.postURL = endpoint
			t.mu.Unlock()
			t.endpointOnce.Do(func() { close(t.gotEndpoint) })
			eventType = ""
			return nil
		}
		var rpcResp RPCResponse
		if err := json.Unmarshal([]byte(data), &rpcResp); err == nil && len(rpcResp.ID) > 0 {
			var id int64
			if json.Unmarshal(rpcResp.ID, &id) == nil {
				t.deliver(id, rpcResp)
			}
		}
		eventType = ""
		return nil
	}

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event:"):
			eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			payload := strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " ")
			if dataBuf.Len()+len(payload)+1 > maxRPCMessageSize {
				streamErr = fmt.Errorf("SSE event exceeds %d byte limit", maxRPCMessageSize)
				return
			}
			if dataBuf.Len() > 0 {
				dataBuf.WriteByte('\n')
			}
			dataBuf.WriteString(payload)
		case line == "":
			if err := dispatch(); err != nil {
				streamErr = err
				return
			}
		}
	}
	if err := scanner.Err(); err != nil {
		streamErr = fmt.Errorf("read legacy SSE stream: %w", err)
	}
}

// An endpoint event is server-controlled, not an authorization to send the
// configured credentials to a different origin or over cleartext HTTP.
func resolveSSEEndpoint(baseURL, endpoint string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid SSE base URL: %w", err)
	}
	ref, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return "", fmt.Errorf("invalid SSE endpoint: %w", err)
	}
	u := base.ResolveReference(ref)
	if err := validateProbeURL(u); err != nil {
		return "", err
	}
	if (u.User != nil && (base.User == nil || u.User.String() != base.User.String())) || !sameHTTPOrigin(base, u) {
		return "", fmt.Errorf("mcprism egress guard: refusing cross-origin or credential-bearing SSE endpoint")
	}
	return u.String(), nil
}

func (t *legacySSETransport) deliver(id int64, resp RPCResponse) {
	t.mu.Lock()
	ch, ok := t.pending[id]
	if ok {
		delete(t.pending, id)
	}
	t.mu.Unlock()
	if !ok {
		return
	}
	if resp.Error != nil {
		ch <- callResult{err: resp.Error}
	} else {
		ch <- callResult{raw: resp.Result}
	}
}

func (t *legacySSETransport) post(ctx context.Context, req RPCRequest) error {
	t.mu.Lock()
	postURL := t.postURL
	t.mu.Unlock()
	if postURL == "" {
		return fmt.Errorf("legacy sse endpoint not yet known")
	}
	if _, err := resolveSSEEndpoint(t.url, postURL); err != nil {
		return err
	}
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("encode legacy SSE request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, postURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range t.headers {
		httpReq.Header.Set(k, v)
	}
	resp, err := t.client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("legacy sse post returned status %d", resp.StatusCode)
	}
	return nil
}

func (t *legacySSETransport) call(ctx context.Context, id int64, method string, params any) (json.RawMessage, error) {
	ch := make(chan callResult, 1)
	t.mu.Lock()
	t.pending[id] = ch
	t.mu.Unlock()

	if err := t.post(ctx, RPCRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params}); err != nil {
		t.remove(id)
		return nil, err
	}
	select {
	case r := <-ch:
		return r.raw, r.err
	case <-ctx.Done():
		t.remove(id)
		return nil, ctx.Err()
	case <-t.closed:
		t.remove(id)
		return nil, fmt.Errorf("legacy sse connection closed")
	}
}

func (t *legacySSETransport) notify(ctx context.Context, method string, params any) error {
	return t.post(ctx, RPCRequest{JSONRPC: "2.0", Method: method, Params: params})
}

func (t *legacySSETransport) remove(id int64) {
	t.mu.Lock()
	delete(t.pending, id)
	t.mu.Unlock()
}

func (t *legacySSETransport) failAll(err error) {
	t.mu.Lock()
	chans := t.pending
	t.pending = map[int64]chan callResult{}
	t.mu.Unlock()
	for _, ch := range chans {
		select {
		case ch <- callResult{err: err}:
		default:
		}
	}
}

func (t *legacySSETransport) close() error {
	if t.cancel != nil {
		t.cancel()
	}
	return nil
}
