package protocol

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/HUA503/mcprism/internal/config"
)

// newHTTPTransport 创建基于 HTTP 的传输；legacy 为 true 时使用旧版 SSE 模式。
func newHTTPTransport(srv *config.Server, legacy bool) (transport, error) {
	if srv.URL == "" {
		return nil, fmt.Errorf("server %q has no url", srv.Name)
	}
	if legacy {
		t := &legacySSETransport{
			url:         srv.URL,
			headers:     srv.Headers,
			client:      &http.Client{},
			pending:     map[int64]chan callResult{},
			closed:      make(chan struct{}),
			gotEndpoint: make(chan struct{}),
		}
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		if err := t.connect(ctx); err != nil {
			return nil, err
		}
		return t, nil
	}
	return &httpTransport{
		url:     srv.URL,
		headers: srv.Headers,
		client:  &http.Client{},
	}, nil
}

// ---------- Streamable HTTP ----------

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
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(body))
	if err != nil {
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

	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		t.mu.Lock()
		t.session = sid
		t.mu.Unlock()
	}

	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		return parseSSEResponse(resp.Body)
	}
	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
		return &RPCResponse{}, nil // 通知被接受
	}
	var rpcResp RPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, fmt.Errorf("decode http response (status %d): %w", resp.StatusCode, err)
	}
	return &rpcResp, nil
}

func (t *httpTransport) close() error { return nil }

// parseSSEResponse 从 SSE 流中提取 JSON-RPC 消息。
func parseSSEResponse(r io.Reader) (*RPCResponse, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	var dataBuf bytes.Buffer
	var last *RPCResponse
	flush := func() {
		if dataBuf.Len() == 0 {
			return
		}
		var rpcResp RPCResponse
		if err := json.Unmarshal(dataBuf.Bytes(), &rpcResp); err == nil {
			last = &rpcResp
		}
		dataBuf.Reset()
	}
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "data:"):
			payload := strings.TrimPrefix(line, "data:")
			payload = strings.TrimPrefix(payload, " ")
			if dataBuf.Len() > 0 {
				dataBuf.WriteByte('\n')
			}
			dataBuf.WriteString(payload)
		case line == "":
			flush()
		}
	}
	flush()
	if last == nil {
		return nil, fmt.Errorf("no JSON-RPC message in SSE stream")
	}
	return last, nil
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
}

func (t *legacySSETransport) connect(ctx context.Context) error {
	streamCtx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel

	req, _ := http.NewRequestWithContext(streamCtx, http.MethodGet, t.url, nil)
	req.Header.Set("Accept", "text/event-stream")
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		cancel()
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
	case <-ctx.Done():
		cancel()
		return fmt.Errorf("timeout waiting for SSE endpoint event")
	case <-t.closed:
		cancel()
		return fmt.Errorf("sse stream closed before endpoint event")
	}
}

func (t *legacySSETransport) readLoop(body io.ReadCloser) {
	defer body.Close()
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	var eventType string
	var dataBuf bytes.Buffer
	dispatch := func() {
		if dataBuf.Len() == 0 {
			eventType = ""
			return
		}
		data := dataBuf.String()
		dataBuf.Reset()
		if eventType == "endpoint" {
			base, _ := url.Parse(t.url)
			ref, err := url.Parse(strings.TrimSpace(data))
			if err == nil {
				t.mu.Lock()
				t.postURL = base.ResolveReference(ref).String()
				t.mu.Unlock()
				t.endpointOnce.Do(func() { close(t.gotEndpoint) })
			}
			eventType = ""
			return
		}
		var rpcResp RPCResponse
		if err := json.Unmarshal([]byte(data), &rpcResp); err == nil && len(rpcResp.ID) > 0 {
			var id int64
			if json.Unmarshal(rpcResp.ID, &id) == nil {
				t.deliver(id, rpcResp)
			}
		}
		eventType = ""
	}

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event:"):
			eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			if dataBuf.Len() > 0 {
				dataBuf.WriteByte('\n')
			}
			dataBuf.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		case line == "":
			dispatch()
		}
	}
	select {
	case <-t.closed:
	default:
		close(t.closed)
	}
	t.failAll(fmt.Errorf("legacy sse stream closed"))
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
	body, _ := json.Marshal(req)
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
