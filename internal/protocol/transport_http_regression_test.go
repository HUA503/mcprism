package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HUA503/mcprism/internal/config"
)

type observedReader struct {
	read bool
	err  error
}

func (r *observedReader) Read([]byte) (int, error) {
	r.read = true
	return 0, r.err
}

func TestParseSSEReturnsBeforeStreamCloses(t *testing.T) {
	tail := &observedReader{err: errors.New("stream is still open")}
	stream := io.MultiReader(strings.NewReader("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"), tail)
	if _, err := parseSSEResponse(stream, 1); err != nil {
		t.Fatal(err)
	}
	if tail.read {
		t.Fatal("read beyond the matching event; a persistent SSE stream would hang")
	}
}

func TestParseSSENotificationDoesNotReadBody(t *testing.T) {
	r := &observedReader{err: errors.New("no response is expected")}
	if _, err := parseSSEResponse(r, 0); err != nil {
		t.Fatal(err)
	}
	if r.read {
		t.Fatal("a notification must not wait for an SSE response")
	}
}

func TestParseSSEPropagatesReadError(t *testing.T) {
	want := errors.New("interrupted stream")
	if _, err := parseSSEResponse(&observedReader{err: want}, 1); !errors.Is(err, want) {
		t.Fatalf("want wrapped read error, got %v", err)
	}
}

func TestParseSSEBoundsMultilineEvents(t *testing.T) {
	// Each line fits the scanner limit, but the complete event is too large.
	stream := strings.Repeat("data: "+strings.Repeat(" ", 256*1024)+"\n", 65) + "\n"
	if _, err := parseSSEResponse(strings.NewReader(stream), 1); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("want event size limit error, got %v", err)
	}
}

type responseTransport func(*http.Request) (*http.Response, error)

func (f responseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestHTTPRejectsInvalidResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"wrong id", 200, `{"jsonrpc":"2.0","id":2,"result":{}}`},
		{"missing id", 200, `{"jsonrpc":"2.0","result":{}}`},
		{"error status", 500, `{"jsonrpc":"2.0","id":1,"result":{}}`},
		{"missing result", 202, ``},
		{"oversized body", 200, `{"jsonrpc":"2.0","id":1,"result":"` + strings.Repeat("x", 16*1024*1024) + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &httpTransport{
				url: "https://mcp.example/mcp",
				client: &http.Client{Transport: responseTransport(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: tc.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body))}, nil
				})},
			}
			if _, err := tr.call(context.Background(), 1, "tools/list", nil); err == nil {
				t.Fatal("expected invalid response to be rejected")
			}
		})
	}
}

func TestHTTPAcceptsMatchingResponseAndNotification(t *testing.T) {
	tr := &httpTransport{
		url: "https://mcp.example/mcp",
		client: &http.Client{Transport: responseTransport(func(req *http.Request) (*http.Response, error) {
			var rpc RPCRequest
			if err := json.NewDecoder(req.Body).Decode(&rpc); err != nil {
				return nil, err
			}
			status, body := http.StatusOK, `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`
			if rpc.ID == nil {
				status, body = http.StatusAccepted, ""
			}
			return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
		})},
	}
	if _, err := tr.call(context.Background(), 1, "tools/list", nil); err != nil {
		t.Fatal(err)
	}
	if err := tr.notify(context.Background(), "notifications/initialized", nil); err != nil {
		t.Fatal(err)
	}
}

func TestLegacySSEEndpointOrigin(t *testing.T) {
	for _, tc := range []struct {
		name     string
		endpoint string
		allowed  bool
	}{
		{"relative", "/messages?session=1", true},
		{"same origin", "https://mcp.example/messages", true},
		{"default port", "https://mcp.example:443/messages", true},
		{"other host", "https://other.example/messages", false},
		{"other port", "https://mcp.example:8443/messages", false},
		{"downgrade", "http://mcp.example/messages", false},
		{"metadata", "http://169.254.169.254/messages", false},
		{"userinfo", "https://user:pass@mcp.example/messages", false},
		{"invalid", "%", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &legacySSETransport{
				url: "https://mcp.example/sse", pending: make(map[int64]chan callResult),
				closed: make(chan struct{}), gotEndpoint: make(chan struct{}),
			}
			tr.readLoop(io.NopCloser(strings.NewReader("event: endpoint\ndata: " + tc.endpoint + "\n\n")))
			if got := tr.postURL != ""; got != tc.allowed {
				t.Fatalf("endpoint accepted = %v, want %v", got, tc.allowed)
			}
		})
	}
}

func TestHTTPDialRejectsInvalidURL(t *testing.T) {
	for _, raw := range []string{"%", "file:///tmp/mcp", "http:///missing-host"} {
		for _, transport := range []config.Transport{config.TransportHTTP, config.TransportSSE} {
			if c, err := Dial(context.Background(), &config.Server{URL: raw, Transport: transport}); err == nil {
				c.Close()
				t.Errorf("expected invalid URL %q to fail for %s", raw, transport)
			}
		}
	}
}

func TestLegacySSEDialHonorsCanceledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Dial(ctx, &config.Server{URL: srv.URL, Transport: config.TransportSSE}); !errors.Is(err, context.Canceled) {
		t.Fatalf("want canceled context, got %v", err)
	}
}

type initializeTransport struct {
	notifyErr error
	notifyCtx context.Context
}

func (*initializeTransport) call(context.Context, int64, string, any) (json.RawMessage, error) {
	return json.RawMessage(`{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"test","version":"1"}}`), nil
}

func (tr *initializeTransport) notify(ctx context.Context, _ string, _ any) error {
	tr.notifyCtx = ctx
	return tr.notifyErr
}

func (*initializeTransport) close() error { return nil }

func TestInitializeUsesCallerContextForNotification(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tr := &initializeTransport{}
	if _, err := (&Client{tr: tr}).Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if tr.notifyCtx != ctx {
		t.Fatal("initialized notification discarded the caller's context")
	}
}

func TestInitializePropagatesNotificationFailure(t *testing.T) {
	want := errors.New("notification failed")
	tr := &initializeTransport{notifyErr: want}
	if _, err := (&Client{tr: tr}).Initialize(context.Background()); !errors.Is(err, want) {
		t.Fatalf("want notification error, got %v", err)
	}
}

func TestHTTPResponseOnPersistentSSEStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := Dial(ctx, &config.Server{URL: srv.URL, Transport: config.TransportHTTP})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	done := make(chan error, 1)
	go func() { _, err := c.ListTools(ctx); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("matching SSE response was not returned while the stream stayed open")
	}
}

func TestLegacySSESessionSurvivesDial(t *testing.T) {
	events := make(chan []byte, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "event: endpoint\ndata: /messages\n\n")
			w.(http.Flusher).Flush()
			for {
				select {
				case data := <-events:
					fmt.Fprintf(w, "event: message\ndata: %s\n\n", data)
					w.(http.Flusher).Flush()
				case <-r.Context().Done():
					return
				}
			}
		}
		var req RPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.ID != nil {
			var result any = map[string]any{"tools": []any{}}
			if req.Method == "initialize" {
				result = map[string]any{"protocolVersion": PreferredVersion, "capabilities": map[string]any{}, "serverInfo": ServerInfo{Name: "test", Version: "1"}}
			}
			data, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
			select {
			case events <- data:
			case <-r.Context().Done():
				return
			}
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := Dial(ctx, &config.Server{URL: srv.URL + "/sse", Transport: config.TransportSSE})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListTools(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPMetadataIsRejectedBeforeProxy(t *testing.T) {
	for _, raw := range []string{
		"http://169.254.169.254/mcp", "http://100.100.100.200/mcp",
		"http://metadata.google.internal./mcp", "http://[fe80::1%25eth0]/mcp",
	} {
		t.Run(raw, func(t *testing.T) {
			called := false
			tr := &httpTransport{
				url: raw,
				client: &http.Client{Transport: responseTransport(func(*http.Request) (*http.Response, error) {
					called = true
					return nil, errors.New("must not contact the proxy")
				})},
			}
			if _, err := tr.call(context.Background(), 1, "initialize", nil); err == nil {
				t.Fatal("expected metadata destination to be blocked")
			}
			if called {
				t.Fatal("blocked destination reached the proxy transport")
			}
		})
	}
}

func TestLegacySSEPreservesConfiguredURLCredentials(t *testing.T) {
	base := "https://user:pass@mcp.example/sse"
	endpoint, err := resolveSSEEndpoint(base, "/messages")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolveSSEEndpoint(base, endpoint); err != nil {
		t.Fatalf("validated endpoint must remain usable for POST: %v", err)
	}
}
