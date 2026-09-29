package config

import "testing"

func TestParseObjectForm(t *testing.T) {
	data := []byte(`{
		"mcpServers": {
			"fs": {"command":"npx","args":["-y","fs","/"],"env":{"A":"b"}},
			"remote": {"url":"https://example.com/mcp"}
		}
	}`)
	servers, err := ParseBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 2 {
		t.Fatalf("want 2 servers, got %d", len(servers))
	}
	if servers[0].Transport != TransportStdio || servers[0].Command != "npx" {
		t.Fatalf("unexpected stdio server: %+v", servers[0])
	}
	if servers[1].Transport != TransportHTTP {
		t.Fatalf("want http transport, got %s", servers[1].Transport)
	}
}

func TestParseArrayForm(t *testing.T) {
	data := []byte(`{"mcpServers":{"x":["npx","-y","pkg"]}}`)
	servers, err := ParseBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 || servers[0].Command != "npx" || len(servers[0].Args) != 2 {
		t.Fatalf("array form parse failed: %+v", servers)
	}
}

func TestParseJSONC(t *testing.T) {
	data := []byte(`{
		// a line comment
		"mcpServers": { /* block comment */ "x":{"command":"echo"} }
	}`)
	servers, err := ParseBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("want 1 server, got %d", len(servers))
	}
}

func TestLegacySSEType(t *testing.T) {
	data := []byte(`{"servers":{"old":{"type":"sse","url":"http://localhost:8080/sse"}}}`)
	servers, err := ParseBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 || servers[0].Transport != TransportSSE {
		t.Fatalf("want sse transport, got %+v", servers)
	}
}
