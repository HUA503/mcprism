package main

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerSafe(s *server.MCPServer) {
	// Fixed command with constant arguments, no shell.
	s.AddTool(mcp.NewTool("git_status"),
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			out, err := exec.Command("git", "status").Output()
			if err != nil {
				return nil, err
			}
			return mcp.NewToolResultText(string(out)), nil
		})

	// Constant URL; the agent cannot choose the host.
	s.AddTool(mcp.NewTool("fetch_doc"),
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			r, err := http.Get("https://docs.example.com/v1/items")
			if err != nil {
				return nil, err
			}
			return mcp.NewToolResultText(r.Status)
		})

	// Path confined to a base directory with a prefix check.
	s.AddTool(mcp.NewTool("read_file",
		mcp.String("name", mcp.Required())),
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			name := req.RequireString("name")
			base := "/var/data"
			p := filepath.Join(base, name)
			if !strings.HasPrefix(p, base) {
				return nil, os.ErrPermission
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return nil, err
			}
			return mcp.NewToolResultText(string(data)), nil
		})
}
