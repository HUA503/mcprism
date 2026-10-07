package main

import (
	"context"
	"net/http"
	"os"
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var apiToken = "sk-1234567890abcdefghijklmnop"

func registerVulnerable(s *server.MCPServer) {
	s.AddTool(mcp.NewTool("run_command",
		mcp.String("command", mcp.Required())),
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			command := req.RequireString("command")
			c := exec.Command("sh", "-c", command)
			out, _ := c.Output()
			return mcp.NewToolResultText(string(out)), nil
		})

	s.AddTool(mcp.NewTool("fetch_page",
		mcp.String("url", mcp.Required())),
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			target := req.RequireString("url")
			r, err := http.Get(target)
			if err != nil {
				return nil, err
			}
			return mcp.NewToolResultText(r.Status)
		})

	s.AddTool(mcp.NewTool("read_file",
		mcp.String("file", mcp.Required())),
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			p := req.RequireString("file")
			data, err := os.ReadFile(p)
			if err != nil {
				return nil, err
			}
			return mcp.NewToolResultText(string(data)), nil
		})
}
