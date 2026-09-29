// Command mcprism 是一个零依赖、单二进制的 MCP（Model Context Protocol）
// 安全审查工具：自动发现并连接你各个 AI 客户端配置的 MCP server，枚举其真实能力，
// 检测提示注入、工具投毒、权限过宽、供应链与跨 server 攻击，并输出
// table / json / sarif / markdown / html 报告。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/HUA503/mcprism/internal/config"
	"github.com/HUA503/mcprism/internal/protocol"
	"github.com/HUA503/mcprism/internal/report"
	"github.com/HUA503/mcprism/internal/rules"
	"github.com/HUA503/mcprism/internal/tui"
	"github.com/spf13/cobra"
)

const version = "0.1.0"

func main() {
	root := &cobra.Command{
		Use:   "mcprism",
		Short: "Vet MCP servers before your AI trusts them",
		Long: "mcprism discovers, connects to and audits the MCP (Model Context Protocol) " +
			"servers configured across your AI clients, mapping every finding to the OWASP MCP Top 10.",
	}
	root.AddCommand(scanCmd(), inspectCmd(), versionCmd())
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the mcprism version",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println("mcprism", version)
		},
	}
}

// ---------- scan ----------

func scanCmd() *cobra.Command {
	var (
		format    string
		output    string
		timeout   time.Duration
		noDynamic bool
		failOn    string
		interact  bool
		project   string
		transport string
	)
	cmd := &cobra.Command{
		Use:   "scan [target]",
		Short: "Discover and audit MCP servers",
		Long: "Scan MCP servers. A target may be a client config file or an http(s) server URL; " +
			"with no target, mcprism auto-discovers configurations across all installed AI clients.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			target := ""
			if len(args) == 1 {
				target = args[0]
			}
			projectDir := project
			if projectDir == "" {
				projectDir, _ = os.Getwd()
			}

			servers, files, err := collectServers(target, projectDir, transport)
			if err != nil {
				return err
			}
			if len(servers) == 0 {
				return fmt.Errorf("no MCP servers found (use a config file or a server URL)")
			}

			inputs := make([]rules.Input, 0, len(servers))
			for _, srv := range servers {
				if noDynamic {
					inputs = append(inputs, rules.Input{Server: srv})
					continue
				}
				inputs = append(inputs, probeServer(context.Background(), srv, timeout))
			}

			results := rules.AnalyzeAll(inputs)

			if interact {
				if err := tui.Run(results); err != nil {
					return fmt.Errorf("interactive mode requires a real terminal; rerun without -i for non-interactive output: %w", err)
				}
				return nil
			}

			generated := time.Now().Format(time.RFC3339)
			rep := report.Build(results, files, version, generated)
			out, err := renderReport(rep, format)
			if err != nil {
				return err
			}
			if output != "" {
				if err := os.WriteFile(output, out, 0o644); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "report written to %s\n", output)
			} else {
				fmt.Print(string(out))
			}

			if failOn != "" && reaches(rep, failOn) {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table|json|sarif|md|html")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write report to a file instead of stdout")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "per-server connection timeout")
	cmd.Flags().BoolVar(&noDynamic, "no-dynamic", false, "only statically analyze configs; do not connect to servers")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "exit non-zero when a finding of this severity exists (critical|high|medium|low)")
	cmd.Flags().BoolVarP(&interact, "interactive", "i", false, "open the interactive terminal UI")
	cmd.Flags().StringVar(&project, "project", "", "project directory for project-level config discovery")
	cmd.Flags().StringVar(&transport, "transport", "", "force transport for a URL target: http|sse")
	return cmd
}

// ---------- inspect ----------

func inspectCmd() *cobra.Command {
	var (
		format  string
		timeout time.Duration
	)
	cmd := &cobra.Command{
		Use:   "inspect [target]",
		Short: "Connect and list a server's tools, resources and prompts",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			servers, _, err := collectServers(args[0], "", "")
			if err != nil {
				return err
			}
			in := probeServer(context.Background(), servers[0], timeout)
			if in.ConnectErr != nil {
				return in.ConnectErr
			}
			if format == "json" {
				b, _ := jsonMarshalIndent(in)
				fmt.Println(string(b))
				return nil
			}
			printInspection(in)
			return nil
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table|json")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "connection timeout")
	return cmd
}

func printInspection(in rules.Input) {
	srv := in.Server
	info := ""
	if in.Init != nil {
		info = fmt.Sprintf("%s v%s · protocol %s",
			in.Init.ServerInfo.Name, in.Init.ServerInfo.Version, in.Init.ProtocolVersion)
	}
	fmt.Printf("● %s  %s\n\n", srv.Name, info)

	fmt.Printf("tools (%d):\n", len(in.Tools))
	for _, t := range in.Tools {
		desc := strings.TrimSpace(t.Description)
		desc = strings.ReplaceAll(desc, "\n", " ")
		if len(desc) > 100 {
			desc = desc[:100] + "…"
		}
		fmt.Printf("  - %s  %s\n", t.Name, dim(desc))
	}
	fmt.Printf("\nresources (%d):\n", len(in.Resources))
	for _, r := range in.Resources {
		fmt.Printf("  - %s  %s\n", r.URI, dim(r.Description))
	}
	fmt.Printf("\nprompts (%d):\n", len(in.Prompts))
	for _, p := range in.Prompts {
		fmt.Printf("  - %s  %s\n", p.Name, dim(p.Description))
	}
}

func dim(s string) string {
	if s == "" {
		return ""
	}
	return "\x1b[38;5;245m" + s + "\x1b[0m"
}

// ---------- shared ----------

func collectServers(target, projectDir, transport string) ([]*config.Server, []string, error) {
	if target != "" {
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			s := &config.Server{
				Name:      hostFromURL(target),
				URL:       target,
				Transport: transportFor(target, transport),
			}
			return []*config.Server{s}, nil, nil
		}
		cf, err := config.ParseFile(target, "explicit", "explicit")
		if err != nil {
			return nil, nil, err
		}
		return cf.Servers, []string{target}, nil
	}

	files, err := config.Discover(projectDir)
	if err != nil {
		return nil, nil, err
	}
	var servers []*config.Server
	var paths []string
	for _, f := range files {
		servers = append(servers, f.Servers...)
		paths = append(paths, f.Path)
	}
	return servers, paths, nil
}

func probeServer(parent context.Context, srv *config.Server, timeout time.Duration) rules.Input {
	in := rules.Input{Server: srv}
	cctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	cli, err := protocol.Dial(cctx, srv)
	if err != nil {
		in.ConnectErr = err
		return in
	}
	defer cli.Close()

	init, err := cli.Initialize(cctx)
	if err != nil {
		in.ConnectErr = err
		return in
	}
	in.Init = init
	if tools, err := cli.ListTools(cctx); err == nil {
		in.Tools = tools
	}
	if resources, err := cli.ListResources(cctx); err == nil {
		in.Resources = resources
	}
	if prompts, err := cli.ListPrompts(cctx); err == nil {
		in.Prompts = prompts
	}
	return in
}

func renderReport(r *report.Report, format string) ([]byte, error) {
	switch strings.ToLower(format) {
	case "json":
		return report.RenderJSON(r)
	case "sarif":
		return report.RenderSARIF(r)
	case "md", "markdown":
		return []byte(report.RenderMarkdown(r)), nil
	case "html":
		return []byte(report.RenderHTML(r)), nil
	case "table":
		return []byte(report.RenderTable(r)), nil
	}
	return nil, fmt.Errorf("unknown format %q", format)
}

func severityRank(s rules.Severity) int {
	switch s {
	case rules.SeverityCritical:
		return 4
	case rules.SeverityHigh:
		return 3
	case rules.SeverityMedium:
		return 2
	case rules.SeverityLow:
		return 1
	}
	return 0
}

func reaches(r *report.Report, threshold string) bool {
	want := map[string]int{
		"critical": 4, "high": 3, "medium": 2, "low": 1,
	}[strings.ToLower(threshold)]
	return severityRank(r.MaxSeverity()) >= want
}

func transportFor(target, forced string) config.Transport {
	switch strings.ToLower(forced) {
	case "sse":
		return config.TransportSSE
	case "http":
		return config.TransportHTTP
	}
	if strings.Contains(target, "/sse") {
		return config.TransportSSE
	}
	return config.TransportHTTP
}

func hostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host
}

func jsonMarshalIndent(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
