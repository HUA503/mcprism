// Command mcprism is a single-binary security scanner for MCP
// (Model Context Protocol) servers. It discovers configured servers,
// enumerates what they can do, runs a set of deterministic checks and
// reports findings with a score. Policy files and profiles let teams
// enforce their own baseline.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/HUA503/mcprism/internal/config"
	"github.com/HUA503/mcprism/internal/policy"
	"github.com/HUA503/mcprism/internal/protocol"
	"github.com/HUA503/mcprism/internal/report"
	"github.com/HUA503/mcprism/internal/rules"
	"github.com/HUA503/mcprism/internal/ui"
	"github.com/spf13/cobra"
)

// Set to the release version by GoReleaser. Local builds keep the explicit
// development marker instead of reporting a stale release number.
var version = "dev"

func init() {
	// Keep the protocol clientInfo version in lockstep with the CLI version.
	protocol.ClientVersion = version
}

func main() {
	os.Exit(exitCode(rootCmd().Execute()))
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "mcprism",
		Short:         "Check MCP server security risks before connecting it to your AI",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	var noColor, ascii bool
	root.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable colored output (also honors NO_COLOR)")
	root.PersistentFlags().BoolVar(&ascii, "ascii", false, "use ASCII glyphs instead of Unicode (legacy Windows consoles)")
	root.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		ui.Init(noColor, ascii)
	}
	root.AddCommand(scanCmd(), demoCmd(), vetCmd(), inspectCmd(), registryCmd(), inventoryCmd(), rulesCmd(), profilesCmd(), versionCmd())
	return root
}

func exitCode(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errAuditFailed), errors.Is(err, errInventoryDrift):
		return 1
	default:
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 2
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the mcprism version",
		Run:   func(_ *cobra.Command, _ []string) { fmt.Println("mcprism", version) },
	}
}

// ---------- scan ----------

func scanCmd() *cobra.Command {
	var (
		o           auditOpts
		project     string
		transport   string
		projectOnly bool
		dynamic     bool
		noDynamic   bool // deprecated: probing is now opt-in by default
	)
	cmd := &cobra.Command{
		Use:   "scan [target ...]",
		Short: "Discover and audit MCP servers",
		Long: `Targets can be config files, directories (searched recursively) or http(s)
server URLs. With no targets, mcprism auto-discovers configs across the
installed AI clients. To check a launch command or package without writing
a config, use 'vet'.

By default scan is static: it reviews configuration without spawning a
server process or connecting to a server. Use 'vet' for source files. Pass
--dynamic to probe live servers; probing starts the server process, so run it
in a sandbox and treat it as executing untrusted code.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			if projectOnly && len(args) > 0 {
				return fmt.Errorf("--project-only is for auto-discovery; specify the directory with --project")
			}
			if transport != "" && !strings.EqualFold(transport, "http") && !strings.EqualFold(transport, "sse") {
				return fmt.Errorf("invalid --transport %q (expected http or sse)", transport)
			}
			if noDynamic {
				dynamic = false
			}
			var servers []*config.Server
			var files []string
			var err error
			if len(args) == 0 {
				servers, files, err = discoverAll(project, !projectOnly)
			} else {
				servers, files, err = collectMany(args, transport)
			}
			if err != nil {
				return err
			}
			if len(servers) == 0 {
				return fmt.Errorf("no MCP servers found (point at a config file, a directory, a server URL, or use 'vet' for a launch command)")
			}
			return audit(servers, files, dynamic, o)
		},
	}

	addAuditFlags(cmd, &o)
	cmd.Flags().BoolVar(&dynamic, "dynamic", false, "probe live servers (spawns processes / connects to enumerate tools; run in a sandbox)")
	cmd.Flags().BoolVar(&noDynamic, "no-dynamic", false, "deprecated: probing is opt-in by default, this flag is a no-op")
	_ = cmd.Flags().MarkHidden("no-dynamic")
	cmd.Flags().StringVar(&project, "project", "", "project directory for project-level config discovery")
	cmd.Flags().BoolVar(&projectOnly, "project-only", false, "discover project configs only (skip global client configs)")
	cmd.Flags().StringVar(&transport, "transport", "", "force transport for URL targets: http|sse")
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
			if format != "table" && format != "json" {
				return fmt.Errorf("unknown format %q (expected table or json)", format)
			}
			if timeout <= 0 {
				return fmt.Errorf("--timeout must be positive")
			}
			servers, _, err := collectMany([]string{args[0]}, "")
			if err != nil {
				return err
			}
			if len(servers) != 1 {
				return fmt.Errorf("inspect requires exactly one MCP server (found %d); use 'scan' for multiple servers", len(servers))
			}
			in := probeServer(context.Background(), servers[0], timeout)
			if in.ConnectErr != nil {
				return in.ConnectErr
			}
			if format == "json" {
				b, _ := json.MarshalIndent(in, "", "  ")
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
		desc := strings.ReplaceAll(strings.TrimSpace(t.Description), "\n", " ")
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

// ---------- rules / profiles ----------

func rulesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rules",
		Short: "List the built-in rules",
		Run: func(_ *cobra.Command, _ []string) {
			for _, c := range rules.Catalog() {
				owasp := c.OWASP
				if owasp == "" {
					owasp = "-"
				}
				fmt.Printf("%s\t%s\t%s\t%s\n", c.ID, owasp, c.DefaultSeverity, c.Title)
			}
		},
	}
}

func profilesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "profiles",
		Short: "List the built-in policy profiles",
		Run: func(_ *cobra.Command, _ []string) {
			for _, p := range policy.ListProfiles() {
				fmt.Printf("%s\t%s\n", p, policy.DescribeProfile(p))
			}
		},
	}
}

// ---------- collection ----------

func collectMany(targets []string, transport string) ([]*config.Server, []string, error) {
	var servers []*config.Server
	var files []string
	seen := map[string]bool{}

	addFile := func(cf *config.ClientFile) error {
		key, err := filepath.Abs(cf.Path)
		if err != nil {
			return err
		}
		if seen[key] {
			return nil
		}
		seen[key] = true
		servers = append(servers, cf.Servers...)
		files = append(files, cf.Path)
		return nil
	}

	for _, t := range targets {
		if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
			servers = append(servers, &config.Server{
				Name: hostFromURL(t), URL: t, Transport: transportFor(t, transport),
			})
			continue
		}
		info, err := os.Stat(t)
		if err != nil {
			return nil, nil, err
		}
		if info.IsDir() {
			cfs, err := config.WalkDir(t)
			if err != nil {
				return nil, nil, err
			}
			for _, cf := range cfs {
				if err := addFile(cf); err != nil {
					return nil, nil, err
				}
			}
			continue
		}
		cf, err := config.ParseFile(t, "explicit", "explicit")
		if err != nil {
			return nil, nil, err
		}
		if err := addFile(cf); err != nil {
			return nil, nil, err
		}
	}
	sort.Strings(files)
	return servers, files, nil
}

func discoverAll(projectDir string, includeGlobal bool) ([]*config.Server, []string, error) {
	if projectDir == "" {
		var err error
		projectDir, err = os.Getwd()
		if err != nil {
			return nil, nil, err
		}
	}
	projectDir, err := filepath.Abs(projectDir)
	if err != nil {
		return nil, nil, err
	}
	info, err := os.Stat(projectDir)
	if err != nil {
		return nil, nil, err
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("project path %q is not a directory", projectDir)
	}
	cfs, err := config.Discover(projectDir, includeGlobal)
	if err != nil {
		return nil, nil, err
	}
	var servers []*config.Server
	var files []string
	for _, cf := range cfs {
		servers = append(servers, cf.Servers...)
		files = append(files, cf.Path)
	}
	sort.Strings(files)
	return servers, files, nil
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
	if tools, err := cli.ListTools(cctx); err != nil {
		in.EnumErr = append(in.EnumErr, "tools/list: "+err.Error())
	} else {
		in.Tools = tools
	}
	if resources, err := cli.ListResources(cctx); err != nil {
		in.EnumErr = append(in.EnumErr, "resources/list: "+err.Error())
	} else {
		in.Resources = resources
	}
	if prompts, err := cli.ListPrompts(cctx); err != nil {
		in.EnumErr = append(in.EnumErr, "prompts/list: "+err.Error())
	} else {
		in.Prompts = prompts
	}
	return in
}

// ---------- rendering / exit ----------

func reportRenderer(format string) (func(*report.Report) ([]byte, error), error) {
	switch strings.ToLower(format) {
	case "json":
		return report.RenderJSON, nil
	case "sarif":
		return report.RenderSARIF, nil
	case "md", "markdown":
		return textReport(report.RenderMarkdown), nil
	case "html":
		return textReport(report.RenderHTML), nil
	case "junit":
		return report.RenderJUnit, nil
	case "cyclonedx", "cdx", "sbom":
		return report.RenderCycloneDX, nil
	case "csv":
		return report.RenderCSV, nil
	case "table":
		return textReport(report.RenderTable), nil
	}
	return nil, fmt.Errorf("unknown format %q", format)
}

func textReport(render func(*report.Report) string) func(*report.Report) ([]byte, error) {
	return func(r *report.Report) ([]byte, error) {
		return []byte(render(r)), nil
	}
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
