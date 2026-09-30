// Command mcprism is a single-binary security scanner for MCP
// (Model Context Protocol) servers. It discovers configured servers,
// enumerates what they can do, runs a set of deterministic checks and
// reports findings with a score. Policy files and profiles let teams
// enforce their own baseline.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/HUA503/mcprism/internal/config"
	"github.com/HUA503/mcprism/internal/policy"
	"github.com/HUA503/mcprism/internal/protocol"
	"github.com/HUA503/mcprism/internal/report"
	"github.com/HUA503/mcprism/internal/rules"
	"github.com/HUA503/mcprism/internal/tui"
	"github.com/spf13/cobra"
)

const version = "0.3.0"

func main() {
	root := &cobra.Command{
		Use:   "mcprism",
		Short: "Vet MCP servers before your AI trusts them",
	}
	root.AddCommand(scanCmd(), inspectCmd(), rulesCmd(), profilesCmd(), versionCmd())
	if err := root.Execute(); err != nil {
		os.Exit(1)
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
		format     string
		output     string
		failOn     string
		project    string
		transport  string
		policyFile string
		profile    string
		suppFile   string
		timeout    time.Duration
		noDynamic  bool
		interact   bool
	)
	cmd := &cobra.Command{
		Use:   "scan [target ...]",
		Short: "Discover and audit MCP servers",
		Long: `Targets can be config files, directories (searched recursively) or http(s)
server URLs. With no targets, mcprism auto-discovers configs across the
installed AI clients.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			pol, err := policy.Builtin(profile)
			if err != nil {
				return err
			}
			policyPath := ""
			if policyFile != "" {
				pol, err = policy.Load(policyFile)
				if err != nil {
					return err
				}
				policyPath = policyFile
			}

			servers, files, err := collectMany(args, project, transport)
			if err != nil {
				return err
			}
			if len(servers) == 0 {
				return fmt.Errorf("no MCP servers found (point at a config file, a directory or a server URL)")
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
			results = policy.Enforce(results, pol)

			var sups []policy.Suppression
			if suppFile != "" {
				sups, err = policy.LoadSuppressions(suppFile)
				if err != nil {
					return err
				}
			}
			results = policy.ApplySuppressions(results, sups, time.Now())
			for _, r := range results {
				rules.Rescore(r)
			}

			compliance := policy.Evaluate(results, pol, profile, policyPath)

			if interact {
				if err := tui.Run(results); err != nil {
					return fmt.Errorf("interactive mode requires a real terminal; rerun without -i for normal output: %w", err)
				}
				return nil
			}

			rep := report.Build(results, files, version, time.Now().Format(time.RFC3339))
			rep.Compliance = &compliance
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

			if !compliance.Pass || (failOn != "" && reaches(rep, failOn)) {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table|json|sarif|md|html|junit|cyclonedx|csv")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write the report to a file instead of stdout")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "per-server connection timeout")
	cmd.Flags().BoolVar(&noDynamic, "no-dynamic", false, "only statically analyze; do not spawn processes or connect")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "exit non-zero when a finding of this severity exists (critical|high|medium|low)")
	cmd.Flags().BoolVarP(&interact, "interactive", "i", false, "open the interactive terminal UI")
	cmd.Flags().StringVar(&project, "project", "", "project directory for project-level config discovery")
	cmd.Flags().StringVar(&transport, "transport", "", "force transport for URL targets: http|sse")
	cmd.Flags().StringVarP(&policyFile, "policy", "p", "", "path to a policy YAML file")
	cmd.Flags().StringVar(&profile, "profile", "", "built-in profile: default|strict|ci")
	cmd.Flags().StringVar(&suppFile, "suppressions", "", "path to a suppressions YAML file")
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
			servers, _, err := collectMany([]string{args[0]}, "", "")
			if err != nil {
				return err
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

func collectMany(targets []string, projectDir, transport string) ([]*config.Server, []string, error) {
	if len(targets) == 0 {
		return discoverAll(projectDir)
	}
	var servers []*config.Server
	var files []string
	seen := map[string]bool{}

	addFile := func(cf *config.ClientFile) {
		for _, s := range cf.Servers {
			key := cf.Path + "::" + s.Name
			if seen[key] {
				continue
			}
			seen[key] = true
			servers = append(servers, s)
		}
		files = append(files, cf.Path)
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
				addFile(cf)
			}
			continue
		}
		cf, err := config.ParseFile(t, "explicit", "explicit")
		if err != nil {
			return nil, nil, err
		}
		addFile(cf)
	}
	sort.Strings(files)
	return servers, files, nil
}

func discoverAll(projectDir string) ([]*config.Server, []string, error) {
	if projectDir == "" {
		projectDir, _ = os.Getwd()
	}
	cfs, err := config.Discover(projectDir)
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

// ---------- rendering / exit ----------

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
	case "junit":
		return report.RenderJUnit(r)
	case "cyclonedx", "cdx", "sbom":
		return report.RenderCycloneDX(r)
	case "csv":
		return report.RenderCSV(r)
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
