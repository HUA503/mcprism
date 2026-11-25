package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/HUA503/mcprism/examples"
	"github.com/HUA503/mcprism/internal/config"
	"github.com/spf13/cobra"
)

func demoCmd() *cobra.Command {
	var format, output string
	cmd := &cobra.Command{
		Use:   "demo",
		Short: "Try mcprism with built-in safe and vulnerable examples",
		Long: `Run an offline scan of built-in MCP configuration examples.
The demo does not read your configuration, start a server, or make network
requests. Findings in the vulnerable example are expected; the command exits
successfully after it renders the report.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			names := []string{"clean.mcp.json", "vulnerable.mcp.json"}
			var servers []*config.Server
			var sources []string
			for _, name := range names {
				data, err := examples.FS.ReadFile(name)
				if err != nil {
					return fmt.Errorf("load built-in demo %s: %w", name, err)
				}
				parsed, err := config.ParseBytes(data)
				if err != nil {
					return fmt.Errorf("parse built-in demo %s: %w", name, err)
				}
				source := "embedded:examples/" + name
				for _, server := range parsed {
					server.Source = source
					server.Client = "demo"
					server.Scope = "example"
				}
				servers = append(servers, parsed...)
				sources = append(sources, source)
			}

			err := audit(servers, sources, false, auditOpts{
				format:  format,
				output:  output,
				timeout: 10 * time.Second,
			})
			if errors.Is(err, errAuditFailed) {
				return nil
			}
			return err
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table|json|sarif|md|html|junit|cyclonedx|csv")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write the report to a file instead of stdout")
	return cmd
}
